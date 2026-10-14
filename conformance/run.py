#!/usr/bin/env python3
"""BNAP socket draft-00 black-box conformance runner, in the style of h2spec.

Usage:
  python3 -I conformance/run.py --target https://host --profile gateway|server|client
      [--payer none|cmd:<shell command>] [--report DIR]
      [--role NAME=ROUTE_ID]... [--dpop-token-cmd CMD] [--max-wait S]
      [--max-spend-sat N] [--fee-limit-sat N] [--allow-http] [--insecure] [--only ID,...] [--allow-skips] [--list]

Profiles:
  client   read-only: the manifest and the 402 offers, everything a client
           relies on. Sends no credential, changes no state.
  server   client, plus credentials: error responses, attestation-only
           flows, replays, the use store and receipts.
  gateway  server, plus what a gate in front of an application owes it:
           the request-target forwarded unchanged and receipts in event
           streams (needs --role echo=... and --role sse=...).

--payer none runs everything that needs no money. --payer cmd:<command>
adds value flows: the command is run through the shell with the BOLT 11
invoice appended as its last argument (and in BNAP_INVOICE); it must pay
it and print the 32-byte preimage in hex. The runner decodes the invoice
strictly, pays only the exact amount of the offer's pay entry, refuses AMP
invoices, and refuses any invoice whose amount plus the routing fee limit
(--fee-limit-sat, default 10, reserved per payment) is over what
--max-spend-sat leaves. It also sets BNAP_EXPECT_AMOUNT_SAT and
BNAP_EXPECT_PAYMENT_HASH (hex): a payer wrapper MUST decode the invoice
itself and refuse to pay when its amount or payment hash differs, so that
the cap holds even where the two decoders disagree. It sets
BNAP_REMAINING_SAT and BNAP_FEE_LIMIT_SAT: the wrapper MUST cap its routing
fee at the limit and refuse unless amount + limit <= remaining. A payer may
print a line fee_msat=<N> before the preimage; the runner then counts the
amount plus that fee (rounded up to a sat), and otherwise the whole limit.
conformance/payers/lncli-payer.sh is such a wrapper for lnd.

Roles name manifest routes with a special application behaviour:
  slow=ID   an action that runs for at least a second (PENDING replays)
  fail=ID   an action whose application fails (FAILED outcomes)
  short=ID  a route whose offers expire within --max-wait - 61 seconds
  echo=ID   (gateway) the application echoes the request-target as JSON {"target"}
  sse=ID    (gateway) the application answers with text/event-stream
  cache=ID  (gateway) the application sends its own Cache-Control, such as
            "public, max-age=60", which the gate must amend to private, no-store

Attestation-only flows use DPoP keys the runner makes, in the suite's
adapter profile bnap-conf-dpop-1 (bnap_conf/dpop.py). --dpop-token-cmd CMD
gets the key's JWK thumbprint (base64url) appended and must print an access
token bound to it; without it the access token is empty.

Exit status: 0 when every MUST case of the profile ran and passed; 1 when a
MUST case failed or any case errored; 3 when none failed but some MUST case was
skipped, or left out by --only (the verdict is then "incomplete" and the
reports list those IDs); 2 on a usage error. --allow-skips turns 3 into 0; the
reports still list the MUST cases that did not run.
Standard library only, Python 3.11 or later. Run with python3 -I.
"""
import argparse
import hashlib
import html
import ipaddress
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from bnap_conf import codec, offer as of, credential as cr, response as rs, manifest as mf  # noqa: E402
from bnap_conf import http as hp, pricing as pr, dpop, lightning as ln, notes, registry  # noqa: E402
from bnap_conf.codec import BnapError, b64u, b64u_decode, H  # noqa: E402
from bnap_conf.crypto import schnorr_pub, schnorr_sign, key_from_label  # noqa: E402

VERSION = "bnap-conformance 0.1 (draft-00)"
EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_INCOMPLETE = 0, 1, 2, 3
PROFILES = ("client", "server", "gateway")
ALL = PROFILES
WITH_CREDENTIALS = ("server", "gateway")
SECTION_TITLES = {
    "2": "2 Conventions", "4": "4 The Offer", "5": "5 The Credential", "6": "6 Uses and the use store",
    "7": "7 Pricing, attestations and metering", "8": "8 Response, receipt and errors",
    "9": "9 Manifest and pinning", "10": "10 The HTTP carrier", "12": "12 Security considerations",
}
DPOP = dpop.SCHEME
POST_BODY = b'{"conformance":true}'
NATIVE_AUTH = ("l402", "lsat", "payment")

# ---------------------------------------------------------------- case registry


class Case:
    def __init__(self, cid, section, level, title, profiles, func, needs, deferred):
        self.id = cid
        self.section = section
        self.level = level
        self.title = title
        self.profiles = profiles
        self.func = func
        self.needs = needs
        self.deferred = deferred

    @property
    def top(self):
        return self.section.split(".")[0]


CASES = []


def case(cid, section, level, title, profiles=ALL, needs=(), deferred=False):
    def deco(fn):
        if any(c.id == cid for c in CASES):
            raise SystemExit("duplicate case id " + cid)
        CASES.append(Case(cid, section, level, title, tuple(profiles), fn, tuple(needs), deferred))
        return fn
    return deco


class Skip(Exception):
    pass


class Fail(Exception):
    pass


class Result:
    def __init__(self, c, status, detail="", notes=(), duration=0.0):
        self.case = c
        self.status = status
        self.detail = detail
        self.notes = list(notes)
        self.duration = duration

    def to_json(self):
        return {"id": self.case.id, "section": self.case.section, "level": self.case.level,
                "title": self.case.title, "status": self.status, "detail": self.detail,
                "notes": self.notes, "duration_s": round(self.duration, 3)}


def check(cond, msg):
    if not cond:
        raise Fail(msg)

# ---------------------------------------------------------------- context


class Route:
    def __init__(self, d, origin):
        self.d = d
        self.id = d.get("id")
        self.match = d.get("match", "")
        self.method, _, self.pattern = self.match.partition(" ")
        self.scope_mode = d.get("scope", "exact")
        self.headers = list(d.get("headers") or [])
        self.origin = origin

    def target(self, leaf="conformance-probe", query=""):
        t = hp.concrete_target(self.match, leaf)
        return t + (("?" + query) if query else "")


class Req:
    def __init__(self, route, target, body=None, headers=()):
        self.route = route
        self.method = route.method
        self.target = target
        self.body = body
        self.headers = list(headers)

    def with_target(self, target):
        return Req(self.route, target, self.body, self.headers)

    def action_scope(self):
        listed = hp.listed_headers(self.route.headers, self.headers)
        return hp.action_scope(self.method, self.route.origin, self.target, self.body or None, listed)

    def htu(self):
        return self.route.origin + self.target.split("?", 1)[0]


class Exchange:
    def __init__(self, req, sent_headers, res, label):
        self.req = req
        self.sent_headers = sent_headers
        self.res = res
        self.label = label
        self.error = None
        self.error_raw = None
        self.error_problem = None
        self.receipt_raw = None
        eh = res.header("BNAP-Error") if res is not None else None
        if eh is not None:
            try:
                self.error_raw = b64u_decode(eh.strip())
                self.error = codec.parse_error(self.error_raw)
            except BnapError as e:
                self.error_problem = f"{e.code}: {e.reason}"
        rh = res.header("BNAP-Receipt") if res is not None else None
        if rh is not None:
            try:
                self.receipt_raw = b64u_decode(rh.strip())
            except BnapError:
                self.receipt_raw = b""

    @property
    def carried_credential(self):
        return any(k.lower() == "bnap-credential" for k, _ in self.sent_headers)

    @property
    def carried_native(self):
        """A native value credential in Authorization (L402, LSAT, MPP Payment)."""
        return any(k.lower() == "authorization" and v.strip().split(" ", 1)[0].lower() in NATIVE_AUTH
                   for k, v in self.sent_headers)

    def has_receipt(self):
        """BNAP-Receipt in the header, or the final bnap-receipt event of an event stream (10.2)."""
        if self.receipt_raw:
            return True
        if self.res is None or not (self.res.header("Content-Type") or "").lower().startswith("text/event-stream"):
            return False
        return any(n == "bnap-receipt" for n, _ in hp.parse_sse(self.res.body or b""))

    def sent_credential(self):
        """The Credential this exchange sent, parsed, or None."""
        v = next((v for k, v in self.sent_headers if k.lower() == "bnap-credential"), None)
        if v is None:
            return None
        try:
            return cr.parse_credential(b64u_decode(v.strip()), 1 << 20)
        except BnapError:
            return None

    @property
    def code(self):
        return self.error.name if self.error is not None else None

    def receipt(self):
        if not self.receipt_raw:
            return None
        try:
            return rs.parse_response(self.receipt_raw, 1 << 20)
        except BnapError:
            return None

    def describe(self):
        if self.res is None:
            return "no response"
        s = f"HTTP {self.res.status}"
        if self.code:
            s += f" {self.code}"
        if self.receipt_raw:
            r = self.receipt()
            s += " receipt " + (f"{r.status_name}{' replayed' if r.replayed else ''}" if r else "unparseable")
        return s


class OfferProblem:
    """An offer challenge the runner could not use.

    stage "challenge": the WWW-Authenticate syntax, a missing offer parameter or
    bad base64url (OFR-CHALLENGE). stage "parse": the bytes decoded but the
    offer breaks a 2 or 4.1 rule (OFR-PARSE); raw holds those bytes.
    """

    def __init__(self, stage, code, reason, raw=None):
        self.stage = stage
        self.code = code
        self.reason = reason
        self.raw = raw

    def __str__(self):
        return f"{self.code} {self.reason}".strip()


class Probe:
    def __init__(self, route, req, ex):
        self.route = route
        self.req = req
        self.ex = ex
        self.offers = []
        self.offer_errors = []
        self.challenges = []
        self.bnap_values = 0
        if ex.res is None:
            return
        for v in ex.res.headers_all("WWW-Authenticate"):
            try:
                self.challenges.extend(hp.parse_challenges(v))
            except ValueError as e:
                self.offer_errors.append(OfferProblem("challenge", "challenge-syntax", str(e)))
        for ch in self.challenges:
            if ch.scheme.lower() != "bnap":
                continue
            val = ch.params.get("offer")
            if val is None:
                self.offer_errors.append(OfferProblem("challenge", "no-offer-param", ch.raw[:60]))
                continue
            try:
                raw = b64u_decode(val)
            except BnapError as e:
                self.offer_errors.append(OfferProblem("challenge", "offer-base64url", e.reason))
                continue
            self.bnap_values += 1
            try:
                o = of.parse_offer(raw, 1 << 20)
            except BnapError as e:
                self.offer_errors.append(OfferProblem("parse", e.code, e.reason, raw))
                continue
            self.offers.append((raw, o))

    def challenge_errors(self):
        return [e for e in self.offer_errors if e.stage == "challenge"]

    def parse_errors(self):
        return [e for e in self.offer_errors if e.stage == "parse"]

    def natives(self):
        return [c for c in self.challenges if c.scheme.lower() != "bnap"]


class Ctx:
    def __init__(self, args):
        self.args = args
        self.base = args.target.rstrip("/")
        self.origin = of.origin_of(self.base)
        self.registry = registry.default()
        self.lock = threading.RLock()
        self.log = []
        self._manifest = None
        self._manifest_err = None
        self._probes = {}
        self.roles = dict(r.split("=", 1) for r in args.role)
        self.spent_sat = 0
        self.dpop_keys = {}
        self.share = {}
        self.seen_offers = []    # (raw, Offer) of every BNAP offer any response carried
        self.offers_by_id = {}

    def now(self):
        return int(time.time())

    # -------------------------------------------------------- HTTP

    def request(self, req, *, credential=None, raw_credential=None, extra=(), label=""):
        headers = list(req.headers)
        if req.body is not None:
            headers.append(("Content-Type", "application/json"))
        if raw_credential is not None:
            headers.append(("BNAP-Credential", raw_credential))
        elif credential is not None:
            headers.append(("BNAP-Credential", b64u(credential)))
        headers += list(extra)
        try:
            res = hp.http_request(self.base, req.method, req.target, req.body, headers,
                                  insecure=self.args.insecure, timeout=30)
        except hp.HttpTransportError as e:
            ex = Exchange(req, headers, None, label)
            ex.transport_error = str(e)
            with self.lock:
                self.log.append(ex)
            return ex
        ex = Exchange(req, headers, res, label)
        found = []
        for v in res.headers_all("WWW-Authenticate"):
            for ch in _safe_challenges(v):
                if ch.scheme.lower() != "bnap" or "offer" not in ch.params:
                    continue
                try:
                    raw = b64u_decode(ch.params["offer"])
                    found.append((raw, of.parse_offer(raw, 1 << 20)))
                except BnapError:
                    continue
        with self.lock:
            self.log.append(ex)
            for raw, o in found:
                self.seen_offers.append((raw, o))
                self.offers_by_id.setdefault(o.offer_id, o)
        return ex

    def offer_of(self, c):
        """The Offer a parsed Credential names, inline or by an OfferID seen in this run."""
        if c.offer is not None:
            try:
                return of.parse_offer(c.offer, 1 << 20)
            except BnapError:
                return None
        with self.lock:
            return self.offers_by_id.get(c.offer_id_ref)

    # -------------------------------------------------------- manifest

    def manifest(self):
        with self.lock:
            if self._manifest is None and self._manifest_err is None:
                try:
                    res = hp.http_request(self.base, "GET", "/.well-known/bnap", insecure=self.args.insecure)
                except hp.HttpTransportError as e:
                    self._manifest_err = "fetch failed: " + str(e)
                    raise Skip(self._manifest_err)
                if res.status != 200:
                    self._manifest_err = f"/.well-known/bnap answered {res.status}"
                else:
                    try:
                        obj = mf.parse_json_strict(res.body)
                        self._manifest = (res, obj)
                    except mf.ManifestReject as e:
                        self._manifest_err = "manifest is not strict I-JSON: " + str(e)
            if self._manifest is None:
                raise Skip("needs the manifest: " + self._manifest_err)
            return self._manifest

    def mobj(self):
        return self.manifest()[1]

    def limits(self):
        return mf.limits_of(self.mobj())

    def pin_keys(self):
        return self.mobj().get("keys", [])

    def routes(self):
        return [Route(r, self.origin) for r in self.mobj().get("routes", []) if isinstance(r, dict)]

    def route(self, rid):
        for r in self.routes():
            if r.id == rid:
                return r
        return None

    def role_route(self, role):
        rid = self.roles.get(role)
        if rid is None:
            raise Skip(f"no --role {role}=ROUTE_ID given")
        r = self.route(rid)
        if r is None:
            raise Skip(f"--role {role}={rid}: no such route in the manifest")
        return r

    def plain_routes(self):
        """Routes without a special role, in manifest order."""
        special = set(self.roles.values())
        return [r for r in self.routes() if r.id not in special]

    def make_req(self, route, leaf="conformance-probe", query="", headers=()):
        body = POST_BODY if route.method in ("POST", "PUT", "PATCH") else None
        hdrs = list(headers)
        for h in route.headers:
            if not any(k.lower() == h for k, _ in hdrs):
                hdrs.append((h, "conformance"))
        return Req(route, route.target(leaf, query), body, hdrs)

    def probe(self, route, fresh=False):
        with self.lock:
            if not fresh and route.id in self._probes:
                return self._probes[route.id]
        req = self.make_req(route)
        p = Probe(route, req, self.request(req, label="probe"))
        if not fresh:
            with self.lock:
                self._probes.setdefault(route.id, p)
        return p

    def all_probes(self):
        return [self.probe(r) for r in self.routes()]

    def find(self, pred, routes=None):
        """First (probe, raw, offer) over routes whose offer satisfies pred."""
        for r in routes if routes is not None else self.plain_routes():
            p = self.probe(r)
            for raw, o in p.offers:
                if pred(o):
                    return p, raw, o
        return None

    def require(self, pred, what, routes=None):
        hit = self.find(pred, routes)
        if hit is None:
            raise Skip("no route offers " + what)
        return hit

    # -------------------------------------------------------- DPoP

    def dpop_key(self, label="default"):
        with self.lock:
            if label not in self.dpop_keys:
                self.dpop_keys[label] = dpop.DpopKey(os.urandom(32))
            return self.dpop_keys[label]

    def dpop_token(self, key):
        cmd = self.args.dpop_token_cmd
        if not cmd:
            return ""
        tp = b64u(key.thumbprint())
        out = subprocess.run(cmd + " " + shlex.quote(tp), shell=True, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise Skip("--dpop-token-cmd failed: " + out.stderr.strip()[:120])
        return out.stdout.strip()

    def dpop_credential(self, req, raw, o, *, key=None, omit_ctx=False, context_for=None, jti=None,
                        by_reference=False, extra=(), binding=None, ext=None):
        """An attestation-only credential: one DPoP proof, no pay. ext goes into the Context (5.2)."""
        key = key or self.dpop_key()
        act = (context_for or req).action_scope()
        ctx = cr.context(o.offer_id, act, None, [DPOP], ext)
        tok = self.dpop_token(key)
        body = dpop.make_body(key, method=req.method, htu=req.htu(), iat=self.now(), jti=jti or b64u(os.urandom(12)),
                              context=ctx, access_token=tok, omit_ctx=omit_ctx)
        cred = cr.build_credential(offer=None if by_reference else raw, offer_id=o.offer_id if by_reference else None,
                                   attest=[cr.SchemeItem(DPOP, body, None)], extra=list(extra), binding=binding,
                                   ext=ext)
        dg = cr.digest(ctx, binding, b"", [body])
        return cred, ctx, dg

    # -------------------------------------------------------- payer

    def pay(self, invoice, entry):
        """Pay invoice for the pay entry entry of an offer, through --payer, and return the preimage.

        The spend cap is checked against the runner's own decode while the payer parses the invoice
        on its own, so the decode is strict (ln.decode_bolt11), the amount must be exactly the
        entry's, and the payer gets BNAP_EXPECT_AMOUNT_SAT and BNAP_EXPECT_PAYMENT_HASH: a wrapper
        MUST decode the invoice itself and refuse to pay when either differs."""
        spec = self.args.payer
        if not spec or spec == "none":
            raise Skip("needs --payer cmd:...")
        if not isinstance(invoice, str):
            raise Fail("the offer names no BOLT 11 invoice to pay")
        try:
            inv = ln.decode_bolt11(invoice)
        except ValueError as e:
            raise Skip(f"the runner refuses to pay an invoice it cannot decode strictly: {e}") from None
        if inv.amount_msat is None:
            raise Skip("invoice has no amount; the runner pays only fixed amounts")
        if entry.unit != "sat":
            raise Skip(f"the pay entry is priced in {entry.unit!r}; the runner pays sat entries only")
        amt = inv.amount_sat
        check(amt is not None and amt == entry.amount,
              f"the invoice asks {inv.amount_msat} msat, the offer's {entry.scheme} entry {entry.amount} sat: "
              "the runner pays only the exact amount the offer names")
        if inv.amp:
            raise Skip("the invoice sets AMP (feature bit 30 or 31): one invoice could take many payments, "
                       "so the runner does not pay it")
        fee = self.args.fee_limit_sat
        cap = self.args.max_spend_sat
        with self.lock:
            # The routing fee is paid on top of the invoice: reserve the whole fee limit now, and
            # count what the payer reports it paid once it is done.
            remaining = cap - self.spent_sat
            if amt + fee > remaining:
                raise Skip(f"invoice of {amt} sat plus a routing fee limit of {fee} sat is over what "
                           f"--max-spend-sat {cap} leaves ({remaining} sat)")
            self.spent_sat += amt + fee
        cmd = spec[4:] + " " + shlex.quote(invoice)
        env = dict(os.environ, BNAP_INVOICE=invoice, BNAP_EXPECT_AMOUNT_SAT=str(amt),
                   BNAP_EXPECT_PAYMENT_HASH=inv.payment_hash.hex(), BNAP_REMAINING_SAT=str(remaining),
                   BNAP_FEE_LIMIT_SAT=str(fee))
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180, env=env)
        if out.returncode != 0:
            # The reservation stays counted: the payer may have paid before it failed.
            raise Fail("payer failed: " + (out.stderr.strip() or out.stdout.strip())[:160])
        lines = [x.strip() for x in out.stdout.splitlines() if x.strip()]
        fees = [m.group(1) for x in lines for m in [re.fullmatch(r"fee_msat=([0-9]{1,18})", x)] if m]
        if fees:
            paid_fee = -(-int(fees[-1]) // 1000)  # whole sat, rounded up
            with self.lock:
                self.spent_sat += paid_fee - fee
            check(paid_fee <= fee, f"the payer paid a routing fee of {fees[-1]} msat, over the "
                  f"{fee} sat limit it was given")
        try:
            pre = bytes.fromhex(lines[-1])
        except (ValueError, IndexError):
            raise Fail("payer printed no hex preimage") from None
        check(len(pre) == 32 and hashlib.sha256(pre).digest() == inv.payment_hash,
              "the preimage the payer printed does not match the invoice's payment hash")
        return pre

# ---------------------------------------------------------------- shared assertions


def expect_error(ex, codes, fresh=None):
    """The exchange carries one of codes with the 8.2 HTTP status."""
    codes = (codes,) if isinstance(codes, str) else tuple(codes)
    check(ex.res is not None, "no HTTP response: " + getattr(ex, "transport_error", ""))
    check(ex.error is not None, f"expected {'/'.join(codes)}, got {ex.describe()} without a parseable BNAP-Error"
          + (f" ({ex.error_problem})" if ex.error_problem else ""))
    check(ex.code in codes, f"expected {'/'.join(codes)}, got {ex.describe()}")
    want = codec.http_status_of(ex.code)
    check(ex.res.status == want, f"{ex.code} must travel with HTTP {want}, got {ex.res.status}")
    if fresh or (fresh is None and ex.code in codec.FRESH_OFFER):
        offers = [c for v in ex.res.headers_all("WWW-Authenticate") for c in _safe_challenges(v)
                  if c.scheme.lower() == "bnap"]
        check(offers, f"{ex.code} must come with a fresh offer (8.2)")


def _safe_challenges(v):
    try:
        return hp.parse_challenges(v)
    except ValueError:
        return []


def expect_not_admitted(ex):
    check(ex.res is not None, "no HTTP response")
    r = ex.receipt()
    check(not (r is not None and r.status == rs.OK), f"admitted: {ex.describe()}")
    check(ex.res.status >= 400, f"expected a refusal, got {ex.describe()}")


def expect_admitted(ex):
    check(ex.res is not None, "no HTTP response: " + getattr(ex, "transport_error", ""))
    check(ex.error is None or ex.receipt_raw, f"refused: {ex.describe()}"
          + (f" detail={ex.error.detail!r}" if ex.error is not None and ex.error.detail else ""))
    check(ex.receipt_raw, f"no BNAP-Receipt: {ex.describe()}")
    r = ex.receipt()
    check(r is not None, "BNAP-Receipt does not parse")
    return r


def dpop_waive(o):
    a = o.attest_entry(DPOP)
    return a is not None and a.effect == 1


def admitted_dpop(ctx):
    """An offer a runner-made DPoP key gets through: a waive, outside special roles,
    exact scope preferred."""
    hit = ctx.find(lambda o: dpop_waive(o) and not o.route_scope)
    return hit or ctx.require(dpop_waive, "an httpauth:DPoP waive")

# ================================================================ 9 Manifest and pinning


@case("MAN-FETCH", "9.1", "MUST", "the manifest is served at /.well-known/bnap as application/json")
def man_fetch(ctx):
    res, _ = ctx.manifest()
    ct = (res.header("Content-Type") or "").split(";")[0].strip().lower()
    check(ct == "application/json", f"Content-Type is {ct or 'missing'}")


@case("MAN-HTTPS", "9.3", "MUST", "the manifest is fetched over HTTPS with a certificate valid for the origin")
def man_https(ctx):
    u = urllib.parse.urlsplit(ctx.base)
    if u.scheme != "https":
        raise Skip("target is plain HTTP (--allow-http); clients fetch manifests over HTTPS only")
    if ctx.args.insecure:
        raise Skip("certificate not verified (--insecure)")
    ctx.manifest()


@case("MAN-IJSON", "9.1", "MUST", "the manifest is I-JSON: no duplicate members, integers only, nothing beyond 2^53")
def man_ijson(ctx):
    ctx.manifest()


@case("MAN-VERSION", "9.1", "MUST", "bnap is 1")
def man_version(ctx):
    check(ctx.mobj().get("bnap") == 1 and not isinstance(ctx.mobj().get("bnap"), bool),
          f"bnap is {ctx.mobj().get('bnap')!r}")


@case("MAN-ORIGIN", "9.1", "MUST", "origin is the RFC 6454 serialization of the target's origin")
def man_origin(ctx):
    o = ctx.mobj().get("origin")
    check(isinstance(o, str) and of.origin_of(o) == o, f"origin {o!r} is not serialized as RFC 6454 asks")
    check(o == ctx.origin, f"origin {o!r} is not {ctx.origin!r}")


@case("MAN-SIG", "9.1", "MUST", "sig verifies under root over H_bnap/manifest(JCS(manifest without sig))")
def man_sig(ctx):
    check(mf.sig_valid(ctx.mobj()), "sig does not verify under root")


@case("MAN-MEMBERS", "9.1", "MUST", "every member has the form 9.1 gives it")
def man_members(ctx):
    probs = [p for p in mf.document_problems(ctx.mobj(), origin=ctx.origin)
             if p[0] not in ("sig-invalid", "origin-mismatch", "origin-not-serialized", "bnap-not-1")]
    check(not probs, "; ".join(f"{a} {b}".strip() for a, b in probs[:6]))


@case("MAN-ISSUED", "9.3", "MUST", "issued - 60 <= now <= issued + max_age + 60, and max_age <= 30 days")
def man_issued(ctx):
    m, now = ctx.mobj(), ctx.now()
    check(isinstance(m.get("max_age"), int) and m["max_age"] <= mf.MAX_AGE_LIMIT, f"max_age {m.get('max_age')!r}")
    check(m["issued"] - 60 <= now <= m["issued"] + m["max_age"] + 60,
          f"issued {m['issued']} max_age {m['max_age']} is not current at {now}")


@case("MAN-KEYS-LIVE", "9.3", "MUST", "at least one live offer key and one live receipt key are listed")
def man_keys_live(ctx):
    now = ctx.now()
    keys = ctx.pin_keys()
    for use in ("offer", "receipt"):
        check(any(k.get("use") == use and isinstance(k.get("not_after"), int) and k["not_after"] >= now
                  for k in keys), f"no live {use} key")


@case("MAN-KEY-LIFETIME", "9.2", "SHOULD", "online offer and receipt keys expire within 30 days")
def man_key_lifetime(ctx):
    now = ctx.now()
    long_ = [k.get("kid", "")[:16] for k in ctx.pin_keys()
             if isinstance(k.get("not_after"), int) and k["not_after"] > now + 30 * 86400 + 60]
    check(not long_, "keys valid for more than 30 days: " + ", ".join(long_))


@case("MAN-CARRIER", "9.1", "SHOULD", "carriers lists http")
def man_carrier(ctx):
    check("http" in (ctx.mobj().get("carriers") or []), f"carriers = {ctx.mobj().get('carriers')!r}")


@case("MAN-PIN", "9.3", "MUST", "a client can pin the manifest, and a refetch passes the pin rules")
def man_pin(ctx):
    res, _ = ctx.manifest()
    now = ctx.now()
    try:
        pin = mf.fetch_accept(res.body, origin=ctx.origin, now=now)
    except mf.ManifestReject as e:
        raise Fail("first contact refused: " + str(e))
    again = hp.http_request(ctx.base, "GET", "/.well-known/bnap", insecure=ctx.args.insecure)
    check(again.status == 200, f"refetch answered {again.status}")
    try:
        mf.fetch_accept(again.body, origin=ctx.origin, now=ctx.now(), pin=pin)
    except mf.ManifestReject as e:
        raise Fail("refetch refused by the pin rules (same bytes or a higher seq): " + str(e))
    ctx.share["pin"] = pin


@case("MAN-ROUTES", "9.1", "MUST", "every route is well formed and names only registered schemes")
def man_routes(ctx):
    routes = ctx.mobj().get("routes")
    check(isinstance(routes, list) and routes, "no routes")
    bad = []
    for r in routes:
        for s in list(r.get("pay", [])) + [a.get("scheme") for a in r.get("attest", []) if isinstance(a, dict)]:
            if not ctx.registry.known(s):
                bad.append(f"{r.get('id')}: {s}")
    check(not bad, "schemes without a registry entry: " + ", ".join(bad))

# ================================================================ 4 The Offer (the 402)


def each_offer(ctx, fn):
    """Apply fn(probe, raw, offer) to every offer of every route; collect failures."""
    probs, n = [], 0
    for p in ctx.all_probes():
        for raw, o in p.offers:
            n += 1
            try:
                fn(p, raw, o)
            except Fail as e:
                probs.append(f"{p.route.id}: {e}")
    if n == 0:
        raise Skip("no offers")
    check(not probs, "; ".join(probs[:5]) + (f" (+{len(probs) - 5} more)" if len(probs) > 5 else ""))


@case("OFR-402", "10.2", "MUST", "a request without a credential gets 402 with BNAP-Error REQUIRED")
def ofr_402(ctx):
    probs = []
    for p in ctx.all_probes():
        try:
            expect_error(p.ex, "REQUIRED", fresh=True)
        except Fail as e:
            probs.append(f"{p.route.id}: {e}")
    check(not probs, "; ".join(probs))


@case("OFR-CHALLENGE", "10.2", "MUST", "each 402 carries WWW-Authenticate: BNAP offer= in canonical base64url")
def ofr_challenge(ctx):
    probs = []
    for p in ctx.all_probes():
        ce = p.challenge_errors()
        if ce:
            probs.append(f"{p.route.id}: {ce[0]}")
        elif not p.bnap_values:
            probs.append(f"{p.route.id}: no BNAP offer")
    check(not probs, "; ".join(probs))


@case("OFR-PARSE", "4.1", "MUST", "every offer parses fully and fits max_offer")
def ofr_parse(ctx):
    lim = ctx.limits()["max_offer"]
    probs, n = [], 0
    for p in ctx.all_probes():
        for e in p.parse_errors():
            n += 1
            probs.append(f"{p.route.id}: an offer does not parse: {e}")
        for raw, o in p.offers:
            n += 1
            if len(raw) > lim:
                probs.append(f"{p.route.id}: {len(raw)} bytes > max_offer {lim}")
    if n == 0:
        raise Skip("no offers")
    check(not probs, "; ".join(probs[:5]) + (f" (+{len(probs) - 5} more)" if len(probs) > 5 else ""))


@case("OFR-MAC", "4.1", "MUST", "offers in a 402 carry mac (only offers published in advance omit it)")
def ofr_mac(ctx):
    def f(p, raw, o):
        check(o.mac is not None, "no mac")
    each_offer(ctx, f)


@case("OFR-KEY", "4.4", "MUST", "offer_key is listed for use offer in the manifest and has not expired")
def ofr_key(ctx):
    now = ctx.now()

    def f(p, raw, o):
        check(of.key_listed(ctx.pin_keys(), o.offer_key, "offer", now), "offer_key not listed or expired")
    each_offer(ctx, f)


@case("OFR-SIG", "4.2", "MUST", "offer_sig verifies over every record outside the signature range")
def ofr_sig(ctx):
    def f(p, raw, o):
        check(of.verify_offer_sig(o), "offer_sig does not verify")
    each_offer(ctx, f)


@case("OFR-EXPIRY", "4.4", "MUST", "expires is in the future and issued_at, if present, is not")
def ofr_expiry(ctx):
    now = ctx.now()

    def f(p, raw, o):
        check(o.expires + 60 >= now, f"expired at {o.expires}")
        check(o.issued_at is None or o.issued_at <= now + 60, "issued_at in the future")
    each_offer(ctx, f)


@case("OFR-INFO", "4.4", "MUST", "info, if present, is on the origin the offer came from")
def ofr_info(ctx):
    def f(p, raw, o):
        check(o.info is None or of.info_same_origin(o.info, ctx.origin), f"info {o.info!r}")
    each_offer(ctx, f)


@case("OFR-SCOPE", "10.1", "MUST", "scope is the action scope of the request, or the route scope of its route")
def ofr_scope(ctx):
    def f(p, raw, o):
        if o.route_scope:
            check(p.route.scope_mode == "route", "route-scope offer on a route the manifest lists as exact")
            check(o.scope == hp.route_scope(ctx.origin, p.route.id), "route scope differs from H(origin, route id)")
        else:
            check(o.scope == p.req.action_scope(), "exact scope differs from the action scope of the request sent")
    each_offer(ctx, f)


@case("OFR-HEADERS", "10.1", "MUST", "exact-scope offers repeat the route's listed headers in record 6")
def ofr_headers(ctx):
    def f(p, raw, o):
        if o.route_scope or not p.route.headers:
            return
        check(o.headers == p.route.headers, f"record 6 is {o.headers!r}, the route lists {p.route.headers!r}")
    each_offer(ctx, f)


def _route_offer_with_native(raw):
    """True when bytes that failed to parse as an Offer still carry route_scope and a native record."""
    try:
        types = {r.type for r in codec.parse_stream(raw)}
    except BnapError:
        return False
    return 4 in types and of.NATIVE in types


@case("OFR-ROUTE-CLASSES", "4.3", "MUST", "route-scope offers list only class S and A schemes and no native")
def ofr_route_classes(ctx):
    probs, n = [], 0
    for p in ctx.all_probes():
        # parse_offer refuses a route-scope offer with a native record (MALFORMED),
        # so such an offer shows up here, among the offers that did not parse.
        for e in p.parse_errors():
            if _route_offer_with_native(e.raw):
                probs.append(f"{p.route.id}: native record in a route-scope offer ({e})")
        for raw, o in p.offers:
            n += 1
            if not o.route_scope:
                continue
            for e in list(o.pay) + list(o.attest):
                c = ctx.registry.binding(e.scheme)
                if c not in ("S", "A"):
                    probs.append(f"{p.route.id}: {e.scheme} (class {c}) in a route-scope offer")
    if n == 0 and not probs:
        raise Skip("no offers")
    check(not probs, "; ".join(probs[:5]) + (f" (+{len(probs) - 5} more)" if len(probs) > 5 else ""))


@case("OFR-CLASS-RULES", "7", "MUST", "no gate-built offer breaks the class, metering or quota rules")
def ofr_class_rules(ctx):
    def f(p, raw, o):
        v = of.offer_rule_violations(o, ctx.registry)
        check(not v, ", ".join(v))
    each_offer(ctx, f)


@case("OFR-NATIVE-EMBED", "4.2", "MUST", "every native artifact embeds the offer's OfferID")
def ofr_native_embed(ctx):
    seen = []

    def f(p, raw, o):
        for n in o.native:
            seen.append(n.kind)
            if n.kind == "bolt11":
                try:
                    inv = ln.decode_bolt11(n.data.decode("ascii"))
                except (ValueError, UnicodeDecodeError) as e:
                    raise Fail(f"the bolt11 native is not a valid BOLT 11 invoice: {e}") from None
                check(inv.description_hash == o.offer_id, "bolt11 description hash is not the OfferID")
            elif n.kind == "l402-macaroon":
                m = ln.parse_macaroon(n.data)
                check(m.caveat_value("bnap_offer") == o.offer_id.hex(), "macaroon has no bnap_offer = OfferID caveat")
            elif n.kind == "mpp-challenge":
                params = json.loads(n.data)
                check(ln.mpp_offer_id(params.get("id", "")) == o.offer_id, "MPP id does not carry the OfferID")
    each_offer(ctx, f)
    if not seen:
        raise Skip("no native records offered")


@case("OFR-NATIVE-MATCH", "9.3", "SHOULD", "native challenges equal native entries of a BNAP offer in the same 402")
def ofr_native_match(ctx):
    probs, n = [], 0
    for p in ctx.all_probes():
        datas = {e.data for _, o in p.offers for e in o.native}
        for ch in p.natives():
            n += 1
            ok = False
            if ch.scheme.upper() in ("L402", "LSAT"):
                import base64
                try:
                    mac = base64.b64decode(ch.params.get("macaroon") or ch.params.get("token") or "")
                except ValueError:
                    mac = b""
                ok = mac in datas and (ch.params.get("invoice", "").encode() in datas)
            elif ch.scheme == "Payment":
                ok = ln.mpp_challenge_json(ch.params) in datas
            else:
                continue
            if not ok:
                probs.append(f"{p.route.id}: {ch.scheme} challenge matches no native entry")
    if n == 0:
        raise Skip("no native challenges")
    check(not probs, "; ".join(probs))


@case("OFR-NONCE-FRESH", "12", "SHOULD", "exact-scope offers carry a fresh random nonce on every 402")
def ofr_nonce_fresh(ctx):
    hit = ctx.find(lambda o: not o.route_scope)
    if hit is None:
        raise Skip("no exact-scope offers")
    p, raw, o = hit
    again = ctx.probe(p.route, fresh=True)
    other = [x for _, x in again.offers if not x.route_scope]
    check(other, "the second 402 had no exact-scope offer")
    check(other[0].nonce != o.nonce, "two 402s for the same request reused the nonce")
    check(len(set(o.nonce)) > 2, "the nonce does not look random")


@case("OFR-ROUTE-REUSE", "5.1", "MUST", "one route-scope offer per route per interval, the same to every request")
def ofr_route_reuse(ctx):
    hit = ctx.find(lambda o: o.route_scope)
    if hit is None:
        raise Skip("no route-scope offers")
    p, raw, o = hit
    ids = [o.offer_id]
    for _ in range(2):
        q = ctx.probe(p.route, fresh=True)
        ids += [x.offer_id for _, x in q.offers if x.route_scope]
    check(len(set(ids)) < len(ids), "every 402 minted a new route-scope offer (nothing bounds the cache)")


@case("OFR-GREASE", "2", "SHOULD", "offers carry a GREASE record")
def ofr_grease(ctx):
    def f(p, raw, o):
        check(o.grease_types(), "no GREASE record")
    each_offer(ctx, f)


@case("OFR-LIFETIME", "12", "SHOULD", "offer lifetimes are minutes for exact scope and hours at most for route scope")
def ofr_lifetime(ctx):
    now = ctx.now()

    def f(p, raw, o):
        life = o.expires - now
        lim = 86400 if o.route_scope else 3600
        check(life <= lim, f"{'route' if o.route_scope else 'exact'} offer lives {life} s")
    each_offer(ctx, f)

# ================================================================ 2, 5 and 8: credentials the gate must refuse


def probe_offer(ctx):
    """Any exact-scope offer outside special roles, else any offer."""
    hit = ctx.find(lambda o: not o.route_scope) or ctx.find(lambda o: True)
    if hit is None:
        raise Skip("no offers")
    return hit


def scheme_cred(raw, o, extra=(), version=1, offer_id=False, pay=None, attest=None, binding=None):
    pay = pay if pay is not None else (cr.SchemeItem(o.pay[0].scheme, b"conformance garbage", None) if o.pay else None)
    attest = attest if attest is not None else ([] if pay else [cr.SchemeItem(o.attest[0].scheme, b"x", None)])
    return cr.build_credential(offer=None if offer_id else raw, offer_id=o.offer_id if offer_id else None, pay=pay,
                               attest=attest, binding=binding, extra=list(extra), version=version)


@case("ERR-BASE64", "10.2", "MUST", "a BNAP-Credential that is not base64url is MALFORMED", profiles=WITH_CREDENTIALS)
def err_base64(ctx):
    p, raw, o = probe_offer(ctx)
    ex = ctx.request(p.req, raw_credential=b64u(scheme_cred(raw, o)) + "==", label="padded")
    expect_error(ex, "MALFORMED")


@case("ERR-TOO-LARGE", "2", "MUST", "a credential over the size limit is TOO_LARGE, checked before parsing",
      profiles=WITH_CREDENTIALS)
def err_too_large(ctx):
    p, raw, o = probe_offer(ctx)
    cap = min(ctx.limits()["max_credential"], cr.HTTP_MAX_CREDENTIAL)
    ex = ctx.request(p.req, credential=b"\xff" * (cap + 1), label="oversize")
    expect_error(ex, "TOO_LARGE")


def pad_offer(raw, size):
    """raw with one experimental odd record added so that it is exactly size bytes. The signatures no
    longer verify, which does not matter: 4.4 checks the size first."""
    recs = [(r.type, r.value) for r in codec.parse_stream(raw)]
    t = codec.EXPERIMENTAL[0] + 1
    while any(x == t for x, _ in recs):
        t += 2
    n = size - len(raw) - len(codec.bigsize(t)) - 1
    while n > 0 and len(raw) + len(codec.bigsize(t)) + len(codec.bigsize(n)) + n > size:
        n -= 1
    out = codec.tlv(sorted(recs + [(t, bytes(n))])) if n >= 0 else b""
    if len(out) != size:
        raise Skip(f"cannot pad a {len(raw)}-byte offer to exactly {size} bytes")
    return out


@case("ERR-OFFER-TOO-LARGE", "4.4", "MUST", "an inline offer over max_offer, in a credential under the size "
      "limit, is TOO_LARGE before any other offer check", profiles=WITH_CREDENTIALS)
def err_offer_too_large(ctx):
    p, raw, o = probe_offer(ctx)
    lim = ctx.limits()
    big = pad_offer(raw, lim["max_offer"] + 1)
    cred = scheme_cred(big, o)
    cap = min(lim["max_credential"], cr.HTTP_MAX_CREDENTIAL)
    if len(cred) >= cap:
        raise Skip(f"an offer of max_offer + 1 = {len(big)} bytes does not fit a credential under {cap} bytes")
    ex = ctx.request(p.req, credential=cred, label=f"inline offer of {len(big)} bytes")
    try:
        expect_error(ex, "TOO_LARGE")
    except Fail as e:
        raise Fail(f"{e}; a {len(cred)}-byte credential carried a {len(big)}-byte offer, one byte over "
                   f"max_offer {lim['max_offer']}") from None


@case("ERR-FIELD-MIN", "10.2", "MUST", "the gate reads a BNAP-Credential field of 12,288 bytes",
      profiles=WITH_CREDENTIALS)
def err_field_min(ctx):
    p, raw, o = probe_offer(ctx)
    base = cr.build_credential(offer_id=o.offer_id, pay=cr.SchemeItem(o.pay[0].scheme, b"", None)) if o.pay else None
    if base is None:
        raise Skip("needs an offer with pay")
    n = 9216 - len(base) - 4
    cred = base + codec.tlv([(14, bytes(n))])
    while len(cred) > 9216:
        n -= 1
        cred = base + codec.tlv([(14, bytes(n))])
    check(len(b64u(cred)) >= 12280, "internal: field too short")
    ex = ctx.request(p.req, credential=cred, label="12288-char field")
    check(ex.res is not None, "no response")
    check(ex.error is not None, f"HTTP {ex.res.status} without BNAP-Error: the field was not read by the gate")
    check(ex.code == "MALFORMED", f"expected MALFORMED (unknown even type), got {ex.describe()}")


@case("ERR-NONMINIMAL", "2", "MUST", "a non-minimal BigSize is MALFORMED", profiles=WITH_CREDENTIALS)
def err_nonminimal(ctx):
    p, raw, o = probe_offer(ctx)
    good = scheme_cred(raw, o, offer_id=True)
    ex = ctx.request(p.req, credential=b"\xfd\x00\x00" + good[1:], label="fd0000 type")
    expect_error(ex, "MALFORMED")


@case("ERR-ORDER", "2", "MUST", "records out of order are MALFORMED", profiles=WITH_CREDENTIALS)
def err_order(ctx):
    p, raw, o = probe_offer(ctx)
    recs = [(r.type, r.value) for r in codec.parse_stream(scheme_cred(raw, o, offer_id=True))]
    ex = ctx.request(p.req, credential=codec.tlv_unsorted(list(reversed(recs))), label="reversed")
    expect_error(ex, "MALFORMED")


@case("ERR-UNKNOWN-EVEN", "2", "MUST", "an unknown even record is MALFORMED", profiles=WITH_CREDENTIALS)
def err_unknown_even(ctx):
    p, raw, o = probe_offer(ctx)
    ex = ctx.request(p.req, credential=scheme_cred(raw, o, extra=[(14, b"\x00")], offer_id=True), label="type 14")
    expect_error(ex, "MALFORMED")


def item_with(item, extra):
    """A scheme item's bytes with extra (type, value) records added, in type order."""
    raw = item.encode() if isinstance(item, cr.SchemeItem) else item
    return codec.tlv(sorted([(r.type, r.value) for r in codec.parse_stream(raw)] + list(extra)))


def item_probe(ctx, ext=None):
    """(probe, raw offer, offer, attest item, pay scheme). Where an offer has a DPoP waive the item is a
    valid proof (with ext in its Context), so a gate that skips a parse rule shows an admission. Otherwise
    a dummy item, which such a gate refuses with another code than MALFORMED."""
    hit = ctx.find(lambda o: dpop_waive(o) and not o.route_scope) or ctx.find(dpop_waive)
    if hit is not None:
        p, raw, o = hit
        cred, _, _ = ctx.dpop_credential(p.req, raw, o, ext=ext)
        # Read the item from the records: the runner's own parser refuses an even extension in ext.
        item = codec.parse_entry_list(codec.as_dict(codec.parse_stream(cred))[6])[0]
    else:
        p, raw, o = probe_offer(ctx)
        item = cr.SchemeItem(o.attest[0].scheme if o.attest else DPOP, b"x", None).encode()
    return p, raw, o, item, (o.pay[0].scheme if o.pay else "httpauth:L402")


@case("ERR-NESTED-EVEN", "2", "MUST", "an unknown even record inside an attest item or a pay item is MALFORMED",
      profiles=WITH_CREDENTIALS)
def err_nested_even(ctx):
    p, raw, o, item, pay_scheme = item_probe(ctx)
    att = cr.build_credential(offer=raw, attest=[item_with(item, [(6, b"\x00")])])
    ex = ctx.request(p.req, credential=att, label="even type 6 in the attest item")
    try:
        expect_error(ex, "MALFORMED")
    except Fail as e:
        raise Fail(f"attest item: {e}; an unknown even record inside a scheme item was not refused") from None
    pay = item_with(cr.SchemeItem(pay_scheme, b"conformance garbage", None), [(6, b"\x00")])
    ex = ctx.request(p.req, credential=cr.build_credential(offer=raw, pay=pay), label="even type 6 in the pay item")
    try:
        expect_error(ex, "MALFORMED")
    except Fail as e:
        raise Fail(f"pay item: {e}; an unknown even record inside a scheme item was not refused") from None


@case("ERR-EXT-EVEN", "5.1", "MUST", "an even-typed extension in ext is MALFORMED", profiles=WITH_CREDENTIALS)
def err_ext_even(ctx):
    ext = codec.tlv([(2, b"x")])
    p, raw, o, item, _ = item_probe(ctx, ext=ext)
    cred = cr.build_credential(offer=raw, attest=[item], ext=ext)
    ex = ctx.request(p.req, credential=cred, label="even extension 2 in ext")
    try:
        expect_error(ex, "MALFORMED")
    except Fail as e:
        raise Fail(f"{e}; an unknown even extension inside ext was not refused, so the gate does not parse ext") \
            from None


@case("ERR-VERSION", "8.2", "MUST", "version 2 is VERSION, HTTP 400", profiles=WITH_CREDENTIALS)
def err_version(ctx):
    p, raw, o = probe_offer(ctx)
    ex = ctx.request(p.req, credential=scheme_cred(raw, o, version=2), label="version 2")
    expect_error(ex, "VERSION")


@case("ERR-OFFER-VERSION", "4.4", "MUST", "an inline offer of version 2 in a version 1 credential is VERSION, HTTP "
      "400, before authenticity and before any plug", profiles=WITH_CREDENTIALS)
def err_offer_version(ctx):
    p, raw, o = probe_offer(ctx)
    # Record 0 of the probe offer set to 2: its MAC and offer_sig no longer verify, and the value body is
    # garbage, so a gate that checks authenticity first answers BAD_OFFER and one that calls a plug first
    # answers BAD_CREDENTIAL. 4.4 step 2 checks the version before either.
    v2 = codec.tlv([(r.type, codec.tu64(2) if r.type == 0 else r.value) for r in o.records])
    ex = ctx.request(p.req, credential=scheme_cred(v2, o), label="offer version 2")
    check(ex.code != "BAD_OFFER", "BAD_OFFER for a version 2 offer: the gate checked its authenticity before its "
          "version (4.4 steps 2 and 3)")
    check(ex.code != "BAD_CREDENTIAL", "BAD_CREDENTIAL for a version 2 offer: a scheme plug ran before the offer "
          "version was checked (4.4)")
    expect_error(ex, "VERSION")


@case("ERR-OFFER-XOR", "5.1", "MUST", "both offer and offer_id, or neither, is MALFORMED", profiles=WITH_CREDENTIALS)
def err_offer_xor(ctx):
    p, raw, o = probe_offer(ctx)
    pay = cr.SchemeItem(o.pay[0].scheme, b"x", None) if o.pay else None
    att = [] if pay else [cr.SchemeItem(o.attest[0].scheme, b"x", None)]
    both = cr.build_credential(offer=raw, offer_id=o.offer_id, pay=pay, attest=att)
    neither = cr.build_credential(pay=pay, attest=att)
    expect_error(ctx.request(p.req, credential=both, label="both"), "MALFORMED")
    expect_error(ctx.request(p.req, credential=neither, label="neither"), "MALFORMED")


@case("ERR-ATTEST-ORDER", "5.1", "MUST", "an attest list out of order or with a scheme twice is MALFORMED",
      profiles=WITH_CREDENTIALS)
def err_attest_order(ctx):
    p, raw, o = probe_offer(ctx)
    a = cr.SchemeItem("httpauth:DPoP", b"a", None).encode()
    b = cr.SchemeItem("httpsig:web-bot-auth", b"b", None).encode()
    expect_error(ctx.request(p.req, credential=cr.build_credential(offer=raw, attest=[b, a]), label="order"),
                 "MALFORMED")
    expect_error(ctx.request(p.req, credential=cr.build_credential(offer=raw, attest=[a, a]), label="twice"),
                 "MALFORMED")


@case("ERR-BINDING-NO-S", "5.1", "MUST", "a binding when no chosen scheme is class S is MALFORMED",
      profiles=WITH_CREDENTIALS)
def err_binding_no_s(ctx):
    p, raw, o = probe_offer(ctx)
    cred = cr.build_credential(offer=raw, attest=[cr.SchemeItem(DPOP, b"x", None)], binding=os.urandom(32))
    expect_error(ctx.request(p.req, credential=cred, label="binding, DPoP only"), "MALFORMED")


@case("ERR-BAD-OFFER-FLIP", "4.4", "MUST", "a flipped bit in any signed record of the offer is BAD_OFFER",
      profiles=WITH_CREDENTIALS)
def err_bad_offer_flip(ctx):
    p, raw, o = probe_offer(ctx)
    probs, n = [], 0
    for r in o.records:
        if codec.is_sig_range(r.type) or not r.value or r.type in (0,):
            continue
        flipped = codec.tlv([(x.type, (x.value[:-1] + bytes([x.value[-1] ^ 1])) if x.type == r.type else x.value)
                             for x in o.records])
        code, _ = (None, None)
        try:
            of.parse_offer(flipped, 1 << 20)
        except BnapError as e:
            code = e.code
        n += 1
        ex = ctx.request(p.req, credential=scheme_cred(flipped, o), label=f"flip {r.type}")
        try:
            expect_error(ex, code or "BAD_OFFER")
        except Fail as e:
            probs.append(f"record {r.type}: {e}")
    check(n, "no signed records to flip")
    check(not probs, "; ".join(probs[:4]))


@case("ERR-BAD-OFFER-ID", "5.1", "MUST", "an unknown OfferID is BAD_OFFER with a fresh offer", profiles=WITH_CREDENTIALS)
def err_bad_offer_id(ctx):
    p, raw, o = probe_offer(ctx)
    cred = cr.build_credential(offer_id=os.urandom(32), pay=cr.SchemeItem(o.pay[0].scheme, b"x", None) if o.pay else None,
                               attest=[] if o.pay else [cr.SchemeItem(o.attest[0].scheme, b"x", None)])
    expect_error(ctx.request(p.req, credential=cred, label="unknown id"), "BAD_OFFER", fresh=True)


@case("ERR-ADVANCE-KEY", "4.4", "MUST", "an offer without mac under a key the gate does not hold is BAD_OFFER",
      profiles=WITH_CREDENTIALS)
def err_advance_key(ctx):
    p, raw, o = probe_offer(ctx)
    sk = os.urandom(32)
    fields = [(r.type, r.value) for r in o.records if not codec.is_sig_range(r.type) and r.type not in (14, 24)]
    fields += [(14, schnorr_pub(sk)), (24, codec.tu64(ctx.now() - 5))]
    forged = of.sign_offer(fields, sk, None)
    expect_error(ctx.request(p.req, credential=scheme_cred(forged, of.parse_offer(forged, 1 << 20)), label="forged"),
                 "BAD_OFFER")


@case("ERR-WRONG-SCOPE-EXACT", "4.3", "MUST", "an exact-scope offer sent with another request is WRONG_SCOPE",
      profiles=WITH_CREDENTIALS)
def err_wrong_scope_exact(ctx):
    hit = ctx.find(lambda o: not o.route_scope and dpop_waive(o)) or ctx.find(lambda o: not o.route_scope)
    if hit is None:
        raise Skip("no exact-scope offers")
    p, raw, o = hit
    other = p.req.with_target(p.req.target + ("&" if "?" in p.req.target else "?") + "conformance=other")
    if dpop_waive(o):
        cred, _, _ = ctx.dpop_credential(p.req, raw, o)
    else:
        cred = scheme_cred(raw, o)
    expect_error(ctx.request(other, credential=cred, label="other request"), "WRONG_SCOPE", fresh=True)


@case("ERR-WRONG-SCOPE-ROUTE", "4.3", "MUST", "a route-scope offer used on another route is WRONG_SCOPE",
      profiles=WITH_CREDENTIALS)
def err_wrong_scope_route(ctx):
    hit = ctx.find(lambda o: o.route_scope)
    if hit is None:
        raise Skip("no route-scope offers")
    p, raw, o = hit
    others = [r for r in ctx.plain_routes() if r.id != p.route.id]
    if not others:
        raise Skip("needs a second route")
    req = ctx.make_req(others[0])
    expect_error(ctx.request(req, credential=scheme_cred(raw, o), label="other route"), "WRONG_SCOPE", fresh=True)


@case("ERR-NOT-OFFERED", "4.4", "MUST", "a scheme the offer does not list is NOT_OFFERED", profiles=WITH_CREDENTIALS)
def err_not_offered(ctx):
    p, raw, o = probe_offer(ctx)
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem("vnd.conformance.not-offered", b"x", None))
    expect_error(ctx.request(p.req, credential=cred, label="pay not offered"), "NOT_OFFERED")
    cred = cr.build_credential(offer=raw, attest=[cr.SchemeItem("vnd.conformance.not-offered", b"x", None)])
    expect_error(ctx.request(p.req, credential=cred, label="attest not offered"), "NOT_OFFERED")


@case("ERR-BAD-CREDENTIAL", "8.2", "MUST", "a value credential the scheme rejects is BAD_CREDENTIAL",
      profiles=WITH_CREDENTIALS)
def err_bad_credential(ctx):
    hit = ctx.find(lambda o: any(ctx.registry.binding(e.scheme) in ("O", "A") for e in o.pay))
    if hit is None:
        raise Skip("no offer with a class O or A value scheme")
    p, raw, o = hit
    e = next(e for e in o.pay if ctx.registry.binding(e.scheme) in ("O", "A"))
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem(e.scheme, b"conformance garbage", None))
    ex = ctx.request(p.req, credential=cred, label="garbage body")
    expect_error(ex, "BAD_CREDENTIAL")


@case("ERR-SCHEME-CODE", "8.2", "SHOULD", "BAD_CREDENTIAL carries a scheme_code namespaced by the scheme ID",
      profiles=WITH_CREDENTIALS)
def err_scheme_code(ctx):
    hits = [x for x in ctx.log if x.code == "BAD_CREDENTIAL"]
    if not hits:
        raise Skip("no BAD_CREDENTIAL seen")
    bad = [x.error.scheme_code for x in hits if not (x.error.scheme_code and "/" in x.error.scheme_code)]
    check(not bad, f"scheme_code missing or not namespaced: {bad[:3]}")


@case("ERR-BINDING", "5.3", "MUST", "a class S credential whose binding cannot match is BINDING",
      profiles=WITH_CREDENTIALS)
def err_binding(ctx):
    hit = ctx.find(lambda o: any(ctx.registry.binding(e.scheme) == "S" for e in o.pay))
    if hit is None:
        raise Skip("no offer with a class S value scheme")
    p, raw, o = hit
    e = next(e for e in o.pay if ctx.registry.binding(e.scheme) == "S")
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem(e.scheme, b"conformance", b"\x00" * 64),
                               binding=os.urandom(32))
    ex = ctx.request(p.req, credential=cred, label="random binding")
    if ex.code == "BAD_CREDENTIAL":
        raise Fail("the scheme rejected the credential before the binding was checked "
                   "(5.3: reject a mismatch with BINDING)")
    expect_error(ex, "BINDING")


@case("ERR-TWO-VALUE", "5.4", "MUST", "a BNAP pay and a native value credential in one request is MALFORMED",
      profiles=WITH_CREDENTIALS)
def err_two_value(ctx):
    p, raw, o = probe_offer(ctx)
    if not o.pay:
        raise Skip("needs an offer with pay")
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem(o.pay[0].scheme, b"x", None))
    ex = ctx.request(p.req, credential=cred, extra=[("Authorization", "L402 AgJ4:" + "00" * 32)], label="two")
    expect_error(ex, "MALFORMED")

# ================================================================ attestation-only flows


def admit_once(ctx, label, **kw):
    p, raw, o = admitted_dpop(ctx)
    cred, c, dg = ctx.dpop_credential(p.req, raw, o, **kw)
    ex = ctx.request(p.req, credential=cred, label=label)
    return p, raw, o, cred, c, dg, ex


def first_admission(ctx):
    with ctx.lock:
        if "first" not in ctx.share:
            ctx.share["first"] = admit_once(ctx, "first admission")
        return ctx.share["first"]


@case("ATT-ADMIT", "7", "MUST", "an attestation-only credential with a verified waive is admitted",
      profiles=WITH_CREDENTIALS)
def att_admit(ctx):
    p, raw, o, cred, c, dg, ex = first_admission(ctx)
    r = expect_admitted(ex)
    check(r.status == rs.OK, f"status {r.status_name}")
    check(r.charged == 0, f"charged {r.charged} after a waive")


@case("RCPT-ACK", "8.1", "MUST", "the receipt parses and its ack verifies under receipt_key",
      profiles=WITH_CREDENTIALS)
def rcpt_ack(ctx):
    *_, ex = first_admission(ctx)
    r = expect_admitted(ex)
    check(rs.verify_ack(r), "ack does not verify")


@case("RCPT-KEY", "9.3", "MUST", "receipt_key is listed for use receipt with not_after >= settled_at",
      profiles=WITH_CREDENTIALS)
def rcpt_key(ctx):
    *_, ex = first_admission(ctx)
    r = expect_admitted(ex)
    check(of.key_listed(ctx.pin_keys(), r.receipt_key, "receipt", r.settled_at), "receipt_key not listed")


@case("RCPT-BOUND", "8.1", "MUST", "the receipt names this request's Digest and OfferID",
      profiles=WITH_CREDENTIALS)
def rcpt_bound(ctx):
    p, raw, o, cred, c, dg, ex = first_admission(ctx)
    r = expect_admitted(ex)
    check(r.digest == dg, "digest is not the Digest of the request")
    check(r.offer_id == o.offer_id, "offer_id is not the OfferID")


@case("RCPT-FIELDS", "8.1", "MUST", "status, charged and settled_at are present and current; no replayed flag",
      profiles=WITH_CREDENTIALS)
def rcpt_fields(ctx):
    *_, ex = first_admission(ctx)
    r = expect_admitted(ex)
    check(not r.replayed, "replayed set on a first admission")
    check(abs(ctx.now() - r.settled_at) <= 60 + ex.res.elapsed, f"settled_at {r.settled_at} is not current")
    chk = rs.client_check_receipt(ex.receipt_raw, now=ctx.now(), pin_keys=ctx.pin_keys())
    check(chk.ok, "client receipt rules: " + str(chk.reason))


@case("RCPT-SIZE", "2", "MUST", "Responses fit max_response", profiles=WITH_CREDENTIALS)
def rcpt_size(ctx):
    lim = ctx.limits()["max_response"]
    big = [len(x.receipt_raw) for x in ctx.log if x.receipt_raw and len(x.receipt_raw) > lim]
    if not any(x.receipt_raw for x in ctx.log):
        raise Skip("no receipts seen")
    check(not big, f"receipts over {lim} bytes: {big[:3]}")


@case("REPLAY-RECORDED", "6.4", "MUST", "a replay returns the recorded outcome with replayed set; the action "
      "does not run again", profiles=WITH_CREDENTIALS)
def replay_recorded(ctx):
    p, raw, o, cred, c, dg, ex = first_admission(ctx)
    r1 = expect_admitted(ex)
    ex2 = ctx.request(p.req, credential=cred, label="replay")
    r2 = expect_admitted(ex2)
    check(r2.replayed, "replayed is not set: the credential ran again")
    check(r2.settled_at == r1.settled_at, "settled_at changed on replay")
    check(r2.charged == r1.charged and r2.scheme_result == r1.scheme_result, "charged or scheme_result changed")
    check(rs.verify_ack(r2) and r2.digest == dg, "the replayed receipt is not signed over this request's Digest")
    if ex.res.body and ex2.res.body:
        check(ex2.res.body == ex.res.body, "the replay returned another application response")


@case("REPLAY-STATUS-STABLE", "6.4", "MUST", "the status never flips on replay", profiles=WITH_CREDENTIALS)
def replay_status(ctx):
    p, raw, o, cred, c, dg, ex = first_admission(ctx)
    r1 = expect_admitted(ex)
    for i in range(3):
        r = expect_admitted(ctx.request(p.req, credential=cred, label=f"replay {i}"))
        check(r.status == r1.status, f"replay {i} reports {r.status_name}, the outcome was {r1.status_name}")


@case("REPLAY-FAILED", "6.4", "MUST", "a FAILED outcome replays as FAILED", profiles=WITH_CREDENTIALS,
      needs=("role:fail",))
def replay_failed(ctx):
    route = ctx.role_route("fail")
    p = ctx.probe(route)
    hit = next(((raw, o) for raw, o in p.offers if dpop_waive(o)), None)
    if hit is None:
        raise Skip("the fail route offers no DPoP waive")
    raw, o = hit
    cred, _, _ = ctx.dpop_credential(p.req, raw, o)
    r1 = expect_admitted(ctx.request(p.req, credential=cred, label="fail"))
    check(r1.status == rs.FAILED, f"the failing action settled {r1.status_name}")
    for i in range(2):
        r = expect_admitted(ctx.request(p.req, credential=cred, label=f"fail replay {i}"))
        check(r.replayed and r.status == rs.FAILED, f"replay {i}: {r.status_name}, replayed={r.replayed}")


@case("REPLAY-BY-ID", "5.1", "MUST", "the same credential naming its route offer by OfferID replays",
      profiles=WITH_CREDENTIALS)
def replay_by_id(ctx):
    hit = ctx.find(lambda o: o.route_scope and dpop_waive(o))
    if hit is None:
        raise Skip("no route-scope offer with a DPoP waive")
    p, raw, o = hit
    req = ctx.make_req(p.route, leaf="by-id-" + b64u(os.urandom(4)))
    key = ctx.dpop_key("by-id")
    cred, c, dg = ctx.dpop_credential(req, raw, o, key=key, jti="by-id")
    r1 = expect_admitted(ctx.request(req, credential=cred, label="inline"))
    # Rebuild the same credential with offer_id: same Context, bodies and IDs, so the same ReplayKey.
    item = cr.parse_credential(cred).attest[0]
    by_id = cr.build_credential(offer_id=o.offer_id, attest=[item])
    r2 = expect_admitted(ctx.request(req, credential=by_id, label="by id"))
    check(r2.replayed and r2.settled_at == r1.settled_at, "offer by reference did not find the recorded outcome")


@case("ATT-UNKNOWN-ODD", "2", "MUST", "unknown odd records outside ext do not affect processing",
      profiles=WITH_CREDENTIALS)
def att_unknown_odd(ctx):
    p, raw, o = admitted_dpop(ctx)
    cred, c, dg = ctx.dpop_credential(p.req, raw, o, extra=[(13, b"\x01"), (3000000011, b"\x2a")])
    r1 = expect_admitted(ctx.request(p.req, credential=cred, label="odd records"))
    check(not r1.replayed, "first send flagged replayed")
    check(r1.digest == dg, "the receipt digest is not the Digest without the unknown odd records: they entered "
          "processing (a class S witness over the Digest would no longer verify)")
    plain = cr.build_credential(offer=raw, attest=cr.parse_credential(cred).attest)
    r2 = expect_admitted(ctx.request(p.req, credential=plain, label="without them"))
    check(r2.replayed, "dropping unknown odd records changed the ReplayKey")


@case("ATT-NESTED-ODD", "2", "MUST", "an unknown odd record inside an attest item is ignored and stays out of "
      "the Digest and the ReplayKey", profiles=WITH_CREDENTIALS)
def att_nested_odd(ctx):
    p, raw, o = admitted_dpop(ctx)
    cred, c, dg = ctx.dpop_credential(p.req, raw, o)
    item = cr.parse_credential(cred).attest[0]
    odd = cr.build_credential(offer=raw, attest=[item_with(item, [(5, b"\x01")])])
    try:
        r1 = expect_admitted(ctx.request(p.req, credential=odd, label="odd type 5 in the attest item"))
    except Fail as e:
        raise Fail(f"{e}; an unknown odd record inside a scheme item must be ignored") from None
    check(r1.status == rs.OK and not r1.replayed, f"first send settled {r1.status_name}, replayed={r1.replayed}")
    check(r1.digest == dg, "the receipt digest is not the Digest without the odd item record: it entered processing")
    r2 = expect_admitted(ctx.request(p.req, credential=cred, label="the same credential without it"))
    check(r2.replayed and r2.settled_at == r1.settled_at,
          "dropping the odd item record changed the ReplayKey, so a party on the path can turn a retry into a "
          "second run")


@case("ATT-EMPTY-FORMS", "2", "MUST", "an empty ext record means the same as no ext record",
      profiles=WITH_CREDENTIALS)
def att_empty_forms(ctx):
    p, raw, o = admitted_dpop(ctx)
    cred, _, _ = ctx.dpop_credential(p.req, raw, o)
    item = cr.parse_credential(cred).attest
    with_ext = cr.build_credential(offer=raw, attest=item, ext=b"")
    r1 = expect_admitted(ctx.request(p.req, credential=with_ext, label="empty ext"))
    check(not r1.replayed, "first send flagged replayed")
    r2 = expect_admitted(ctx.request(p.req, credential=cred, label="no ext"))
    check(r2.replayed, "absent and empty ext gave different Contexts or ReplayKeys")


@case("ATT-EXT-BOUND", "5.2", "MUST", "the Context covers ext: a non-empty ext is admitted under H(ext) and the "
      "receipt names that Digest; the same body with an altered ext is refused", profiles=WITH_CREDENTIALS)
def att_ext_bound(ctx):
    p, raw, o = admitted_dpop(ctx)
    ext = codec.tlv([(1, b"bnap-conformance")])  # one odd-typed extension, which the gate ignores
    cred, c, dg = ctx.dpop_credential(p.req, raw, o, ext=ext)
    try:
        r = expect_admitted(ctx.request(p.req, credential=cred, label="non-empty ext"))
    except Fail as e:
        raise Fail(f"{e}; a DPoP proof over the Context with H(ext) did not count, so the gate leaves ext out "
                   "of its Context or refuses an odd extension it must ignore") from None
    check(r.status == rs.OK and not r.replayed, f"first send settled {r.status_name}, replayed={r.replayed}")
    check(r.digest == dg, "the receipt digest is not the Digest over a Context with H(ext): the gate left ext out")
    item = cr.parse_credential(cred).attest
    altered = cr.build_credential(offer=raw, attest=item, ext=codec.tlv([(1, b"bnap-conformancE")]))
    try:
        expect_not_admitted(ctx.request(p.req, credential=altered, label="ext altered on the path"))
    except Fail as e:
        raise Fail(f"{e}: the same body with an altered ext was admitted, so ext is not bound by the Context") \
            from None


@case("ATT-BODY-ONLY", "5.1", "MUST", "an adapter reads what it verifies from the body, never from request fields",
      profiles=WITH_CREDENTIALS)
def att_body_only(ctx):
    p, raw, o = admitted_dpop(ctx)
    good, c, _ = ctx.dpop_credential(p.req, raw, o)
    proof = codec.parse_stream(cr.parse_credential(good).attest[0].body)[1].value.decode()
    weak, _, _ = ctx.dpop_credential(p.req, raw, o, omit_ctx=True)
    ex = ctx.request(p.req, credential=weak, extra=[("DPoP", proof)], label="proof in the DPoP field only")
    expect_not_admitted(ex)


@case("ATT-CANONICAL-BODY", "5.1", "MUST", "a body with bytes the scheme does not verify is refused: an extra "
      "record, and the high-S copy of an admitted DPoP proof, which must not settle as a new outcome",
      profiles=WITH_CREDENTIALS)
def att_canonical_body(ctx):
    p, raw, o = admitted_dpop(ctx)
    good, _, _ = ctx.dpop_credential(p.req, raw, o)
    item = cr.parse_credential(good).attest[0]
    body = item.body + codec.tlv([(4, b"x")])
    bad = cr.build_credential(offer=raw, attest=[cr.SchemeItem(DPOP, body, None)])
    expect_not_admitted(ctx.request(p.req, credential=bad, label="extra record in the body"))
    # Signature malleability: plain ECDSA also accepts (r, n - s). The profile requires low-S, so the
    # copy a party on the path can make of an admitted proof must not count. Its body hash, and so its
    # ReplayKey, differs from the original's: admitted, it would run the action a second time.
    r1 = expect_admitted(ctx.request(p.req, credential=good, label="canonical body"))
    check(r1.status == rs.OK and not r1.replayed, f"the canonical body settled {r1.status_name}, "
          f"replayed={r1.replayed}")
    mall = cr.build_credential(offer=raw, attest=[cr.SchemeItem(DPOP, dpop.other_s_body(item.body), None)])
    ex = ctx.request(p.req, credential=mall, label="high-S copy of the admitted proof")
    r2 = ex.receipt()
    check(r2 is None or r2.replayed, f"the high-S copy of an admitted proof settled as a new outcome "
          f"({ex.describe()}): one client proof ran the action twice (profile {dpop.PROFILE} requires s <= n/2)")
    if r2 is None:
        expect_not_admitted(ex)


@case("SCOPE-BODY-HASH", "10.1", "MUST", "the gate hashes the content itself and ignores Content-Digest",
      profiles=WITH_CREDENTIALS)
def scope_body_hash(ctx):
    hit = ctx.find(lambda o: dpop_waive(o) and o.route_scope) or ctx.find(dpop_waive)
    if hit is None:
        raise Skip("no offer with a DPoP waive")
    p, raw, o = hit
    if p.req.body is None:
        raise Skip("the route takes no content")
    req = ctx.make_req(p.route, leaf="digest-" + b64u(os.urandom(4))) if o.route_scope else p.req
    cred, _, _ = ctx.dpop_credential(req, raw, o)
    ex = ctx.request(req, credential=cred, extra=[("Content-Digest", "sha-256=:" + b64u(bytes(32)) + "=:")],
                     label="wrong Content-Digest")
    expect_admitted(ex)


def host_variant(base):
    """(Host value, how) that reaches the same server as base but spells its authority differently, or
    (None, why not). A host name goes upper case, a loopback address becomes localhost, an address on the
    default port gets the port written out."""
    u = urllib.parse.urlsplit(base)
    host, port = u.hostname, u.port
    tail = f":{port}" if port else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None and any(ch.isalpha() for ch in host):
        return host.upper() + tail, "the host name in upper case"
    if ip is not None and ip.is_loopback:
        return "localhost" + tail, "localhost for a loopback address"
    if port is None:
        lit = f"[{host}]" if ip is not None and ip.version == 6 else host
        return f"{lit}:{443 if u.scheme == 'https' else 80}", "the default port written out"
    return None, "a non-loopback address on an explicit port has no other spelling"


@case("SCOPE-MANIFEST-ORIGIN", "10.1", "MUST", "scope and proof inputs come from the manifest origin, not the Host "
      "field: a credential sent with another spelling of the authority is admitted under the runner's Digest",
      profiles=WITH_CREDENTIALS)
def scope_manifest_origin(ctx):
    host, how = host_variant(ctx.base)
    if host is None:
        raise Skip(how)
    p, raw, o = admitted_dpop(ctx)
    hdr = [("Host", host)]
    ex0 = ctx.request(p.req, extra=hdr, label=f"no credential, Host: {host}")
    offers = [(r, x) for r, x in Probe(p.route, p.req, ex0).offers]
    if ex0.res is None or ex0.res.status != 402 or not offers:
        raise Skip(f"the target does not answer Host: {host} ({how}) with a BNAP 402: {ex0.describe()}")
    for _, x in offers:
        want = hp.route_scope(ctx.origin, p.route.id) if x.route_scope else p.req.action_scope()
        check(x.scope == want, f"the offer minted for Host: {host} names a scope that is not built from the "
                               f"manifest origin {ctx.origin}")
    cred, c, dg = ctx.dpop_credential(p.req, raw, o)
    try:
        r = expect_admitted(ctx.request(p.req, credential=cred, extra=hdr, label=f"credential, Host: {host}"))
    except Fail as e:
        raise Fail(f"{e}; with Host: {host} ({how}) the gate built the action scope or the proof's htu from the "
                   f"Host field instead of the manifest origin {ctx.origin}") from None
    check(r.status == rs.OK and not r.replayed, f"settled {r.status_name}, replayed={r.replayed}")
    check(r.digest == dg, f"with Host: {host} the receipt digest is not the Digest over the manifest origin's scope")


@case("ATT-CONTEXT-BOUND", "5.1", "MUST", "an attestation whose proof does not carry the Context does not count",
      profiles=WITH_CREDENTIALS)
def att_context_bound(ctx):
    p, raw, o = admitted_dpop(ctx)
    cred, _, _ = ctx.dpop_credential(p.req, raw, o, omit_ctx=True)
    expect_not_admitted(ctx.request(p.req, credential=cred, label="no Context claim"))


@case("ATT-CROSS-REQUEST", "4.3", "MUST", "a credential made for one request is refused on another request "
      "of the same route", profiles=WITH_CREDENTIALS)
def att_cross_request(ctx):
    hit = ctx.find(lambda o: o.route_scope and dpop_waive(o))
    if hit is None:
        raise Skip("no route-scope offer with a DPoP waive")
    p, raw, o = hit
    a = ctx.make_req(p.route, leaf="cross-a")
    b = ctx.make_req(p.route, leaf="cross-b")
    cred, _, _ = ctx.dpop_credential(a, raw, o)
    ex = ctx.request(b, credential=cred, label="made for a, sent with b")
    expect_not_admitted(ex)
    check(ex.code not in ("PENDING",), "treated as a replay of another request")


@case("ATT-SAME-KEY", "6.2", "MUST", "the same attestation key under another ReplayKey follows the scheme's "
      "use model (reusable: a new outcome; single: SPENT)", profiles=WITH_CREDENTIALS)
def att_same_key(ctx):
    p, raw, o = admitted_dpop(ctx)
    key = ctx.dpop_key("same-key")
    c1, _, _ = ctx.dpop_credential(p.req, raw, o, key=key, jti="one")
    c2, _, _ = ctx.dpop_credential(p.req, raw, o, key=key, jti="two")
    r1 = expect_admitted(ctx.request(p.req, credential=c1, label="proof 1"))
    ex2 = ctx.request(p.req, credential=c2, label="proof 2")
    model = ctx.registry.use(DPOP)
    if model == "single":
        expect_error(ex2, "SPENT")
    else:
        r2 = expect_admitted(ex2)
        check(not r2.replayed, "another ReplayKey was answered as a replay")
        check(r2.settled_at >= r1.settled_at, "settled_at went backwards")


@case("ATT-CONTEXT-HEADER", "10.2", "MUST", "BNAP-Context equal to the gate's Context is accepted; any other "
      "value is MALFORMED", profiles=WITH_CREDENTIALS)
def att_context_header(ctx):
    p, raw, o = admitted_dpop(ctx)
    cred, c, _ = ctx.dpop_credential(p.req, raw, o)
    bad = ctx.request(p.req, credential=cred, extra=[("BNAP-Context", b64u(os.urandom(32)))], label="wrong context")
    expect_error(bad, "MALFORMED")
    good = ctx.request(p.req, credential=cred, extra=[("BNAP-Context", b64u(c))], label="right context")
    expect_admitted(good)


@case("ATT-UNDERPAID", "7", "MUST", "an attestation-only credential without a waive is UNDERPAID",
      profiles=WITH_CREDENTIALS)
def att_underpaid(ctx):
    hit = ctx.find(lambda o: o.pay and o.attest_entry(DPOP) is not None and o.attest_entry(DPOP).effect == 2)
    if hit is None:
        hit = ctx.find(lambda o: o.pay and o.attest_entry(DPOP) is not None and o.attest_entry(DPOP).effect == 1)
        if hit is None:
            raise Skip("no offer with a DPoP discount or waive and pay entries")
        p, raw, o = hit
        cred, _, _ = ctx.dpop_credential(p.req, raw, o, omit_ctx=True)
    else:
        p, raw, o = hit
        cred, _, _ = ctx.dpop_credential(p.req, raw, o)
    expect_error(ctx.request(p.req, credential=cred, label="no waive"), "UNDERPAID")


@case("ATT-REQUIRED", "7", "MUST", "a required attestation that does not verify is POLICY", profiles=WITH_CREDENTIALS)
def att_required(ctx):
    hit = ctx.find(lambda o: o.attest_entry(DPOP) is not None and o.attest_entry(DPOP).effect == 0)
    if hit is None:
        raise Skip("no offer with a required DPoP attestation")
    p, raw, o = hit
    cred, _, _ = ctx.dpop_credential(p.req, raw, o, omit_ctx=True)
    expect_error(ctx.request(p.req, credential=cred, label="required, unverified"), "POLICY")


@case("ATT-QUOTA", "6.2", "MUST", "a quota admits at most value actions per epoch per identity",
      profiles=WITH_CREDENTIALS)
def att_quota(ctx):
    hit = ctx.find(lambda o: o.attest_entry(DPOP) is not None and o.attest_entry(DPOP).effect == 3)
    if hit is None:
        raise Skip("no offer with a DPoP quota")
    p, raw, o = hit
    q = o.attest_entry(DPOP)
    if q.value > 5:
        raise Skip(f"quota of {q.value} is too large to exhaust in a test")
    key = ctx.dpop_key("quota-" + b64u(os.urandom(4)))
    for i in range(q.value):
        fresh = ctx.probe(p.route, fresh=True)
        fr = next(((x, y) for x, y in fresh.offers if y.attest_entry(DPOP)), None)
        cred, _, _ = ctx.dpop_credential(p.req, fr[0], fr[1], key=key, jti=f"q{i}")
        r = expect_admitted(ctx.request(p.req, credential=cred, label=f"quota {i + 1}/{q.value}"))
        check(r.charged == 0, f"charged {r.charged} inside the quota")
    fresh = ctx.probe(p.route, fresh=True)
    fr = next(((x, y) for x, y in fresh.offers if y.attest_entry(DPOP)), None)
    cred, _, _ = ctx.dpop_credential(p.req, fr[0], fr[1], key=key, jti="over")
    expect_error(ctx.request(p.req, credential=cred, label="over quota"), ("UNDERPAID", "RATE_LIMITED"))
    other = ctx.dpop_key("quota-other-" + b64u(os.urandom(4)))
    cred, _, _ = ctx.dpop_credential(p.req, fr[0], fr[1], key=other, jti="other")
    expect_admitted(ctx.request(p.req, credential=cred, label="another identity"))


@case("ATT-PENDING", "6.4", "MUST", "the same credential while it is in flight is PENDING with retry_after",
      profiles=WITH_CREDENTIALS, needs=("role:slow",))
def att_pending(ctx):
    route = ctx.role_route("slow")
    p = ctx.probe(route)
    hit = next(((raw, o) for raw, o in p.offers if dpop_waive(o)), None)
    if hit is None:
        raise Skip("the slow route offers no DPoP waive")
    raw, o = hit
    cred, _, _ = ctx.dpop_credential(p.req, raw, o)
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("first", ctx.request(p.req, credential=cred, label="slow 1")))
    t.start()
    time.sleep(0.4)
    second = ctx.request(p.req, credential=cred, label="slow 2, in flight")
    t.join()
    expect_admitted(box["first"])
    expect_error(second, "PENDING")
    check(second.error.retry_after is not None, "PENDING without retry_after")
    third = expect_admitted(ctx.request(p.req, credential=cred, label="slow 3, after"))
    check(third.replayed, "after completion the credential is not a replay")


def _wait_hint(ctx):
    """What would let an expiry case run: a short role if none was given, else a longer wait."""
    return "raise --max-wait" if "short" in ctx.roles else "give --role short=ROUTE_ID or raise --max-wait"


@case("ATT-STALE", "4.4", "MUST", "an expired offer is STALE with a fresh offer; 60 s of skew are allowed",
      profiles=WITH_CREDENTIALS, deferred=True)
def att_stale(ctx):
    routes = [ctx.role_route("short")] if "short" in ctx.roles else ctx.plain_routes()
    best = None
    for r in routes:
        for raw, o in ctx.probe(r, fresh=True).offers:
            if dpop_waive(o) and not o.route_scope and (best is None or o.expires < best[2].expires):
                best = (ctx.probe(r), raw, o)
    if best is None:
        raise Skip("no exact-scope offer with a DPoP waive")
    p, raw, o = best
    wait = o.expires + 62 - ctx.now()
    if wait > ctx.args.max_wait:
        raise Skip(f"the shortest offer expires in {o.expires - ctx.now()} s; --max-wait {ctx.args.max_wait} "
                   f"is below the {wait} s this needs ({_wait_hint(ctx)})")
    t_skew = o.expires + 5 - ctx.now()
    if t_skew > 0:
        time.sleep(t_skew)
    cred, _, _ = ctx.dpop_credential(p.req, raw, o)
    ex = ctx.request(p.req, credential=cred, label="5 s after expiry")
    check(ex.code != "STALE", "STALE 5 s after expires: the 60 s skew was not allowed")
    expect_admitted(ex)
    time.sleep(max(0, o.expires + 62 - ctx.now()))
    cred2, _, _ = ctx.dpop_credential(p.req, raw, o)
    expect_error(ctx.request(p.req, credential=cred2, label="62 s after expiry"), "STALE", fresh=True)

def _plug_entry(ctx, o):
    """The first pay entry a scheme plug verifies against the request: class O or A."""
    return next((e for e in o.pay if ctx.registry.binding(e.scheme) in ("O", "A")), None)


@case("ERR-EXPIRY-BEFORE-PLUG", "4.4", "MUST", "expiry is checked before scope and before any plug: an expired "
      "offer with a garbage value body is STALE, not BAD_CREDENTIAL, and sent with another request STALE, not "
      "WRONG_SCOPE", profiles=WITH_CREDENTIALS, deferred=True)
def err_expiry_before_plug(ctx):
    routes = [ctx.role_route("short")] if "short" in ctx.roles else ctx.plain_routes()
    best = None
    for r in routes:
        p = ctx.probe(r, fresh=True)
        for raw, o in p.offers:
            if not o.route_scope and _plug_entry(ctx, o) and (best is None or o.expires < best[2].expires):
                best = (p, raw, o)
    if best is None:
        raise Skip("no exact-scope offer with a class O or A pay entry")
    p, raw, o = best
    wait = o.expires + 62 - ctx.now()
    if wait > ctx.args.max_wait:
        raise Skip(f"the shortest offer expires in {o.expires - ctx.now()} s; --max-wait {ctx.args.max_wait} "
                   f"is below the {wait} s this needs ({_wait_hint(ctx)})")
    time.sleep(max(0, wait))
    e = _plug_entry(ctx, o)
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem(e.scheme, b"conformance garbage", None))
    ex = ctx.request(p.req, credential=cred, label="garbage body under an expired offer")
    check(ex.code != "BAD_CREDENTIAL", f"BAD_CREDENTIAL from {e.scheme} for an offer expired 62 s ago: the scheme "
          "plug ran before the expiry check (4.4 step 4)")
    expect_error(ex, "STALE", fresh=True)
    # The same expired offer with another request target: its exact scope no longer matches either,
    # and 4.4 checks expiry (step 4) before scope (step 5).
    other = p.req.with_target(p.req.target + ("&" if "?" in p.req.target else "?") + "conformance=expired-other")
    ex = ctx.request(other, credential=cred, label="expired offer with another request")
    check(ex.code != "WRONG_SCOPE", "WRONG_SCOPE for an offer expired 62 s ago sent with another request: the "
          "scope check ran before the expiry check (4.4 steps 4 and 5)")
    expect_error(ex, "STALE", fresh=True)

# ================================================================ 10 gateway behaviour


@case("GW-TARGET", "10.1", "MUST", "the gate forwards the request-target to the application unchanged",
      profiles=("gateway",), needs=("role:echo",))
def gw_target(ctx):
    route = ctx.role_route("echo")
    req = ctx.make_req(route, leaf="a%7Eb/./c", query="z=1&a=%41")
    p = Probe(route, req, ctx.request(req, label="echo probe"))
    hit = next(((raw, o) for raw, o in p.offers if dpop_waive(o)), None)
    if hit is None:
        raise Skip("the echo route offers no DPoP waive")
    cred, _, _ = ctx.dpop_credential(req, hit[0], hit[1])
    ex = ctx.request(req, credential=cred, label="echo")
    expect_admitted(ex)
    try:
        got = json.loads(ex.res.body).get("target")
    except (ValueError, AttributeError):
        raise Fail("the echo application did not answer with JSON {\"target\"}") from None
    check(got == req.target, f"the application saw {got!r}, the client sent {req.target!r}")


@case("GW-SSE", "10.2", "MUST", "an event stream ends with one bnap-receipt event; application ones are stripped",
      profiles=("gateway",), needs=("role:sse",))
def gw_sse(ctx):
    route = ctx.role_route("sse")
    p = ctx.probe(route)
    hit = next(((raw, o) for raw, o in p.offers if dpop_waive(o)), None)
    if hit is None:
        raise Skip("the sse route offers no DPoP waive")
    cred, _, dg = ctx.dpop_credential(p.req, hit[0], hit[1])
    ex = ctx.request(p.req, credential=cred, label="sse")
    check(ex.res is not None and ex.res.status < 400, f"got {ex.describe()}")
    ct = (ex.res.header("Content-Type") or "").lower()
    check(ct.startswith("text/event-stream"), f"Content-Type {ct}")
    events = hp.parse_sse(ex.res.body)
    rec = [d for n, d in events if n == "bnap-receipt"]
    check(len(rec) == 1, f"{len(rec)} bnap-receipt events")
    check(events[-1][0] == "bnap-receipt", "the bnap-receipt event is not the last")
    try:
        r = rs.parse_response(b64u_decode(rec[0]))
    except BnapError as e:
        raise Fail("the bnap-receipt event does not parse: " + str(e)) from None
    check(rs.verify_ack(r) and r.digest == dg, "the event's receipt does not verify for this request")

# ================================================================ value flows (payer)


def l402_offer(ctx, fresh=False):
    for r in ctx.plain_routes():
        p = ctx.probe(r, fresh=fresh)
        for raw, o in p.offers:
            idx = next((i for i, e in enumerate(o.pay) if e.scheme == "httpauth:L402"), None)
            if idx is None:
                continue
            mac = next((n.data for n in o.native if n.pay_index == idx and n.kind == "l402-macaroon"), None)
            inv = next((n.data.decode() for n in o.native if n.pay_index == idx and n.kind == "bolt11"), None)
            if mac and inv:
                return p, raw, o, mac, inv
    raise Skip("no exact-scope offer with an L402 macaroon and invoice")


@case("PAY-L402", "5.1", "MUST", "an L402 payment in a BNAP credential is admitted and charged the offer price",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def pay_l402(ctx):
    p, raw, o, mac, inv = l402_offer(ctx, fresh=True)
    pre = ctx.pay(inv, o.pay_entry("httpauth:L402"))
    token = ln.l402_token(mac, pre)
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem("httpauth:L402", token.encode(), None))
    ex = ctx.request(p.req, credential=cred, label="L402 via BNAP")
    r = expect_admitted(ex)
    e = o.pay_entry("httpauth:L402")
    check(r.status == rs.OK and r.charged == e.amount and r.unit == e.unit,
          f"receipt {r.status_name} charged {r.charged} {r.unit}, the offer says {e.amount} {e.unit}")
    ctx.share["l402"] = (p, raw, o, mac, inv, pre)


@case("PAY-OFFER-BINDING", "4.2", "MUST", "a paid token is bound to its OfferID: under another offer it is refused",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def pay_offer_binding(ctx):
    if "l402" not in ctx.share:
        raise Skip("needs PAY-L402")
    p, raw, o, mac, inv, pre = ctx.share["l402"]
    q = ctx.probe(p.route, fresh=True)
    other = next(((x, y) for x, y in q.offers if y.pay_entry("httpauth:L402") and y.offer_id != o.offer_id), None)
    if other is None:
        raise Skip("no second offer")
    cred = cr.build_credential(offer=other[0], pay=cr.SchemeItem("httpauth:L402", ln.l402_token(mac, pre).encode(), None))
    ex = ctx.request(p.req, credential=cred, label="token under another offer")
    expect_not_admitted(ex)
    check(ex.code == "BAD_CREDENTIAL", f"refused as {ex.code}, not BAD_CREDENTIAL: the OfferID binding was not checked")


@case("PAY-TWO-SCHEMES", "6.1", "MUST", "one Lightning payment presented through two schemes admits one action",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def pay_two_schemes(ctx):
    if "l402" not in ctx.share:
        raise Skip("needs PAY-L402")
    p, raw, o, mac, inv, pre = ctx.share["l402"]
    idx = next((i for i, e in enumerate(o.pay) if e.scheme == "payment:lightning/charge"), None)
    chal = next((n.data for n in o.native if n.pay_index == idx and n.kind == "mpp-challenge"), None) \
        if idx is not None else None
    if chal is None:
        raise Skip("the L402 offer has no payment:lightning/charge entry with an MPP challenge")
    params = json.loads(chal)
    if ln.mpp_request_invoice(params) != inv:
        raise Skip("the MPP challenge names another invoice, so one payment cannot reach both schemes")
    cred = cr.build_credential(offer=raw, pay=cr.SchemeItem("payment:lightning/charge",
                                                            ln.mpp_credential(params, pre).encode(), None))
    expect_error(ctx.request(p.req, credential=cred, label="same payment via MPP"), "SPENT")


@case("PAY-MPP", "5.1", "MUST", "a payment:lightning/charge payment in a BNAP credential is admitted",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def pay_mpp(ctx):
    for r in ctx.plain_routes():
        p = ctx.probe(r, fresh=True)
        for raw, o in p.offers:
            idx = next((i for i, e in enumerate(o.pay) if e.scheme == "payment:lightning/charge"), None)
            chal = next((n.data for n in o.native if idx is not None and n.pay_index == idx
                         and n.kind == "mpp-challenge"), None)
            if chal is None:
                continue
            params = json.loads(chal)
            pre = ctx.pay(ln.mpp_request_invoice(params), o.pay[idx])
            cred = cr.build_credential(offer=raw, pay=cr.SchemeItem("payment:lightning/charge",
                                                                    ln.mpp_credential(params, pre).encode(), None))
            rr = expect_admitted(ctx.request(p.req, credential=cred, label="MPP via BNAP"))
            check(rr.status == rs.OK and rr.charged == o.pay[idx].amount, f"charged {rr.charged}")
            return
    raise Skip("no offer with an MPP challenge")


@case("PAY-NATIVE", "5.4", "MUST", "a native L402 credential gets a BNAP receipt over the native envelope",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def pay_native(ctx):
    p, raw, o, mac, inv = l402_offer(ctx, fresh=True)
    pre = ctx.pay(inv, o.pay_entry("httpauth:L402"))
    token = ln.l402_token(mac, pre)
    ex = ctx.request(p.req, extra=[("Authorization", "L402 " + token)], label="native L402")
    r = expect_admitted(ex)
    nctx = cr.native_context(o.offer_id, p.req.action_scope(), "httpauth:L402")
    check(r.digest == cr.native_digest(nctx, token.encode()), "receipt digest is not the native Digest")
    check(rs.verify_ack(r), "ack")
    r2 = expect_admitted(ctx.request(p.req, extra=[("Authorization", "L402 " + token)], label="native replay"))
    check(r2.replayed, "the native replay is not flagged replayed")


@case("PAY-METERED", "7", "MUST", "a metered charge is min(price(ceil(units x rate / 1000)), price(amount))",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def pay_metered(ctx):
    hit = ctx.find(lambda o: o.metered)
    if hit is None:
        raise Skip("no metered offers")
    p, raw, o = hit
    payable = [e for e in o.pay if e.scheme in ("httpauth:L402", "payment:lightning/charge")]
    if not payable:
        raise Skip("metered offers list only schemes the runner cannot pay: " + notes.skip_reason())
    raise Skip("metered entries for L402 or MPP break the 7 refund rule; nothing to pay")


@case("NOTES-VALUE", "5.1", "MUST", "bnap:notes value flows: change outputs, metered refunds, witnesses",
      profiles=WITH_CREDENTIALS, needs=("payer",))
def notes_value(ctx):
    raise Skip(notes.skip_reason())

# ================================================================ checks over every exchange


def _commit_sweep(ctx):
    """One admissible DPoP-only credential on every route that offers a DPoP waive, roles or
    not, so that each route's commit path (a failing application's included) is seen once."""
    win = ctx.limits()["replay_window"]
    for r in ctx.routes():
        p = ctx.probe(r, fresh=True)
        cands = sorted(((raw, o) for raw, o in p.offers if dpop_waive(o) and o.expires + 60 <= ctx.now() + win),
                       key=lambda x: x[1].route_scope)
        if not cands:
            continue
        raw, o = cands[0]
        req = ctx.make_req(r, leaf="sweep-" + b64u(os.urandom(4))) if o.route_scope else p.req
        cred, _, _ = ctx.dpop_credential(req, raw, o)
        ctx.request(req, credential=cred, label=f"sweep {r.id}")


@case("RCPT-EVERY-COMMIT", "10.2", "MUST", "every response to a request that reached commit carries BNAP-Receipt, "
      "FAILED outcomes included", profiles=WITH_CREDENTIALS)
def rcpt_every(ctx):
    _commit_sweep(ctx)
    # A credentialed request answered without BNAP-Error was not refused, so it reached
    # commit: whatever its HTTP status (a 5xx from a failed action included), it needs a receipt.
    xs = [x for x in list(ctx.log) if x.res is not None and (x.carried_credential or x.carried_native)
          and x.error is None and not x.error_problem]
    if not xs:
        raise Skip("no credentialed request was answered without BNAP-Error")
    bad = [f"{x.label} (HTTP {x.res.status})" for x in xs if not x.has_receipt()]
    check(not bad, f"{len(bad)} of {len(xs)} responses carry neither BNAP-Receipt nor BNAP-Error: "
          + ", ".join(bad[:5]))


@case("ERR-FORMAT", "8.2", "MUST", "every BNAP-Error parses, has version 1 and the HTTP status of its code",
      profiles=WITH_CREDENTIALS)
def err_format(ctx):
    errs = [x for x in ctx.log if x.res is not None and (x.error is not None or x.error_problem)]
    if not errs:
        raise Skip("no errors seen")
    bad = []
    for x in errs:
        if x.error_problem:
            bad.append(f"{x.label}: {x.error_problem}")
        elif x.error.name in codec.ERRORS and x.res.status != codec.http_status_of(x.error.name):
            bad.append(f"{x.label}: {x.error.name} with HTTP {x.res.status}")
        elif x.error.detail is not None and len(x.error.detail.encode()) > 256:
            bad.append(f"{x.label}: detail over 256 bytes")
        elif x.error.name in codec.NEEDS_RETRY_AFTER and x.error.retry_after is None:
            bad.append(f"{x.label}: {x.error.name} without retry_after")
    check(not bad, "; ".join(bad[:4]))


def _cache_directives(res):
    return ",".join(res.headers_all("Cache-Control")).lower().replace(" ", "").split(",")


@case("ERR-CACHE-CONTROL", "10.2", "MUST", "every response to a request with BNAP-Credential has "
      "Cache-Control: private, no-store, also when the application sent its own Cache-Control "
      "(gateway: needs --role cache)", profiles=WITH_CREDENTIALS)
def err_cache_control(ctx):
    app_ex, missing = None, None
    if "cache" in ctx.roles:
        route = ctx.role_route("cache")
        p = ctx.probe(route)
        hit = next(((raw, o) for raw, o in p.offers if dpop_waive(o)), None)
        if hit is None:
            missing = "the cache route offers no DPoP waive, so its application cannot be reached"
        else:
            cred, _, _ = ctx.dpop_credential(p.req, hit[0], hit[1])
            app_ex = ctx.request(p.req, credential=cred, label="cache: the application sets Cache-Control")
            expect_admitted(app_ex)
    else:
        missing = ("needs --role cache=ROUTE_ID, a route whose application sends its own Cache-Control, to show "
                   "the gate adds private, no-store where the application did not")
    xs = [x for x in ctx.log if x.res is not None and x.carried_credential]
    if not xs:
        raise Skip("no credentials sent")
    bad = []
    for x in xs:
        cc = _cache_directives(x.res)
        if "private" not in cc or "no-store" not in cc:
            bad.append(f"{x.label} (HTTP {x.res.status}): {','.join(c for c in cc if c) or 'none'}")
    # The cache role's exchange is among xs: an application's own Cache-Control must not pass unamended.
    check(not bad, f"{len(bad)} of {len(xs)}: " + "; ".join(bad[:3]))
    if app_ex is None and ctx.args.profile == "gateway":
        raise Skip("every credentialed response carried private, no-store, but " + missing)


@case("OFR-NONCE-ONE-MINT", "12", "MUST", "native challenges are minted at most once per offer nonce: exact offers "
      "that share a nonce carry byte-identical natives (DECISIONS row 24)")
def ofr_nonce_one_mint(ctx):
    for r in ctx.routes():
        if any(o.native for _, o in ctx.probe(r).offers):
            for _ in range(2):
                ctx.probe(r, fresh=True)
    with ctx.lock:
        seen = list(ctx.seen_offers)
    by_nonce = {}
    for raw, o in seen:
        if o.native and not o.route_scope:
            by_nonce.setdefault(o.nonce, {})[raw] = o
    if not by_nonce:
        raise Skip("no native records offered")
    probs = []
    for nonce, offers in by_nonce.items():
        sets = {tuple(sorted((n.pay_index, n.kind, n.data) for n in o.native)) for o in offers.values()}
        if len(sets) > 1:
            kinds = {x[1] for nat in sets for x in nat}
            differ = sorted(k for k in kinds if len({tuple(x for x in nat if x[1] == k) for nat in sets}) > 1)
            probs.append(f"nonce {nonce.hex()[:12]}: {len(offers)} offers carry {len(sets)} different native sets "
                         f"({', '.join(differ)} differ)")
    check(not probs, f"{len(probs)} nonce(s) with more than one mint: " + "; ".join(probs[:3]))


def _no_single_use_id(ctx, c):
    """6.1: a credential that yields no ID under the single model, here one without
    pay whose attestations all have the reusable or rate model in the registry."""
    return (c.pay is None and bool(c.attest)
            and all(ctx.registry.use(s) in ("reusable", "rate") for s in c.attest_schemes))


@case("USE-REUSABLE-WINDOW", "6.1", "MUST", "a credential with no single-use ID is admitted only if its offer's "
      "expires + 60 <= now + replay_window", profiles=WITH_CREDENTIALS)
def use_reusable_window(ctx):
    win = ctx.limits()["replay_window"]
    probs, active, audited = [], 0, 0
    # Offers that outlive the outcome record (with a minute to spare for clock skew):
    # a DPoP-only credential under one of them must be refused.
    for r in ctx.routes():
        p = ctx.probe(r, fresh=True)
        for raw, o in p.offers:
            if not dpop_waive(o) or o.expires + 60 <= ctx.now() + win + 60:
                continue
            active += 1
            req = ctx.make_req(r, leaf="window-" + b64u(os.urandom(4))) if o.route_scope else p.req
            cred, _, _ = ctx.dpop_credential(req, raw, o)
            ex = ctx.request(req, credential=cred, label=f"{r.id}: offer outlives replay_window")
            if ex.receipt() is not None:
                probs.append(f"{r.id}: a DPoP-only credential was admitted under an offer that expires at "
                             f"{o.expires}, after now + replay_window = {ctx.now() + win}")
    # Every admission of the run so far: the rule must have held when it was admitted.
    for x in list(ctx.log):
        rc = x.receipt()
        c = x.sent_credential() if rc is not None else None
        if c is None or not _no_single_use_id(ctx, c):
            continue
        o = ctx.offer_of(c)
        if o is None:
            continue
        audited += 1
        if o.expires + 60 > rc.settled_at + win:
            probs.append(f"{x.label}: settled at {rc.settled_at} under an offer that expires at {o.expires}; "
                         f"with replay_window {win} the outcome record may go first")
    if not active and not audited:
        raise Skip("no credential without a single-use ID was admitted, and no offer outlives replay_window")
    check(not probs, f"{len(probs)} admission(s) break 6.1: " + "; ".join(probs[:3]))

# ================================================================ running


class RunResult:
    def __init__(self, args, results, started, finished, ctx):
        self.args = args
        self.results = results
        self.started = started
        self.finished = finished
        self.ctx = ctx

    def must_failures(self):
        return [r for r in self.results if r.status in ("fail", "error") and r.case.level == "MUST"]

    def must_skips(self):
        """MUST cases that did not run. A gate is not shown conformant while any remain."""
        return [r for r in self.results if r.status == "skip" and r.case.level == "MUST"]

    def must_not_selected(self):
        """MUST cases of the profile that --only left out. They did not run either."""
        ran = {r.case.id for r in self.results}
        return [c for c in CASES if self.args.profile in c.profiles and c.level == "MUST" and c.id not in ran]

    def incomplete(self):
        return bool(self.must_skips() or self.must_not_selected())

    def failed(self):
        return bool(self.must_failures()) or any(r.status == "error" for r in self.results)

    def verdict(self):
        if self.failed():
            return "not conformant"
        parts = []
        n = len(self.must_skips())
        if n:
            parts.append(f"{n} MUST case{'' if n == 1 else 's'} not run")
        n = len(self.must_not_selected())
        if n:
            parts.append(f"{n} MUST case{'' if n == 1 else 's'} not selected")
        if parts:
            return "incomplete: " + "; ".join(parts) + (" (accepted with --allow-skips)" if self.args.allow_skips
                                                        else "")
        return "conformant for this profile"

    def exit_status(self):
        if self.failed():
            return EXIT_FAIL
        if self.incomplete() and not self.args.allow_skips:
            return EXIT_INCOMPLETE
        return EXIT_OK

    def summary(self):
        s = {k: 0 for k in ("pass", "fail", "skip", "error")}
        for r in self.results:
            s[r.status] += 1
        s["must_fail"] = len(self.must_failures())
        s["must_skip"] = len(self.must_skips())
        s["must_not_selected"] = len(self.must_not_selected())
        s["should_fail"] = sum(1 for r in self.results if r.status == "fail" and r.case.level == "SHOULD")
        return s


def run_case(ctx, c):
    t0 = time.monotonic()
    try:
        c.func(ctx)
        return Result(c, "pass", duration=time.monotonic() - t0)
    except Skip as e:
        return Result(c, "skip", str(e), duration=time.monotonic() - t0)
    except Fail as e:
        return Result(c, "fail", str(e), duration=time.monotonic() - t0)
    except Exception as e:
        tb = traceback.format_exception_only(type(e), e)[-1].strip()
        return Result(c, "error", tb, duration=time.monotonic() - t0)


def selected(args):
    only = set(x.strip() for x in args.only.split(",")) if args.only else None
    out = []
    for c in CASES:
        if args.profile not in c.profiles:
            continue
        if only and c.id not in only:
            continue
        out.append(c)
    return out


def parse_args(argv):
    ap = argparse.ArgumentParser(prog="run.py", description="BNAP draft-00 black-box conformance runner")
    ap.add_argument("--target", help="https://host[:port] of the gate under test")
    ap.add_argument("--profile", choices=PROFILES, default="server")
    ap.add_argument("--payer", default="none", help="none, or cmd:<shell command that pays a bolt11 and prints "
                                                    "the preimage>")
    ap.add_argument("--report", help="directory for report.json, junit.xml and report.html")
    ap.add_argument("--role", action="append", default=[], help="NAME=ROUTE_ID (slow, fail, short, echo, sse, "
                                                                 "cache)")
    ap.add_argument("--dpop-token-cmd", help="prints an access token for the thumbprint given as last argument")
    ap.add_argument("--max-wait", type=int, default=120, help="longest wait a case may take, in seconds")
    ap.add_argument("--max-spend-sat", type=int, default=100,
                    help="total the payer may spend, routing fees included")
    ap.add_argument("--fee-limit-sat", type=int, default=10,
                    help="routing fee limit per payment, reserved against --max-spend-sat (default 10)")
    ap.add_argument("--allow-http", action="store_true", help="allow a plain-HTTP target (test gates only)")
    ap.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate (test gates only)")
    ap.add_argument("--only", help="comma-separated case IDs; a run that leaves out MUST cases of the profile "
                                   "is incomplete (exit 3), never conformant")
    ap.add_argument("--allow-skips", action="store_true",
                    help="exit 0 even when MUST cases were skipped (the verdict still says incomplete)")
    ap.add_argument("--list", action="store_true", help="list the cases and exit")
    a = ap.parse_args(argv)
    if a.list:
        return a
    if not a.target:
        ap.error("--target is required")
    u = urllib.parse.urlsplit(a.target)
    if u.scheme not in ("https", "http") or not u.hostname:
        ap.error("--target must be an https:// URL")
    if u.scheme == "http" and not a.allow_http:
        ap.error("plain HTTP needs --allow-http (BNAP clients use HTTPS)")
    if u.path not in ("", "/"):
        ap.error("--target is an origin, without a path")
    for r in a.role:
        if "=" not in r:
            ap.error("--role takes NAME=ROUTE_ID")
    if a.payer != "none" and not a.payer.startswith("cmd:"):
        ap.error("--payer is none or cmd:<command>")
    if a.fee_limit_sat < 0 or a.max_spend_sat < 0:
        ap.error("--fee-limit-sat and --max-spend-sat are not negative")
    return a


def run(argv, quiet=False):
    args = parse_args(argv)
    if args.list:
        for c in CASES:
            print(f"{c.id:<24} {c.section:<5} {c.level:<6} {','.join(c.profiles):<22} {c.title}")
        return None
    ctx = Ctx(args)
    cases = selected(args)
    started = time.time()
    results = {}
    deferred = [c for c in cases if c.deferred]
    threads = []
    for c in deferred:
        t = threading.Thread(target=lambda c=c: results.__setitem__(c.id, run_case(ctx, c)), daemon=True)
        t.start()
        threads.append(t)
    for c in cases:
        if c.deferred:
            continue
        r = run_case(ctx, c)
        results[c.id] = r
        if not quiet:
            _print_result(r)
    for t in threads:
        t.join(timeout=args.max_wait + 120)
    for c in deferred:
        r = results.get(c.id) or Result(c, "error", "deferred case did not finish")
        results[c.id] = r
        if not quiet:
            _print_result(r)
    ordered = [results[c.id] for c in cases]
    rr = RunResult(args, ordered, started, time.time(), ctx)
    if args.report:
        write_reports(rr, pathlib.Path(args.report))
    if not quiet:
        s = rr.summary()
        print(f"\n{s['pass']} passed, {s['fail']} failed ({s['must_fail']} MUST, {s['should_fail']} SHOULD), "
              f"{s['error']} errors, {s['skip']} skipped ({s['must_skip']} MUST)")
        print("verdict:", rr.verdict())
        if rr.must_skips():
            print("MUST cases not run: " + ", ".join(r.case.id for r in rr.must_skips()))
        if rr.must_not_selected():
            print(f"MUST cases not selected by --only: {len(rr.must_not_selected())} "
                  f"(listed in the reports)")
    return rr


def _print_result(r):
    mark = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP", "error": "ERR "}[r.status]
    line = f"  {mark} {r.case.id:<24} [{r.case.section} {r.case.level}] {r.case.title}"
    print(line)
    if r.detail and r.status != "pass":
        print(f"         {r.detail}")

# ---------------------------------------------------------------- reports


def write_reports(rr, out):
    out.mkdir(parents=True, exist_ok=True)
    s = rr.summary()
    data = {"tool": VERSION, "target": rr.args.target, "profile": rr.args.profile,
            "payer": "none" if rr.args.payer == "none" else "cmd", "started": int(rr.started),
            "finished": int(rr.finished), "verdict": rr.verdict(), "exit_status": rr.exit_status(),
            "allow_skips": bool(rr.args.allow_skips), "summary": s,
            "must_skipped": [{"id": r.case.id, "section": r.case.section, "reason": r.detail}
                             for r in rr.must_skips()],
            "only": rr.args.only or None,
            "must_not_selected": [{"id": c.id, "section": c.section, "title": c.title}
                                  for c in rr.must_not_selected()],
            "results": [r.to_json() for r in rr.results]}
    (out / "report.json").write_text(json.dumps(data, indent=1) + "\n")
    suites = ET.Element("testsuites", name="bnap-conformance", tests=str(len(rr.results)),
                        failures=str(s["fail"]), errors=str(s["error"]), skipped=str(s["skip"]))
    by = {}
    for r in rr.results:
        by.setdefault(r.case.top, []).append(r)
    for top in sorted(by, key=lambda x: int(x)):
        rs_ = by[top]
        ts = ET.SubElement(suites, "testsuite", name=SECTION_TITLES.get(top, top), tests=str(len(rs_)),
                           failures=str(sum(r.status == "fail" for r in rs_)),
                           errors=str(sum(r.status == "error" for r in rs_)),
                           skipped=str(sum(r.status == "skip" for r in rs_)))
        for r in rs_:
            tc = ET.SubElement(ts, "testcase", classname=f"bnap.s{r.case.section}",
                               name=f"{r.case.id} [{r.case.level}] {r.case.title}", time=f"{r.duration:.3f}")
            if r.status == "fail":
                ET.SubElement(tc, "failure", message=r.detail[:200], type=r.case.level).text = r.detail
            elif r.status == "error":
                ET.SubElement(tc, "error", message=r.detail[:200]).text = r.detail
            elif r.status == "skip":
                ET.SubElement(tc, "skipped", message=r.detail[:200])
    ET.ElementTree(suites).write(out / "junit.xml", encoding="utf-8", xml_declaration=True)
    (out / "report.html").write_text(render_html(rr, s))


def render_html(rr, s):
    e = html.escape
    rows = []
    by = {}
    for r in rr.results:
        by.setdefault(r.case.top, []).append(r)
    for top in sorted(by, key=lambda x: int(x)):
        rows.append(f'<tr class="sec"><th colspan="5">{e(SECTION_TITLES.get(top, top))}</th></tr>')
        for r in by[top]:
            rows.append(f'<tr class="{r.status}"><td class="st">{r.status.upper()}</td><td><code>{e(r.case.id)}'
                        f'</code></td><td>{e(r.case.section)}</td><td>{e(r.case.level)}</td><td>{e(r.case.title)}'
                        + (f'<div class="d">{e(r.detail)}</div>' if r.detail else "") + "</td></tr>")
    verdict = rr.verdict()
    vclass = "fail" if rr.failed() else ("skip" if rr.incomplete() else "pass")
    skipped = "".join(f'<li><code>{e(r.case.id)}</code> ({e(r.case.section)}) {e(r.detail)}</li>'
                      for r in rr.must_skips())
    skipped_block = (f'<section class="notrun"><h2>MUST cases not run ({len(rr.must_skips())})</h2>'
                     f'<p>Until these run and pass, this report does not show the target conformant.</p>'
                     f'<ul>{skipped}</ul></section>') if skipped else ""
    left = rr.must_not_selected()
    if left:
        items = "".join(f'<li><code>{e(c.id)}</code> ({e(c.section)}) {e(c.title)}</li>' for c in left)
        skipped_block += (f'<section class="notrun"><h2>MUST cases not selected ({len(left)})</h2>'
                          f'<p>--only {e(rr.args.only or "")} left these cases of the {e(rr.args.profile)} '
                          f'profile out. A partial run does not show the target conformant.</p>'
                          f'<ul>{items}</ul></section>')
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(rr.started))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>BNAP conformance report</title>
<style>
:root {{ --bg:#fbfbf9; --fg:#1d1d1b; --muted:#6b6b66; --line:#e2e1dc; --pass:#1f7a3f; --fail:#b42318;
  --skip:#8a6d00; --error:#7a2e9a; --sec:#f0efe9; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg:#161614; --fg:#ecebe6;
  --muted:#a3a29b; --line:#33322e; --pass:#5fc27e; --fail:#ff7b6b; --skip:#e0c25a; --error:#c99be0; --sec:#22221f; }} }}
:root[data-theme="dark"] {{ --bg:#161614; --fg:#ecebe6; --muted:#a3a29b; --line:#33322e; --pass:#5fc27e;
  --fail:#ff7b6b; --skip:#e0c25a; --error:#c99be0; --sec:#22221f; }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; margin:0; padding:24px 16px; }}
main {{ max-width:1100px; margin:0 auto; }}
h1 {{ font-size:22px; margin:0 0 4px; font-weight:600; }}
p.meta {{ color:var(--muted); margin:0 0 16px; overflow-wrap:anywhere; }}
.sum {{ display:flex; flex-wrap:wrap; gap:16px; margin:0 0 20px; }}
.sum div {{ border:1px solid var(--line); border-radius:8px; padding:8px 14px; }}
.sum b {{ font-size:20px; display:block; }}
.wrap {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; }}
td, th {{ border-bottom:1px solid var(--line); padding:6px 8px; text-align:left; vertical-align:top; }}
tr.sec th {{ background:var(--sec); font-weight:600; }}
td.st {{ font-weight:600; white-space:nowrap; }}
tr.pass td.st {{ color:var(--pass); }} tr.fail td.st {{ color:var(--fail); }}
tr.skip td.st {{ color:var(--skip); }} tr.error td.st {{ color:var(--error); }}
.d {{ color:var(--muted); font-size:13px; overflow-wrap:anywhere; }}
code {{ font-size:13px; }}
p.verdict {{ font-size:17px; font-weight:600; margin:0 0 16px; }}
p.verdict.pass {{ color:var(--pass); }} p.verdict.fail {{ color:var(--fail); }} p.verdict.skip {{ color:var(--skip); }}
section.notrun {{ border:1px solid var(--line); border-radius:8px; padding:4px 14px; margin:0 0 20px; }}
section.notrun h2 {{ font-size:16px; font-weight:600; margin:8px 0 4px; }}
section.notrun li {{ overflow-wrap:anywhere; }}
</style></head><body><main>
<h1>BNAP conformance report</h1>
<p class="meta">{e(VERSION)} &middot; target {e(rr.args.target)} &middot; profile {e(rr.args.profile)} &middot;
payer {e("none" if rr.args.payer == "none" else "command")} &middot; {e(when)}</p>
<p class="verdict {vclass}">Verdict: {e(verdict)}</p>
<div class="sum"><div><b>{s['pass']}</b>passed</div><div><b>{s['must_fail']}</b>MUST failed</div>
<div><b>{s['should_fail']}</b>SHOULD failed</div><div><b>{s['error']}</b>errors</div>
<div><b>{s['skip']}</b>skipped</div><div><b>{s['must_skip']}</b>MUST not run</div>
<div><b>{s['must_not_selected']}</b>MUST not selected</div></div>
{skipped_block}
<div class="wrap"><table><thead><tr><th>Result</th><th>Case</th><th>Section</th><th>Level</th><th>Requirement</th>
</tr></thead><tbody>
{chr(10).join(rows)}
</tbody></table></div></main></body></html>
"""


def main(argv=None):
    rr = run(sys.argv[1:] if argv is None else argv)
    if rr is None:
        return EXIT_OK
    return rr.exit_status()


if __name__ == "__main__":
    sys.exit(main())
