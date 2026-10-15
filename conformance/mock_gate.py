#!/usr/bin/env python3
"""A deliberately minimal in-process BNAP gate, built from bnap_conf, for
checking that run.py bites.

Usage:
  python3 -I conformance/mock_gate.py serve [--port N] [--fault F]... [--short-ttl S]
  python3 -I conformance/mock_gate.py pay --gate URL INVOICE
  python3 -I conformance/mock_gate.py selftest [--report DIR] [--with-payer]

serve     runs the gate and its test application on 127.0.0.1 (plain HTTP).
pay       is a fake Lightning payer for run.py --payer cmd:...: it asks the mock
          to settle INVOICE and prints the preimage.
selftest  runs run.py against the clean mock (every case must pass) and once
          per fault (the matching case must fail), and prints the table.

Faults:
  strip-attest          the DPoP adapter ignores the Context claim
  status-flip           a replay reports the opposite status
  no-replay             the store forgets outcomes, so a replay runs again
  wrong-scope-accepted  exact-scope offers are accepted for any request
  bad-ack               every Response ack is corrupted
  no-dpop               no route offers an httpauth:DPoP waive (not a fault in
                        itself: without a payer the runner can then reach no
                        admission, and must say so instead of passing)
  quote-expires-over    exact-scope pay entries carry quote_expires after expires
  native-in-route       route-scope offers carry a native record
  ext-ignored           the gate leaves ext out of the Context (5.2)
  reusable-window       replay_window drops to 120 s and the 6.1 check is gone, so
                        DPoP-only credentials are admitted under offers that
                        outlive their outcome record
  late-expiry           the scheme plugs run before the expiry check, and STALE
                        is raised only afterwards (4.4 order broken)
  nonce-reuse           one fixed nonce per route, with a new invoice on every 402
  no-receipt-on-failed  responses to FAILED outcomes carry no BNAP-Receipt
  nested-odd-rejected   a scheme item with an unknown odd record is MALFORMED
  nested-odd-in-rk      unknown odd records inside scheme items enter the ReplayKey
  nested-even-ignored   unknown even records inside scheme items are dropped, not refused
  ext-even-ignored      the gate does not parse ext, so an even extension passes
  offer-size-unchecked  an inline offer is not checked against max_offer
  htu-from-host         the DPoP adapter builds htu from the raw Host field
  scope-from-host       the action scope is built from the Host field, not the manifest origin
  top-odd-in-digest     unknown odd records at the top level of the Credential enter the Digest
  scope-before-expiry   the offer checks run authenticity, then scope, then expiry (4.4 order broken)
  offer-version-masked  the MAC is checked before the offer version, so a version 2 offer is BAD_OFFER
  high-s-accepted       the DPoP adapter accepts a high-S ES256 signature (plain ECDSA), so a copy of a
                        proof with s replaced by n - s verifies under another ReplayKey
  cache-control-kept    the gate adds Cache-Control: private, no-store only when the application sent no
                        Cache-Control at all, so the cache route's "public, max-age=60" goes out unchanged

The mock is not a gate to deploy. It has no durability, no TLS, no rate
limits on unauthenticated work, and it verifies L402, MPP and DPoP only in
the suite's test profiles (notes/n11-conformance.md).
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import socketserver
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from bnap_conf import codec, offer as of, credential as cr, response as rs, manifest as mf  # noqa: E402
from bnap_conf import http as hp, pricing as pr, store as st, dpop, lightning as ln, registry  # noqa: E402
from bnap_conf.codec import BnapError, b64u, b64u_decode  # noqa: E402
from bnap_conf.crypto import schnorr_pub, key_from_label  # noqa: E402

FAULTS = ("strip-attest", "status-flip", "no-replay", "wrong-scope-accepted", "bad-ack", "no-dpop",
          "quote-expires-over", "native-in-route", "ext-ignored", "reusable-window", "late-expiry",
          "nonce-reuse", "no-receipt-on-failed", "nested-odd-rejected", "nested-odd-in-rk", "nested-even-ignored",
          "ext-even-ignored", "offer-size-unchecked", "htu-from-host", "scope-from-host", "top-odd-in-digest",
          "scope-before-expiry", "offer-version-masked", "high-s-accepted", "cache-control-kept")
REG = registry.default()
WAIVE = {"scheme": "httpauth:DPoP", "effect": "waive"}

ROUTES = [
    {"id": "free", "match": "GET /conformance/free", "scope": "exact", "price": {"sat": 21},
     "pay": ["httpauth:L402", "payment:lightning/charge"], "attest": [WAIVE], "headers": []},
    {"id": "api", "match": "POST /conformance/api/*", "scope": "route", "price": {"sat": 10},
     "pay": ["bnap:notes"], "attest": [WAIVE], "headers": []},
    {"id": "chat", "match": "POST /v1/chat/completions", "scope": "route", "metered": True, "meter": "tokens",
     "price": {"sat": 2100}, "pay": ["bnap:notes", "httpauth:L402"],
     "attest": [{"scheme": "httpauth:DPoP", "effect": "discount", "value": 2000}], "headers": []},
    {"id": "quota", "match": "GET /conformance/quota", "scope": "exact", "price": {"sat": 5},
     "pay": ["httpauth:L402"], "attest": [{"scheme": "httpauth:DPoP", "effect": "quota", "value": 2, "epoch": 3600}],
     "headers": []},
    {"id": "required", "match": "GET /conformance/required", "scope": "exact", "price": {"sat": 5},
     "pay": ["httpauth:L402"], "attest": [{"scheme": "httpauth:DPoP", "effect": "required"}], "headers": []},
    {"id": "short", "match": "GET /conformance/short", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": []},
    {"id": "slow", "match": "GET /conformance/slow", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": []},
    {"id": "fail", "match": "GET /conformance/fail", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": []},
    {"id": "sse", "match": "GET /conformance/sse", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": []},
    {"id": "echo", "match": "GET /conformance/echo/*", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": []},
    # Its application sends Cache-Control: public, max-age=60; the gate must still send private, no-store.
    {"id": "cache", "match": "GET /conformance/cache", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": []},
    {"id": "headers", "match": "GET /conformance/headers", "scope": "exact", "price": {"sat": 1},
     "pay": ["httpauth:L402"], "attest": [WAIVE], "headers": ["accept", "x-conformance"]},
    # Its route offer lives a day, past replay_window: a DPoP-only credential under it
    # has no single-use ID and must be refused (6.1).
    {"id": "window", "match": "GET /conformance/window", "scope": "route", "price": {"sat": 1},
     "pay": ["bnap:notes"], "attest": [WAIVE], "headers": []},
]
ROLES = {"slow": "slow", "fail": "fail", "sse": "sse", "echo": "echo", "short": "short", "cache": "cache"}

EXACT_TTL = 300
ROUTE_TTL = 3600
ROUTE_TTLS = {"window": 86400}
REPLAY_WINDOW = 7200
FAULT_REPLAY_WINDOW = 120
PENDING_TIMEOUT = 30
HTTP_CAP = cr.HTTP_MAX_CREDENTIAL


class GateError(Exception):
    def __init__(self, code, detail="", scheme_code=None, retry_after=None):
        self.code = code
        self.detail = detail
        self.scheme_code = scheme_code
        self.retry_after = retry_after
        super().__init__(code)


class Reply:
    def __init__(self, status, headers=None, body=b""):
        self.status = status
        self.headers = list(headers or [])
        self.body = body


class MockGate:
    def __init__(self, port=0, faults=(), short_ttl=1, host="127.0.0.1"):
        for f in faults:
            if f not in FAULTS:
                raise ValueError("unknown fault " + f)
        self.faults = set(faults)
        self.short_ttl = short_ttl
        self.routes = [self._route_for_faults(r) for r in ROUTES]
        self.root_sk = key_from_label("bnap mock root key")
        self.backup_sk = key_from_label("bnap mock backup key")
        self.offer_sk = key_from_label("bnap mock offer key")
        self.receipt_sk = key_from_label("bnap mock receipt key")
        self.mac_key = os.urandom(32)
        self.macaroon_root = os.urandom(32)
        self.mpp_key = os.urandom(32)
        self.node_sk = key_from_label("bnap mock lightning node key")
        self.replay_window = FAULT_REPLAY_WINDOW if "reusable-window" in self.faults else REPLAY_WINDOW
        self.store = st.UseStore(self.replay_window, PENDING_TIMEOUT)
        self.cache = {}
        self.route_offers = {}
        self.invoices = {}
        self.app_counter = 0
        self.lock = threading.RLock()
        self.server = _Server((host, port), _Handler)
        self.server.daemon_threads = True
        self.server.gate = self
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.started = int(time.time())
        self.manifest_bytes = self._manifest()
        self.thread = None

    # ------------------------------------------------------------ lifecycle

    def start(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self):
        return self.origin

    def _route_for_faults(self, r):
        r = json.loads(json.dumps(r))
        if "no-dpop" in self.faults:
            r["attest"] = [a for a in r["attest"] if not (a["scheme"] == "httpauth:DPoP" and a["effect"] == "waive")]
        return r

    # ------------------------------------------------------------ manifest

    def _manifest(self):
        na = self.started + 7 * 86400
        m = {"bnap": 1, "origin": self.origin, "seq": 1, "issued": self.started, "max_age": 7 * 86400,
             "root": schnorr_pub(self.root_sk).hex(), "backup": schnorr_pub(self.backup_sk).hex(),
             "required": True,
             "keys": [{"kid": schnorr_pub(self.offer_sk).hex(), "use": "offer", "not_after": na},
                      {"kid": schnorr_pub(self.receipt_sk).hex(), "use": "receipt", "not_after": na}],
             "limits": {"replay_window": self.replay_window, "pending_timeout": PENDING_TIMEOUT,
                        "max_offer": 4096, "max_credential": 16384, "max_response": 8192},
             "carriers": ["http"], "routes": self.routes}
        return mf.jcs(mf.sign_manifest(m, self.root_sk))

    # ------------------------------------------------------------ offers

    def _attest_entries(self, route, classes):
        out = []
        for a in route.get("attest", []):
            if REG.binding(a["scheme"]) in classes:
                out.append(of.attest_entry(a["scheme"], a["effect"], a.get("value"), a.get("epoch")))
        return out

    def route_offer(self, route, now):
        with self.lock:
            cur = self.route_offers.get(route["id"])
            if cur and cur[1] > now + 60:
                return cur[0]
            unit, amount = next(iter(route["price"].items()))
            ttl = ROUTE_TTLS.get(route["id"], ROUTE_TTL)
            pay = []
            for s in route["pay"]:
                if REG.binding(s) in ("S", "A"):
                    pay.append(of.pay_entry(s, amount, unit, rate=500 if route.get("metered") else None))
            native = []
            if "native-in-route" in self.faults and pay:
                inv = ln.encode_bolt11(payment_hash=os.urandom(32), description_hash=bytes(32), amount_sat=amount,
                                       timestamp=now, node_sk=self.node_sk)
                native = [of.native_entry(0, "bolt11", inv.encode())]
            fields = of.offer_fields(scope=hp.route_scope(self.origin, route["id"]), route_scope=True,
                                     metered=bool(route.get("metered")), expires=now + ttl,
                                     info=self.origin + "/.well-known/bnap", offer_key=schnorr_pub(self.offer_sk),
                                     nonce=os.urandom(16), pay=pay, attest=self._attest_entries(route, ("S", "A")),
                                     native=native, extra=[(3000000001 + 2 * (now % 400), os.urandom(2))])
            raw = of.sign_offer(fields, self.offer_sk, self.mac_key)
            oid = of.offer_id_of(raw)
            self.cache[oid] = raw
            self.route_offers[route["id"]] = (raw, now + ttl)
            return raw

    def _mpp_id(self, params):
        """The challenge id: an HMAC over the bound parameters (draft-httpauth-payment-01)."""
        bound = "|".join(params.get(k, "") for k in ("realm", "method", "intent", "request", "expires",
                                                     "digest", "opaque"))
        return b64u(hmac.new(self.mpp_key, bound.encode(), hashlib.sha256).digest())

    def exact_offer(self, route, scope, headers, now):
        """An exact-scope offer, with natives for its class O entries, and the native challenges."""
        unit, amount = next(iter(route["price"].items()))
        route_mode = route["scope"] == "route"
        pay_schemes = [s for s in route["pay"] if not (route_mode and REG.binding(s) in ("S", "A"))]
        if not pay_schemes:
            return None, []
        ttl = self.short_ttl if route["id"] == "short" else EXACT_TTL
        qe = now + ttl + 30 if "quote-expires-over" in self.faults else None
        pay = [of.pay_entry(s, amount, unit, quote_expires=qe) for s in pay_schemes]
        attest = self._attest_entries(route, ("S", "A", "O"))
        if "nonce-reuse" in self.faults:
            nonce = hashlib.sha256(b"fixed nonce " + route["id"].encode()).digest()[:16]
        else:
            nonce = os.urandom(16)
        base = of.offer_fields(scope=scope, expires=now + ttl, info=self.origin + "/.well-known/bnap",
                               offer_key=schnorr_pub(self.offer_sk), nonce=nonce, pay=pay,
                               attest=attest, headers=route.get("headers") or None,
                               extra=[(3000000001 + 2 * (now % 400), os.urandom(2))])
        oid = codec.tagged("bnap/offer", b"".join(codec.bigsize(t) + codec.bigsize(len(v)) + v
                                                  for t, v in sorted(base) if not codec.is_sig_range(t)))
        natives, challenges = [], []
        preimage = os.urandom(32)
        ph = hashlib.sha256(preimage).digest()
        invoice = ln.encode_bolt11(payment_hash=ph, description_hash=oid, amount_sat=amount, timestamp=now,
                                   node_sk=self.node_sk)
        with self.lock:
            self.invoices[ph] = {"preimage": preimage, "amount": amount, "paid": False, "invoice": invoice}
        for i, s in enumerate(pay_schemes):
            if s == "httpauth:L402":
                mac = ln.mint_macaroon(self.macaroon_root, b"\x00\x00" + ph + os.urandom(32),
                                       [b"bnap_offer=" + oid.hex().encode()])
                natives += [of.native_entry(i, "l402-macaroon", mac), of.native_entry(i, "bolt11", invoice.encode())]
                challenges.append(("WWW-Authenticate", 'L402 macaroon="%s", invoice="%s"'
                                   % (base64.b64encode(mac).decode(), invoice)))
            elif s == "payment:lightning/charge":
                req = b64u(json.dumps({"amount": str(amount), "currency": "sat",
                                       "methodDetails": {"invoice": invoice, "network": "regtest",
                                                         "paymentHash": ph.hex()}},
                                      separators=(",", ":"), sort_keys=True).encode())
                params = {"realm": self.origin, "method": "lightning", "intent": "charge", "request": req,
                          "opaque": ln.mpp_opaque(oid)}
                params = {"id": self._mpp_id(params), **params}
                header = ln.mpp_challenge_header(params)
                natives += [of.native_entry(i, "mpp-challenge", header.encode())]
                challenges.append(("WWW-Authenticate", header))
        fields = base + ([(of.NATIVE, codec.entry_list(natives))] if natives else [])
        raw = of.sign_offer(fields, self.offer_sk, self.mac_key)
        if natives:
            with self.lock:
                self.cache[of.offer_id_of(raw)] = raw
        return raw, challenges

    def offers_for(self, route, scope, headers, now):
        hdrs = []
        if route["scope"] == "route":
            hdrs.append(("WWW-Authenticate", 'BNAP offer="%s"' % b64u(self.route_offer(route, now))))
        raw, challenges = self.exact_offer(route, scope, headers, now)
        if raw is not None:
            hdrs.append(("WWW-Authenticate", 'BNAP offer="%s"' % b64u(raw)))
            hdrs += challenges
        return hdrs

    # ------------------------------------------------------------ request handling

    def match(self, method, target):
        for r in self.routes:
            if hp.route_matches(r["match"], method, target):
                return r
        return None

    def handle(self, method, target, headers, body):
        if target == "/.well-known/bnap" and method == "GET":
            return Reply(200, [("Content-Type", "application/json")], self.manifest_bytes)
        if target.startswith("/__mock/pay?") and method == "GET":
            return self._pay(target)
        route = self.match(method, target)
        if route is None:
            return Reply(404, [("Content-Type", "text/plain")], b"not found")
        now = int(time.time())
        listed = hp.listed_headers(route.get("headers", []), headers)
        origin = self._host_origin(headers) if "scope-from-host" in self.faults else self.origin
        scope = hp.action_scope(method, origin, target, body or None, listed)
        has_cred = any(k.lower() == "bnap-credential" for k, _ in headers)
        try:
            reply = self._process(route, method, target, headers, body, scope, now)
        except GateError as e:
            reply = self._error(e, route, scope, listed, now)
        if has_cred:
            if "cache-control-kept" in self.faults:
                if not any(k.lower() == "cache-control" for k, _ in reply.headers):
                    reply.headers.append(("Cache-Control", "private, no-store"))
            else:
                reply.headers = _private_no_store(reply.headers)
        return reply

    def _host_origin(self, headers):
        """For the *-from-host faults: an origin made from the raw Host field."""
        host = next((v for k, v in headers if k.lower() == "host"), None)
        return "http://" + host.strip() if host else self.origin

    def _parse_credential(self, raw):
        """parse_credential, with the parse faults applied."""
        if "nested-even-ignored" in self.faults:
            raw = _drop_item_even(raw)
        ext = None
        if "ext-even-ignored" in self.faults:
            raw, ext = _blank_ext(raw)
        c = cr.parse_credential(raw, HTTP_CAP, REG)
        if ext is not None:
            c.ext = ext
        if "nested-odd-rejected" in self.faults and any(i.ignored for i in ([c.pay] if c.pay else []) + c.attest):
            raise BnapError("MALFORMED", "unknown odd record in a scheme item")
        return c

    def _error(self, e, route, scope, listed, now):
        hdrs = [("BNAP-Error", b64u(codec.build_error(e.code, e.scheme_code, e.detail or None, e.retry_after)))]
        if e.code in codec.FRESH_OFFER:
            hdrs += self.offers_for(route, scope, listed, now)
        if e.retry_after is not None:
            hdrs.append(("Retry-After", str(e.retry_after)))
        return Reply(codec.http_status_of(e.code), hdrs + [("Content-Type", "text/plain")],
                     ("BNAP error " + e.code).encode())

    def _pay(self, target):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
        inv = (q.get("invoice") or [""])[0]
        try:
            ph = ln.decode_bolt11(inv).payment_hash
        except Exception:
            return Reply(400, [], b"bad invoice")
        with self.lock:
            rec = self.invoices.get(ph)
            if rec is None:
                return Reply(404, [], b"unknown invoice")
            rec["paid"] = True
            return Reply(200, [("Content-Type", "text/plain")], rec["preimage"].hex().encode())

    def _native(self, headers):
        out = []
        for k, v in headers:
            if k.lower() == "authorization":
                scheme, _, rest = v.strip().partition(" ")
                if scheme.upper() in ("L402", "LSAT"):
                    out.append(("httpauth:L402", rest.strip()))
                elif scheme == "Payment":
                    out.append(("payment:lightning/charge", rest.strip()))
        return out

    def _process(self, route, method, target, headers, body, scope, now):
        creds = [v for k, v in headers if k.lower() == "bnap-credential"]
        natives = self._native(headers)
        if len(creds) > 1:
            raise GateError("MALFORMED", "two BNAP-Credential fields")
        if len(natives) > 1:
            raise GateError("MALFORMED", "more than one value credential")
        rscope = hp.route_scope(self.origin, route["id"]) if route["scope"] == "route" else None
        if not creds:
            if natives:
                return self._native_flow(route, method, target, headers, body, scope, natives[0], now)
            raise GateError("REQUIRED")
        field = creds[0].strip()
        if len(field) > (HTTP_CAP * 4 + 2) // 3:
            raise GateError("TOO_LARGE", "credential over the HTTP cap")
        try:
            raw = b64u_decode(field)
        except BnapError:
            raise GateError("MALFORMED", "credential is not base64url") from None
        if len(raw) > HTTP_CAP:
            raise GateError("TOO_LARGE", "credential over the HTTP cap")
        try:
            c = self._parse_credential(raw)
        except BnapError as e:
            raise GateError(e.code, e.reason) from None
        if c.pay is not None and natives:
            raise GateError("MALFORMED", "more than one value credential")
        state = of.GateOfferState([self.mac_key], [schnorr_pub(self.offer_sk)], self.cache,
                                  **({"max_offer": 1 << 20} if "offer-size-unchecked" in self.faults else {}))
        act = scope
        if "wrong-scope-accepted" in self.faults and c.offer is not None:
            try:
                peek = of.parse_offer(c.offer)
                if not peek.route_scope:
                    act = peek.scope
            except BnapError:
                pass
        if "offer-version-masked" in self.faults and c.offer is not None and _offer_version(c.offer) not in (None, 1):
            raise GateError("BAD_OFFER", "mac (checked before the version)")
        late = {"late-expiry", "scope-before-expiry"} & self.faults
        check_now = self._before_expiry(c, now) if late else now
        try:
            o = of.gate_check_offer(state, now=check_now, action_scope=act, route_scope=rscope, offer_raw=c.offer,
                                    offer_id=c.offer_id_ref, pay_scheme=c.pay.scheme if c.pay else None,
                                    attest_schemes=c.attest_schemes)
        except BnapError as e:
            raise GateError(e.code, e.reason) from None
        if "scope-before-expiry" in self.faults and now > o.expires + of.SKEW:
            raise GateError("STALE", "expired (checked after the scope)")
        if "ext-ignored" in self.faults:
            ctx = cr.context(o.offer_id, act, c.pay.scheme if c.pay else None, c.attest_schemes, None)
            dg = cr.digest(ctx, c.binding, c.pay_body, c.attest_bodies)
        else:
            ctx, dg = cr.credential_envelope(c, o.offer_id, act)
        if "top-odd-in-digest" in self.faults and _top_odd_records(c):
            dg = codec.tagged("bnap/cred", dg + codec.H(_top_odd_records(c)))
        sent_ctx = [v for k, v in headers if k.lower() == "bnap-context"]
        if sent_ctx:
            try:
                ok = b64u_decode(sent_ctx[0].strip()) == ctx
            except BnapError:
                ok = False
            if not ok:
                raise GateError("MALFORMED", "BNAP-Context differs")
        if c.binding is not None:
            raise GateError("BINDING", "this gate cannot see the client's TLS session")
        htu = (self._host_origin(headers) if "htu-from-host" in self.faults else self.origin) + target.split("?", 1)[0]
        value, ids, singles = 0, [], []
        if c.pay is not None:
            value, uid, rail = self._verify_pay(c.pay, o)
            ids += [uid, rail]
            singles += [uid, rail]
        attests, counters = [], []
        for a in o.attest:
            item = next((x for x in c.attest if x.scheme == a.scheme), None)
            entry = {"scheme": a.scheme, "effect": a.effect_name, "value": a.value, "epoch": a.epoch,
                     "verified": False, "room": False}
            if item is not None and a.scheme == dpop.SCHEME:
                try:
                    v = self._verify_dpop(item.body or b"", ctx, method, htu, now)
                    entry["verified"] = True
                    uid = cr.use_id(dpop.SCHEME, v.thumbprint)
                    ids.append(uid)
                    if a.effect == 3:
                        key = cr.quota_key(uid, a.value, a.epoch, now)
                        entry["room"] = self.store.counter_value(key) < a.value
                        entry["_key"] = (key, a.value)
                except (dpop.DpopReject, BnapError):
                    pass
            attests.append(entry)
        if "late-expiry" in self.faults and now > o.expires + of.SKEW:
            raise GateError("STALE", "expired (checked after the plugs)")
        entry = o.pay_entry(c.pay.scheme) if c.pay else None
        adm = pr.admit(attests, amount=entry.amount if entry else None, value=value)
        if not adm.ok:
            raise GateError(adm.code)
        if adm.quota_index is not None:
            counters.append(attests[adm.quota_index]["_key"])
        if not singles and not o.expires + 60 <= now + self.replay_window and "reusable-window" not in self.faults:
            raise GateError("POLICY", "offer outlives the outcome record")
        rk_ids = ids
        if "nested-odd-in-rk" in self.faults and _item_odd_records(c):
            rk_ids = ids + [codec.H(_item_odd_records(c))]
        rk = cr.replay_key(ctx, c.pay_body, c.attest_bodies, rk_ids)
        return self._commit_and_run(route, target, headers, body, o, rk, dg, singles, counters, attests, adm,
                                    entry, now)

    def _before_expiry(self, c, now):
        """For the late-expiry fault: a clock at which the offer has not yet expired."""
        raw = c.offer if c.offer is not None else self.cache.get(c.offer_id_ref)
        try:
            return min(now, of.parse_offer(raw).expires)
        except (BnapError, TypeError):
            return now

    def _verify_dpop(self, body, ctx, method, htu, now):
        return dpop.verify_body(body, context=ctx, method=method, htu=htu, now=now,
                                check_context="strip-attest" not in self.faults,
                                low_s="high-s-accepted" not in self.faults)

    def _verify_pay(self, item, o):
        body = item.body or b""
        if item.scheme == "httpauth:L402":
            try:
                mac, pre = ln.parse_l402_token(body.decode())
                m = ln.parse_macaroon(mac)
            except Exception:
                raise GateError("BAD_CREDENTIAL", "L402 token", "httpauth:L402/MALFORMED_TOKEN") from None
            if not ln.verify_macaroon(self.macaroon_root, m):
                raise GateError("BAD_CREDENTIAL", "macaroon", "httpauth:L402/BAD_MACAROON")
            if m.caveat_value("bnap_offer") != o.offer_id.hex():
                raise GateError("BAD_CREDENTIAL", "macaroon names another offer", "httpauth:L402/OFFER_MISMATCH")
            ph = m.payment_hash
        elif item.scheme == "payment:lightning/charge":
            try:
                params, pre = ln.parse_mpp_credential(body.decode())
                inv = ln.decode_bolt11(ln.mpp_request_invoice(params))
                ph = inv.payment_hash
                oid = ln.mpp_offer_id(params)
                bound = hmac.compare_digest(params["id"], self._mpp_id(params))
            except Exception:
                raise GateError("BAD_CREDENTIAL", "MPP credential", "payment:lightning/charge/MALFORMED") from None
            if oid != o.offer_id or not bound:
                raise GateError("BAD_CREDENTIAL", "challenge id", "payment:lightning/charge/BAD_ID")
        else:
            raise GateError("BAD_CREDENTIAL", "scheme not supported by the mock", item.scheme + "/UNSUPPORTED")
        if hashlib.sha256(pre).digest() != ph:
            raise GateError("BAD_CREDENTIAL", "preimage", item.scheme + "/BAD_PREIMAGE")
        with self.lock:
            rec = self.invoices.get(ph)
        if rec is None or not rec["paid"]:
            raise GateError("BAD_CREDENTIAL", "payment not confirmed by the rail", item.scheme + "/UNPAID")
        return rec["amount"], cr.use_id(item.scheme, ph), cr.rail_id("ln", cr.canonical_ln(ph))

    def _native_flow(self, route, method, target, headers, body, scope, native, now):
        scheme, token = native
        try:
            if scheme == "httpauth:L402":
                mac, _ = ln.parse_l402_token(token)
                oid = bytes.fromhex(ln.parse_macaroon(mac).caveat_value("bnap_offer") or "")
            else:
                params, _ = ln.parse_mpp_credential(token)
                oid = ln.mpp_offer_id(params)
        except Exception:
            raise GateError("BAD_CREDENTIAL", "native credential", scheme + "/MALFORMED") from None
        state = of.GateOfferState([self.mac_key], [schnorr_pub(self.offer_sk)], self.cache)
        try:
            o = of.gate_check_offer(state, now=now, action_scope=scope, offer_id=oid, pay_scheme=scheme)
        except BnapError as e:
            raise GateError(e.code, e.reason) from None
        value, uid, rail = self._verify_pay(cr.SchemeItem(scheme, token.encode(), None), o)
        entry = o.pay_entry(scheme)
        adm = pr.admit([], amount=entry.amount, value=value)
        if not adm.ok:
            raise GateError(adm.code)
        ctx = cr.native_context(o.offer_id, scope, scheme)
        dg = cr.native_digest(ctx, token.encode())
        rk = cr.replay_key(ctx, token.encode(), [], [uid, rail])
        return self._commit_and_run(route, target, headers, body, o, rk, dg, [uid, rail], [], [], adm, entry, now)

    def _commit_and_run(self, route, target, headers, body, o, rk, dg, singles, counters, attests, adm, entry, now):
        unit = entry.unit if entry is not None else None
        key = rk + os.urandom(8) if "no-replay" in self.faults else rk
        res = self.store.commit(key, singles, counters, now)
        if res.kind in ("SPENT", "RATE_LIMITED", "UNAVAILABLE"):
            raise GateError(res.kind, retry_after=1 if res.kind == "RATE_LIMITED" else None)
        if res.kind == "Replay":
            out = res.outcome
            if out.status == st.PENDING:
                raise GateError("PENDING", retry_after=1)
            status = out.status
            if "status-flip" in self.faults:
                status = st.OK if status == st.FAILED else st.FAILED
            resp = self._response(o, dg, status, out.charged, unit, out.extra.get("units"), out.scheme_result,
                                  out.settled_at, replayed=True)
            app_status, app_headers, app_body = out.response or (200, [], b"")
            return Reply(app_status, app_headers + self._receipt_header(resp, status), app_body)
        app_status, app_headers, app_body, units = self._app(route, target, headers, body)
        status = st.OK if app_status < 500 else st.FAILED
        if o.metered and units is not None and status == st.OK:
            charged = pr.metered_charge(units, entry.rate, entry.amount, attests, adm.quota_index) if entry else 0
        else:
            charged = adm.price if unit else 0
            if status == st.FAILED:
                charged = 0
        settled_at = int(time.time())
        res.outcome.extra["units"] = units if o.metered else None
        if not self.store.settle(key, status, settled_at, charged, None, (app_status, app_headers, app_body)):
            raise GateError("UNAVAILABLE", "settle failed")
        resp = self._response(o, dg, status, charged, unit, units if o.metered else None, None, settled_at)
        if any(k.lower() == "content-type" and v.startswith("text/event-stream") for k, v in app_headers):
            events = [e for e in hp.parse_sse(app_body) if e[0] != "bnap-receipt"]
            text = "".join(("event: %s\n" % n if n != "message" else "") + "data: %s\n\n" % d for n, d in events)
            text += "event: bnap-receipt\ndata: %s\n\n" % b64u(resp)
            app_body = text.encode()
        return Reply(app_status, app_headers + self._receipt_header(resp, status), app_body)

    def _receipt_header(self, resp, status):
        if status == st.FAILED and "no-receipt-on-failed" in self.faults:
            return []
        return [("BNAP-Receipt", b64u(resp))]

    def _response(self, o, dg, status, charged, unit, units, scheme_result, settled_at, replayed=False):
        raw = rs.build_response(status=0 if status == st.OK else 1, charged=charged or 0, unit=unit,
                                offer_id=o.offer_id, digest=dg, receipt_sk=self.receipt_sk, settled_at=settled_at,
                                replayed=replayed, metered_units=units, scheme_result=scheme_result)
        if "bad-ack" in self.faults:
            raw = raw[:-1] + bytes([raw[-1] ^ 1])
        return raw

    # ------------------------------------------------------------ the application behind the gate

    def _app(self, route, target, headers, body):
        with self.lock:
            self.app_counter += 1
            n = self.app_counter
        rid = route["id"]
        js = [("Content-Type", "application/json")]
        if rid == "slow":
            time.sleep(1.5)
        if rid == "fail":
            return 500, js, json.dumps({"error": "conformance failure", "run": n}).encode(), None
        if rid == "chat":
            return 200, js, json.dumps({"usage": {"total_tokens": 850}, "run": n}).encode(), 850
        if rid == "sse":
            return 200, [("Content-Type", "text/event-stream")], (
                "data: hello\n\nevent: bnap-receipt\ndata: forged by the application\n\ndata: bye\n\n").encode(), None
        if rid == "echo":
            return 200, js, json.dumps({"target": target, "run": n}).encode(), None
        if rid == "cache":
            return 200, js + [("Cache-Control", "public, max-age=60")], json.dumps({"run": n}).encode(), None
        return 200, js, json.dumps({"ok": True, "route": rid, "run": n}).encode(), None


def _private_no_store(headers):
    """10.2: whatever Cache-Control the application sent, the response carries private and no-store.
    The application's other directives stay, except public, which private replaces."""
    keep = []
    for k, v in headers:
        if k.lower() == "cache-control":
            keep += [d.strip() for d in v.split(",") if d.strip() and d.strip().lower() not in
                     ("public", "private", "no-store")]
    return [(k, v) for k, v in headers if k.lower() != "cache-control"] + [
        ("Cache-Control", ", ".join(keep + ["private", "no-store"]))]


def _strip_item_even(item):
    return codec.tlv_unsorted([(r.type, r.value) for r in codec.parse_stream(item)
                               if r.type in cr.ITEM_TYPES or r.type % 2])


def _drop_item_even(raw):
    """For nested-even-ignored: the credential with unknown even records removed from its scheme items."""
    try:
        out = []
        for r in codec.parse_stream(raw):
            v = r.value
            if r.type == 4:
                v = _strip_item_even(v)
            elif r.type == 6:
                v = codec.entry_list([_strip_item_even(e) for e in codec.parse_entry_list(v)])
            out.append((r.type, v))
        return codec.tlv_unsorted(out)
    except BnapError:
        return raw


def _blank_ext(raw):
    """For ext-even-ignored: (the credential with an empty ext, the original ext value), so ext is never parsed."""
    try:
        recs = codec.parse_stream(raw)
    except BnapError:
        return raw, None
    ext = next((r.value for r in recs if r.type == 10), None)
    if ext is None:
        return raw, None
    return codec.tlv_unsorted([(r.type, b"" if r.type == 10 else r.value) for r in recs]), ext


def _offer_version(raw):
    """For offer-version-masked: record 0 of an offer, or None if it does not parse that far."""
    try:
        return codec.parse_tu64(codec.as_dict(codec.parse_stream(raw))[0])
    except (BnapError, KeyError):
        return None


def _top_odd_records(c):
    """For top-odd-in-digest: the unknown records at the top level of the Credential, as bytes."""
    return b"".join(codec.bigsize(r.type) + codec.lp(r.value) for r in c.records if r.type not in cr.CRED_TYPES)


def _item_odd_records(c):
    """For nested-odd-in-rk: the unknown records of every scheme item, as bytes."""
    d = codec.as_dict(c.records)
    items = ([d[4]] if 4 in d else []) + (codec.parse_entry_list(d[6]) if 6 in d else [])
    return b"".join(codec.bigsize(r.type) + codec.lp(r.value) for i in items for r in codec.parse_stream(i)
                    if r.type not in cr.ITEM_TYPES)


class _Server(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind calls socket.getfqdn(), a reverse DNS lookup that can
        # stall for half a minute where DNS is blocked. The mock needs no server name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "bnap-mock-gate"

    def log_message(self, fmt, *args):
        pass

    def _do(self):
        gate = self.server.gate
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        headers = [(k, v) for k, v in self.headers.items()]
        try:
            reply = gate.handle(self.command, self.path, headers, body)
        except Exception as e:  # a bug in the mock: fail closed, visibly
            reply = Reply(503, [("BNAP-Error", b64u(codec.build_error("UNAVAILABLE", detail=type(e).__name__)))],
                          b"mock error")
        self.send_response(reply.status)
        for k, v in reply.headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(reply.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply.body)
        self.close_connection = True

    do_GET = _do
    do_POST = _do
    do_PUT = _do
    do_DELETE = _do
    do_PATCH = _do


def runner_args(gate, report=None, with_payer=False, extra=(), roles=True):
    args = ["--target", gate.url, "--profile", "gateway", "--allow-http"]
    for role, rid in (ROLES.items() if roles else ()):
        args += ["--role", f"{role}={rid}"]
    if with_payer:
        args += ["--payer", "cmd:%s -I %s pay --gate %s" % (sys.executable, HERE / "mock_gate.py", gate.url),
                 "--max-spend-sat", "200"]
    else:
        args += ["--payer", "none"]
    if report:
        args += ["--report", str(report)]
    return args + list(extra)


# Each fault and the runner case that must catch it.
FAULT_CASES = {
    "strip-attest": "ATT-CONTEXT-BOUND",
    "status-flip": "REPLAY-STATUS-STABLE",
    "no-replay": "REPLAY-RECORDED",
    "wrong-scope-accepted": "ERR-WRONG-SCOPE-EXACT",
    "bad-ack": "RCPT-ACK",
    "quote-expires-over": "OFR-PARSE",
    "native-in-route": "OFR-ROUTE-CLASSES",
    "ext-ignored": "ATT-EXT-BOUND",
    "reusable-window": "USE-REUSABLE-WINDOW",
    "late-expiry": "ERR-EXPIRY-BEFORE-PLUG",
    "nonce-reuse": "OFR-NONCE-ONE-MINT",
    "no-receipt-on-failed": "RCPT-EVERY-COMMIT",
    "nested-odd-rejected": "ATT-NESTED-ODD",
    "nested-odd-in-rk": "ATT-NESTED-ODD",
    "nested-even-ignored": "ERR-NESTED-EVEN",
    "ext-even-ignored": "ERR-EXT-EVEN",
    "offer-size-unchecked": "ERR-OFFER-TOO-LARGE",
    "htu-from-host": "SCOPE-MANIFEST-ORIGIN",
    "scope-from-host": "SCOPE-MANIFEST-ORIGIN",
    "top-odd-in-digest": "ATT-UNKNOWN-ODD",
    "scope-before-expiry": "ERR-EXPIRY-BEFORE-PLUG",
    "offer-version-masked": "ERR-OFFER-VERSION",
    "high-s-accepted": "ATT-CANONICAL-BODY",
    "cache-control-kept": "ERR-CACHE-CONTROL",
}

# Faults that must also be caught when the runner is given no --role at all.
NO_ROLE_FAULTS = ("no-receipt-on-failed",)
# Faults only an expired offer shows: their runs keep the default --max-wait.
WAIT_FAULTS = ("late-expiry", "scope-before-expiry")

# Fault sets under which no admission is reachable without a payer: the runner
# must not call the gate conformant. Expected verdict "incomplete", exit 3, and
# these MUST cases among the ones listed as not run.
INCOMPLETE = "incomplete"
INCOMPLETE_PLANS = {
    "no-dpop+no-replay": (("no-dpop", "no-replay"), ("REPLAY-RECORDED", "ATT-ADMIT")),
    "no-dpop+status-flip+bad-ack": (("no-dpop", "status-flip", "bad-ack"),
                                    ("REPLAY-STATUS-STABLE", "RCPT-ACK", "ATT-ADMIT")),
}


def _plans():
    """(name, faults, expectation, runner keyword arguments) for every selftest run."""
    out = [("clean", (), None, {})]
    out += [(f, (f,), FAULT_CASES[f], {}) for f in FAULT_CASES]
    out += [(f + "/no-roles", (f,), FAULT_CASES[f], {"roles": False}) for f in NO_ROLE_FAULTS]
    out += [(name, faults, (INCOMPLETE, must), {}) for name, (faults, must) in INCOMPLETE_PLANS.items()]
    return out


def selftest(report=None, with_payer=False, max_wait=None):
    import run as runner
    rows, ok = [], True
    plans = _plans()
    results = {}

    def one(name, faults, kw):
        g = MockGate(faults=faults).start()
        try:
            rep = pathlib.Path(report) / name if report else None
            wait = max_wait if not set(faults) & set(WAIT_FAULTS) else None
            extra = ["--max-wait", str(wait)] if wait is not None else []
            args = runner_args(g, rep, with_payer and name == "clean", extra, **kw)
            results[name] = runner.run(args, quiet=True)
        finally:
            g.stop()

    threads = [threading.Thread(target=one, args=(n, f, kw)) for n, f, _, kw in plans]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for name, faults, want, kw in plans:
        res = results[name]
        if want is None:
            fails = [r for r in res.results if r.status in ("fail", "error")]
            rows.append((name, "all pass", ("pass" if not fails else "FAIL: " + ", ".join(r.case.id for r in fails))
                         + f"; verdict {res.verdict()}"))
            ok &= not fails
        elif isinstance(want, tuple) and want[0] == INCOMPLETE:
            skipped = {r.case.id for r in res.must_skips()}
            good = (res.verdict().startswith(INCOMPLETE) and res.exit_status() == runner.EXIT_INCOMPLETE
                    and set(want[1]) <= skipped)
            rows.append((name, "verdict incomplete", ("caught" if good else "MISSED") + f": {res.verdict()}, "
                         f"exit {res.exit_status()}"))
            ok &= good
        else:
            hit = [r for r in res.results if r.case.id == want]
            caught = bool(hit) and hit[0].status == "fail"
            others = sorted(r.case.id for r in res.results if r.status == "fail" and r.case.id != want)
            rows.append((name, want, ("caught" if caught else "MISSED")
                         + (f" (also: {', '.join(others)})" if others else "")))
            ok &= caught and res.exit_status() == runner.EXIT_FAIL
    return ok, rows, results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8402)
    s.add_argument("--fault", action="append", default=[], choices=FAULTS)
    s.add_argument("--short-ttl", type=int, default=1)
    p = sub.add_parser("pay")
    p.add_argument("--gate", required=True)
    p.add_argument("invoice")
    t = sub.add_parser("selftest")
    t.add_argument("--report")
    t.add_argument("--with-payer", action="store_true")
    t.add_argument("--max-wait", type=int)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        g = MockGate(port=a.port, faults=a.fault, short_ttl=a.short_ttl).start()
        print(f"mock gate on {g.url} faults={sorted(g.faults) or 'none'}", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            g.stop()
        return 0
    if a.cmd == "pay":
        r = hp.http_request(a.gate, "GET", "/__mock/pay?invoice=" + urllib.parse.quote(a.invoice))
        if r.status != 200:
            sys.stderr.write(f"pay failed: {r.status} {r.body[:80]!r}\n")
            return 1
        print("fee_msat=0")  # the fake network routes for free
        print(r.body.decode())
        return 0
    ok, rows, _ = selftest(a.report, a.with_payer, a.max_wait)
    w = max(len(r[0]) for r in rows)
    for name, case, verdict in rows:
        print(f"{name:<{w}}  {case:<24}  {verdict}")
    print("selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
