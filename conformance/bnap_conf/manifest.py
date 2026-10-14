"""The manifest (draft-00 section 9): strict JSON, JCS, root signature, pinning.

The manifest is hashed and signed through JCS (RFC 8785), which assumes
I-JSON (RFC 7493). parse_json_strict() therefore rejects duplicate member
names at every depth, numbers that are not integers, integers beyond 2^53,
null, lone surrogates and a byte order mark, so two parsers can never read
two different documents out of the same signed bytes.
"""
import json
import re

from .codec import H, tagged
from .crypto import schnorr_verify, schnorr_sign
from .offer import origin_of, EFFECT_CODES

SKEW = 60
MAX_AGE_LIMIT = 2_592_000
PIN_CAP = 30 * 86400
REFETCH_MIN = 300
INT_LIMIT = 1 << 53
DEFAULT_LIMITS = {"replay_window": 86400, "pending_timeout": 300,  # DECISIONS row 21
                  "max_offer": 4096, "max_credential": 16384, "max_response": 8192}

_HEX32 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{128}\Z")
_TOKEN_LOWER = re.compile(r"\A[!#$%&'*+.^_`|~0-9a-z-]+\Z")
_METHOD = re.compile(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class ManifestReject(Exception):
    def __init__(self, reason, detail=""):
        self.reason = reason
        self.detail = detail
        super().__init__(reason + (f": {detail}" if detail else ""))

# ---------------------------------------------------------------- strict JSON


def _reject_float(s):
    raise ManifestReject("json-number-not-integer", s)


def _reject_constant(s):
    raise ManifestReject("json-constant", s)


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ManifestReject("json-duplicate-member", k)
        out[k] = v
    return out


def _walk(v, path):
    if v is None:
        raise ManifestReject("json-null", path)
    if isinstance(v, bool):
        return
    if isinstance(v, int):
        if abs(v) > INT_LIMIT:
            raise ManifestReject("json-integer-range", path)
        return
    if isinstance(v, str):
        try:
            v.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ManifestReject("json-lone-surrogate", path) from None
        return
    if isinstance(v, list):
        for i, x in enumerate(v):
            _walk(x, f"{path}[{i}]")
        return
    if isinstance(v, dict):
        for k, x in v.items():
            _walk(k, path + ".<name>")
            _walk(x, f"{path}.{k}")
        return
    raise ManifestReject("json-type", path)


def parse_json_strict(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ManifestReject("json-bom")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ManifestReject("json-utf8") from None
    try:
        obj = json.loads(text, object_pairs_hook=_pairs, parse_float=_reject_float,
                         parse_constant=_reject_constant)
    except ManifestReject:
        raise
    except (ValueError, RecursionError) as e:
        raise ManifestReject("json-syntax", str(e)[:80]) from None
    _walk(obj, "$")
    return obj

# ---------------------------------------------------------------- JCS


def _quote(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > INT_LIMIT:
            raise ValueError("integer beyond 2^53")
        return str(v)
    if isinstance(v, str):
        return _quote(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_quote(k) + ":" + _jcs(v[k]) for k in keys) + "}"
    raise ValueError("JCS: unsupported value " + type(v).__name__)


def jcs(obj):
    """RFC 8785 for values holding strings, integers, booleans, arrays and objects."""
    return _jcs(obj).encode("utf-8")


def signing_input(obj):
    body = {k: v for k, v in obj.items() if k != "sig"}
    return tagged("bnap/manifest", jcs(body))


def sign_manifest(obj, root_sk):
    body = {k: v for k, v in obj.items() if k != "sig"}
    sig = schnorr_sign(root_sk, tagged("bnap/manifest", jcs(body)))
    out = dict(body)
    out["sig"] = sig.hex()
    return out


def sig_valid(obj):
    root, sig = obj.get("root"), obj.get("sig")
    if not (isinstance(root, str) and _HEX32.match(root) and isinstance(sig, str) and _HEX64.match(sig)):
        return False
    return schnorr_verify(bytes.fromhex(root), signing_input(obj), bytes.fromhex(sig))

# ---------------------------------------------------------------- document checks (9.1)


def limits_of(obj):
    out = dict(DEFAULT_LIMITS)
    lim = obj.get("limits")
    if isinstance(lim, dict):
        for k in DEFAULT_LIMITS:
            if isinstance(lim.get(k), int) and not isinstance(lim.get(k), bool):
                out[k] = lim[k]
    return out


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def document_problems(obj, origin=None, now=None):
    """Return a list of (reason, detail) for the 9.1 rules this document breaks."""
    p = []
    if not isinstance(obj, dict):
        return [("not-an-object", "")]
    for m in ("bnap", "origin", "seq", "issued", "max_age", "root", "backup", "keys", "sig"):
        if m not in obj:
            p.append(("missing-member", m))
    if "bnap" in obj and obj["bnap"] != 1 or isinstance(obj.get("bnap"), bool):
        p.append(("bnap-not-1", repr(obj.get("bnap"))))
    o = obj.get("origin")
    if "origin" in obj:
        if not isinstance(o, str) or origin_of(o) != o:
            p.append(("origin-not-serialized", repr(o)))
        elif origin is not None and o != origin:
            p.append(("origin-mismatch", f"{o} != {origin}"))
    for m in ("seq", "issued", "max_age"):
        if m in obj and (not _is_int(obj[m]) or obj[m] < 0):
            p.append(("bad-integer", m))
    if _is_int(obj.get("max_age")) and obj["max_age"] > MAX_AGE_LIMIT:
        p.append(("max-age-over-30-days", str(obj["max_age"])))
    for m in ("root", "backup"):
        if m in obj and not (isinstance(obj[m], str) and _HEX32.match(obj[m])):
            p.append(("bad-key-hex", m))
    if "sig" in obj and not (isinstance(obj["sig"], str) and _HEX64.match(obj["sig"])):
        p.append(("bad-sig-hex", ""))
    keys = obj.get("keys")
    if "keys" in obj:
        if not isinstance(keys, list):
            p.append(("bad-keys", "not an array"))
        else:
            for i, k in enumerate(keys):
                if not (isinstance(k, dict) and isinstance(k.get("kid"), str) and _HEX32.match(k["kid"])
                        and k.get("use") in ("offer", "receipt") and _is_int(k.get("not_after"))):
                    p.append(("bad-key-entry", str(i)))
    if "required" in obj and not isinstance(obj["required"], bool):
        p.append(("bad-required", ""))
    if "limits" in obj:
        lim = obj["limits"]
        if not isinstance(lim, dict):
            p.append(("bad-limits", ""))
        else:
            for k, v in lim.items():
                if k in DEFAULT_LIMITS and (not _is_int(v) or v < 0):
                    p.append(("bad-limit", k))
    if "carriers" in obj and not (isinstance(obj["carriers"], list)
                                  and all(isinstance(c, str) for c in obj["carriers"])):
        p.append(("bad-carriers", ""))
    if "routes" in obj:
        routes = obj["routes"]
        if not isinstance(routes, list):
            p.append(("bad-routes", ""))
        else:
            ids = set()
            for i, r in enumerate(routes):
                for reason in route_problems(r):
                    p.append((reason, str(i)))
                if isinstance(r, dict):
                    if r.get("id") in ids:
                        p.append(("duplicate-route-id", str(r.get("id"))))
                    ids.add(r.get("id"))
    if isinstance(obj.get("root"), str) and "sig" in obj and not sig_valid(obj):
        p.append(("sig-invalid", ""))
    if now is not None and _is_int(obj.get("issued")) and _is_int(obj.get("max_age")):
        if not obj["issued"] - SKEW <= now <= obj["issued"] + obj["max_age"] + SKEW:
            p.append(("issued-window", f"issued {obj['issued']} max_age {obj['max_age']} now {now}"))
    return p


def route_problems(r):
    out = []
    if not isinstance(r, dict):
        return ["route-not-object"]
    if not isinstance(r.get("id"), str) or not r.get("id"):
        out.append("route-id")
    m = r.get("match")
    if not isinstance(m, str) or m.count(" ") != 1 or not _METHOD.match(m.split(" ")[0]) \
            or not m.split(" ")[1].startswith("/"):
        out.append("route-match")
    if r.get("scope", "exact") not in ("exact", "route"):
        out.append("route-scope-value")
    if "metered" in r and not isinstance(r["metered"], bool):
        out.append("route-metered")
    if r.get("metered") and not isinstance(r.get("meter"), str):
        out.append("route-meter")
    price = r.get("price", {})
    if not isinstance(price, dict) or not all(_is_int(v) and v >= 0 for v in price.values()):
        out.append("route-price")
    pay = r.get("pay", [])
    if not isinstance(pay, list) or not all(isinstance(s, str) for s in pay):
        out.append("route-pay")
    att = r.get("attest", [])
    if not isinstance(att, list):
        out.append("route-attest")
    else:
        for a in att:
            if not (isinstance(a, dict) and isinstance(a.get("scheme"), str)
                    and a.get("effect") in EFFECT_CODES):
                out.append("route-attest-entry")
    hd = r.get("headers", [])
    if not isinstance(hd, list) or not all(isinstance(h, str) and _TOKEN_LOWER.match(h) for h in hd):
        out.append("route-headers")
    if "require" in r and not isinstance(r["require"], dict):
        out.append("route-require")
    return out

# ---------------------------------------------------------------- pinning (9.3)


class Pin:
    def __init__(self, root, backup, seq, hash_, required, keys, until):
        self.root = root
        self.backup = backup
        self.seq = seq
        self.hash = hash_
        self.required = required
        self.keys = keys
        self.until = until

    def live(self, now):
        return now <= self.until

    def to_json(self):
        return {"root": self.root, "backup": self.backup, "seq": self.seq, "hash": self.hash.hex(),
                "required": self.required, "keys": self.keys, "until": self.until}

    @classmethod
    def from_json(cls, d):
        return cls(d["root"], d["backup"], d["seq"], bytes.fromhex(d["hash"]), d["required"],
                   d["keys"], d["until"])


def may_fetch(url, last_fetch, now):
    """9.3 fetch(): HTTPS only, at most once per 5 minutes. Return (ok, reason)."""
    if not url.startswith("https://"):
        return False, "https-only"
    if last_fetch is not None and now - last_fetch < REFETCH_MIN:
        return False, "fetched-within-5-minutes"
    return True, None


def fetch_accept(raw, *, origin, now, pin=None):
    """The fetch(origin) rule of 9.3 after the GET. Return the new Pin or raise."""
    m = parse_json_strict(raw)
    if not isinstance(m, dict):
        raise ManifestReject("not-an-object")
    if m.get("bnap") != 1 or isinstance(m.get("bnap"), bool):
        raise ManifestReject("bnap-not-1")
    if m.get("origin") != origin:
        raise ManifestReject("origin-mismatch")
    if not sig_valid(m):
        raise ManifestReject("sig-invalid")
    issued, max_age = m.get("issued"), m.get("max_age")
    if not (_is_int(issued) and _is_int(max_age)):
        raise ManifestReject("bad-integer")
    if max_age > MAX_AGE_LIMIT:
        raise ManifestReject("max-age-over-30-days")
    if not issued - SKEW <= now <= issued + max_age + SKEW:
        raise ManifestReject("issued-window")
    seq = m.get("seq")
    if not _is_int(seq):
        raise ManifestReject("bad-integer", "seq")
    h = H(raw if isinstance(raw, bytes) else raw.encode())
    if pin is not None and pin.live(now):
        same = m.get("root") == pin.root and m.get("backup") == pin.backup
        rotation = m.get("root") == pin.backup
        if not (same or rotation):
            if m.get("root") == pin.root:
                raise ManifestReject("backup-changed-without-rotation")
            raise ManifestReject("root-not-pinned")
        if not (seq > pin.seq or h == pin.hash):
            raise ManifestReject("rollback")
    keys = m.get("keys") if isinstance(m.get("keys"), list) else []
    return Pin(m["root"], m.get("backup"), seq, h, bool(m.get("required", False)), keys,
               min(issued + max_age, now + PIN_CAP))
