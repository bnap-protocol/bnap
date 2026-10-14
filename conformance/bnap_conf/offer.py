"""The Offer (draft-00 section 4): parse, rules, OfferID, signature, checks.

parse_offer() applies every encoding rule of sections 2 and 4.1 and raises
BnapError(TOO_LARGE | MALFORMED | VERSION). offer_rule_violations() applies
the rules that need the registry (binding classes, metering, quotas).
client_check_offer() is the client side of 4.4 and gate_check_offer() the
gate side, in the order 4.4 fixes. A client cannot check the MAC.
"""
import re
import urllib.parse

from . import codec
from .codec import BnapError, malformed, parse_tu64, utf8, fixed, flag, tagged
from .crypto import schnorr_sign, schnorr_verify, schnorr_pub

SKEW = 60
DEFAULT_MAX_OFFER = 4096

OFFER_TYPES = frozenset({0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 26, 240, 242})
PAY_TYPES = frozenset({0, 2, 4, 6, 8, 10})
ATTEST_TYPES = frozenset({0, 2, 4, 6, 8})
NATIVE_TYPES = frozenset({0, 2, 4})
OFFER_SIG, MAC, NATIVE = 240, 242, 26

EFFECTS = {0: "required", 1: "waive", 2: "discount", 3: "quota"}
EFFECT_CODES = {v: k for k, v in EFFECTS.items()}

_TCHAR_LOWER = re.compile(r"\A[!#$%&'*+.^_`|~0-9a-z-]+\Z")


class PayEntry:
    def __init__(self, scheme, amount, unit, quote_expires, params, rate, ignored):
        self.scheme = scheme
        self.amount = amount
        self.unit = unit
        self.quote_expires = quote_expires
        self.params = params
        self.rate = rate
        self.ignored = ignored


class AttestEntry:
    def __init__(self, scheme, effect, value, epoch, params, ignored):
        self.scheme = scheme
        self.effect = effect
        self.value = value
        self.epoch = epoch
        self.params = params
        self.ignored = ignored

    @property
    def effect_name(self):
        return EFFECTS[self.effect]


class NativeEntry:
    def __init__(self, pay_index, kind, data):
        self.pay_index = pay_index
        self.kind = kind
        self.data = data


class Offer:
    """A parsed Offer. raw is the exact byte string received."""

    def __init__(self, raw, records):
        self.raw = raw
        self.records = records
        self.ignored = []
        self.version = None
        self.scope = None
        self.route_scope = False
        self.headers = None
        self.metered = False
        self.expires = None
        self.info = None
        self.offer_key = None
        self.nonce = None
        self.pay = []
        self.attest = []
        self.issued_at = None
        self.native = []
        self.offer_sig = None
        self.mac = None
        self.offer_id = tagged("bnap/offer", codec.signed_bytes(records, exclude=(NATIVE,)))
        self.signed = codec.signed_bytes(records)

    def pay_entry(self, scheme):
        for e in self.pay:
            if e.scheme == scheme:
                return e
        return None

    def attest_entry(self, scheme):
        for e in self.attest:
            if e.scheme == scheme:
                return e
        return None

    def has_waive(self):
        return any(a.effect == 1 for a in self.attest)

    def grease_types(self):
        return [r.type for r in self.records if codec.is_grease(r.type)]


def _parse_headers(b):
    s = utf8(b, "headers")
    names = s.split(",")
    for n in names:
        if not _TCHAR_LOWER.match(n):
            raise malformed("bad-headers-record", s)
    return names


def _nested(raw, known, what):
    recs = codec.parse_stream(raw)
    ignored = codec.check_known(recs, known, nested=True)
    return codec.as_dict(recs), ignored


def parse_pay_entry(raw, metered):
    d, ignored = _nested(raw, PAY_TYPES, "pay")
    for t, name in ((0, "scheme"), (2, "amount"), (4, "unit")):
        if t not in d:
            raise malformed("missing-record", "pay entry " + name)
    scheme = utf8(d[0], "scheme")
    if not scheme:
        raise malformed("empty-scheme-id")
    unit = utf8(d[4], "unit")
    if not unit:
        raise malformed("empty-unit")
    rate = parse_tu64(d[10]) if 10 in d else None
    if metered and rate is None:
        raise malformed("metered-entry-without-rate", scheme)
    return PayEntry(scheme, parse_tu64(d[2]), unit,
                    parse_tu64(d[6]) if 6 in d else None,
                    d.get(8), rate, ignored)


def parse_attest_entry(raw):
    d, ignored = _nested(raw, ATTEST_TYPES, "attest")
    for t, name in ((0, "scheme"), (2, "effect")):
        if t not in d:
            raise malformed("missing-record", "attest entry " + name)
    scheme = utf8(d[0], "scheme")
    if not scheme:
        raise malformed("empty-scheme-id")
    effect = parse_tu64(d[2])
    if effect not in EFFECTS:
        raise malformed("effect-out-of-range", str(effect))
    value = parse_tu64(d[4]) if 4 in d else None
    epoch = parse_tu64(d[6]) if 6 in d else None
    if effect == 2 and (value is None or not 1 <= value <= 10000):
        raise malformed("discount-value-out-of-range", str(value))
    if effect == 3:
        if value is None or value < 1:
            raise malformed("quota-value-out-of-range", str(value))
        if epoch is None or epoch < 1:
            raise malformed("quota-epoch-out-of-range", str(epoch))
    return AttestEntry(scheme, effect, value, epoch, d.get(8), ignored)


def parse_native_entry(raw):
    d, _ = _nested(raw, NATIVE_TYPES, "native")
    for t, name in ((0, "pay_index"), (2, "kind"), (4, "data")):
        if t not in d:
            raise malformed("missing-record", "native entry " + name)
    kind = utf8(d[2], "kind")
    if not kind:
        raise malformed("empty-native-kind")
    return NativeEntry(parse_tu64(d[0]), kind, d[4])


def parse_offer(raw, max_size=DEFAULT_MAX_OFFER):
    raw = bytes(raw)
    if len(raw) > max_size:
        raise BnapError("TOO_LARGE", "offer-size", f"{len(raw)} > {max_size}")
    recs = codec.parse_stream(raw)
    d = codec.as_dict(recs)
    if 0 not in d:
        raise malformed("missing-record", "version")
    version = parse_tu64(d[0])
    if version != 1:
        raise BnapError("VERSION", "unsupported-version", str(version))
    o = Offer(raw, recs)
    o.version = version
    o.ignored = codec.check_known(recs, OFFER_TYPES)
    for t, name in ((2, "scope"), (10, "expires"), (14, "offer_key"), (16, "nonce"),
                    (OFFER_SIG, "offer_sig")):
        if t not in d:
            raise malformed("missing-record", name)
    o.scope = fixed(d[2], 32, "scope")
    o.route_scope = flag(d[4], "route_scope") if 4 in d else False
    o.headers = _parse_headers(d[6]) if 6 in d else None
    o.metered = flag(d[8], "metered") if 8 in d else False
    o.expires = parse_tu64(d[10])
    o.info = utf8(d[12], "info") if 12 in d else None
    o.offer_key = fixed(d[14], 32, "offer_key")
    o.nonce = fixed(d[16], 16, "nonce")
    if 18 in d:
        o.pay = [parse_pay_entry(e, o.metered) for e in codec.parse_entry_list(d[18])]
    if 20 in d:
        o.attest = [parse_attest_entry(e) for e in codec.parse_entry_list(d[20])]
    o.issued_at = parse_tu64(d[24]) if 24 in d else None
    if NATIVE in d:
        o.native = [parse_native_entry(e) for e in codec.parse_entry_list(d[NATIVE])]
    o.offer_sig = fixed(d[OFFER_SIG], 64, "offer_sig")
    o.mac = fixed(d[MAC], 32, "mac") if MAC in d else None
    seen = set()
    for e in o.pay:
        if e.scheme in seen:
            raise malformed("duplicate-pay-scheme", e.scheme)
        seen.add(e.scheme)
        if e.quote_expires is not None and e.quote_expires > o.expires:
            raise malformed("quote-expires-after-expires", e.scheme)
    seen = set()
    for a in o.attest:
        if a.scheme in seen:
            raise malformed("duplicate-attest-scheme", a.scheme)
        seen.add(a.scheme)
    if not o.pay and not o.has_waive():
        raise malformed("pay-required", "no pay entries and no waive")
    if o.native and o.route_scope:
        raise malformed("native-in-route-offer")
    for n in o.native:
        if n.pay_index >= len(o.pay):
            raise malformed("native-pay-index", str(n.pay_index))
    return o


def offer_rule_violations(o, registry):
    """Rules that need the registry. Return a list of reason labels."""
    out = []
    cls = registry.binding
    if o.route_scope:
        for e in list(o.pay) + list(o.attest):
            c = cls(e.scheme)
            if c is not None and c not in ("S", "A"):
                out.append(f"class-{c}-in-route-offer:{e.scheme}")
    for n in o.native:
        s = o.pay[n.pay_index].scheme
        c = cls(s)
        if c is not None and c != "O":
            out.append(f"native-for-class-{c}:{s}")
    for a in o.attest:
        c = cls(a.scheme)
        if a.effect in (1, 2, 3) and c is not None and c not in ("S", "A", "O"):
            out.append(f"class-{c}-{a.effect_name}:{a.scheme}")
        if a.effect == 3 and registry.known(a.scheme) and not registry.quota_id(a.scheme):
            out.append(f"quota-without-quota-id:{a.scheme}")
    for e in o.pay:
        c = cls(e.scheme)
        if c == "none" and e.amount > 0:
            out.append(f"class-none-priced:{e.scheme}")
        if o.metered and registry.known(e.scheme) and not registry.meterable(e.scheme):
            out.append(f"metered-not-refundable:{e.scheme}")
    return out


def verify_offer_sig(o):
    return schnorr_verify(o.offer_key, tagged("bnap/offer-sig", o.signed), o.offer_sig)


def verify_mac(o, mac_keys):
    if o.mac is None:
        return False
    for k in mac_keys:
        if codec.hmac_sha256(k, o.signed) == o.mac:
            return True
    return False


def offer_id_of(raw):
    recs = codec.parse_stream(raw)
    return tagged("bnap/offer", codec.signed_bytes(recs, exclude=(NATIVE,)))

# ---------------------------------------------------------------- building


def pay_entry(scheme, amount, unit="sat", quote_expires=None, params=None, rate=None, extra=()):
    recs = [(0, scheme.encode()), (2, codec.tu64(amount)), (4, unit.encode())]
    if quote_expires is not None:
        recs.append((6, codec.tu64(quote_expires)))
    if params is not None:
        recs.append((8, params))
    if rate is not None:
        recs.append((10, codec.tu64(rate)))
    recs.extend(extra)
    return codec.tlv(sorted(recs))


def attest_entry(scheme, effect, value=None, epoch=None, params=None, extra=()):
    eff = EFFECT_CODES[effect] if isinstance(effect, str) else effect
    recs = [(0, scheme.encode()), (2, codec.tu64(eff))]
    if value is not None:
        recs.append((4, codec.tu64(value)))
    if epoch is not None:
        recs.append((6, codec.tu64(epoch)))
    if params is not None:
        recs.append((8, params))
    recs.extend(extra)
    return codec.tlv(sorted(recs))


def native_entry(pay_index, kind, data):
    return codec.tlv([(0, codec.tu64(pay_index)), (2, kind.encode()), (4, data)])


def sign_offer(records, offer_sk, mac_key=None, sig_override=None):
    """records: (type, value) pairs without 240/242. Return the offer bytes.

    sig_override replaces the signature (for negative tests).
    """
    recs = sorted(records)
    body = [(t, v) for t, v in recs if not codec.is_sig_range(t)]
    S = b"".join(codec.bigsize(t) + codec.bigsize(len(v)) + v for t, v in body)
    sig = sig_override if sig_override is not None else schnorr_sign(offer_sk, tagged("bnap/offer-sig", S))
    extra = [(OFFER_SIG, sig)]
    if mac_key is not None:
        extra.append((MAC, codec.hmac_sha256(mac_key, S)))
    return codec.tlv(sorted(recs + extra))


def offer_fields(*, scope, expires, offer_key, nonce, pay=(), attest=(), route_scope=False,
                 headers=None, metered=False, info=None, issued_at=None, native=(), extra=()):
    """Assemble offer records from parts (entries already encoded)."""
    recs = [(0, codec.tu64(1)), (2, scope), (10, codec.tu64(expires)), (14, offer_key), (16, nonce)]
    if route_scope:
        recs.append((4, b""))
    if headers:
        recs.append((6, ",".join(headers).encode()))
    if metered:
        recs.append((8, b""))
    if info is not None:
        recs.append((12, info.encode()))
    if pay:
        recs.append((18, codec.entry_list(pay)))
    if attest:
        recs.append((20, codec.entry_list(attest)))
    if issued_at is not None:
        recs.append((24, codec.tu64(issued_at)))
    if native:
        recs.append((NATIVE, codec.entry_list(native)))
    recs.extend(extra)
    return recs

# ---------------------------------------------------------------- checks (4.4)


def origin_of(uri):
    """RFC 6454 serialization of the origin of an absolute http(s) URI."""
    u = urllib.parse.urlsplit(uri)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    host = u.hostname.lower()
    try:
        port = u.port
    except ValueError:
        return None
    default = {"http": 80, "https": 443}[u.scheme]
    if ":" in host:
        host = "[" + host + "]"
    if port is None or port == default:
        return f"{u.scheme}://{host}"
    return f"{u.scheme}://{host}:{port}"


def info_same_origin(info, origin):
    if info.startswith("/") and not info.startswith("//"):
        return True
    return origin_of(info) == origin


def key_listed(keys, kid, use, at):
    for k in keys or ():
        if k.get("kid", "").lower() == kid.hex() and k.get("use") == use and k.get("not_after", -1) >= at:
            return True
    return False


class OfferCheck:
    def __init__(self, ok, code=None, reason=None, offer=None, tofu=False, violations=()):
        self.ok = ok
        self.code = code
        self.reason = reason
        self.offer = offer
        self.tofu = tofu
        self.violations = list(violations)

    def __repr__(self):
        return f"OfferCheck(ok={self.ok}, code={self.code}, reason={self.reason})"


def client_check_offer(raw, *, now, origin, pin_keys=None, scope=None, route_scope=None,
                       registry=None, max_size=DEFAULT_MAX_OFFER):
    """The client checks of 4.4. pin_keys None means no pin: trust on first use.

    scope: the action scope of the request the client is about to send.
    route_scope: the route scope of the manifest route it expects, if any.
    """
    try:
        o = parse_offer(raw, max_size)
    except BnapError as e:
        return OfferCheck(False, e.code, e.reason)
    if now > o.expires + SKEW:
        return OfferCheck(False, "STALE", "expired", o)
    if o.issued_at is not None and o.issued_at > now + SKEW:
        return OfferCheck(False, "STALE", "issued-in-future", o)
    if o.mac is None and o.issued_at is None:
        return OfferCheck(False, "BAD_OFFER", "advance-offer-without-issued-at", o)
    tofu = pin_keys is None
    if not tofu and not key_listed(pin_keys, o.offer_key, "offer", now):
        return OfferCheck(False, "BAD_OFFER", "offer-key-not-pinned", o)
    if not verify_offer_sig(o):
        return OfferCheck(False, "BAD_OFFER", "offer-sig", o)
    if o.info is not None and not info_same_origin(o.info, origin):
        return OfferCheck(False, "BAD_OFFER", "info-cross-origin", o)
    want = route_scope if o.route_scope else scope
    if want is None or want != o.scope:
        return OfferCheck(False, "WRONG_SCOPE", "scope-mismatch", o)
    if registry is not None:
        v = offer_rule_violations(o, registry)
        if v:
            return OfferCheck(False, "MALFORMED", v[0], o, violations=v)
    return OfferCheck(True, offer=o, tofu=tofu)


class GateOfferState:
    """What a gate holds for 4.4 step 3 and offer-by-reference lookups."""

    def __init__(self, mac_keys, listed_offer_keys, cache=None, max_offer=DEFAULT_MAX_OFFER):
        self.mac_keys = list(mac_keys)
        self.listed_offer_keys = set(listed_offer_keys)
        self.cache = cache if cache is not None else {}
        self.max_offer = max_offer


def gate_check_offer(state, *, now, action_scope, route_scope=None, offer_raw=None, offer_id=None,
                     pay_scheme=None, attest_schemes=()):
    """4.4 gate checks 1 to 6 in order. Return the Offer or raise BnapError."""
    if offer_raw is None:
        offer_raw = state.cache.get(offer_id)
        if offer_raw is None:
            raise BnapError("BAD_OFFER", "unknown-offer-id")
    if len(offer_raw) > state.max_offer:
        raise BnapError("TOO_LARGE", "offer-size")
    o = parse_offer(offer_raw, state.max_offer)
    if o.mac is not None:
        if not verify_mac(o, state.mac_keys):
            raise BnapError("BAD_OFFER", "mac")
    else:
        if o.issued_at is None:
            raise BnapError("BAD_OFFER", "advance-offer-without-issued-at")
        if o.offer_key not in state.listed_offer_keys:
            raise BnapError("BAD_OFFER", "advance-offer-key-not-held")
        if not verify_offer_sig(o):
            raise BnapError("BAD_OFFER", "offer-sig")
    if now > o.expires + SKEW:
        raise BnapError("STALE", "expired")
    if pay_scheme is not None:
        e = o.pay_entry(pay_scheme)
        if e is not None and e.quote_expires is not None and now > e.quote_expires + SKEW:
            raise BnapError("STALE", "quote-expired")
    if o.issued_at is not None and o.issued_at > now + SKEW:
        raise BnapError("STALE", "issued-in-future")
    want = route_scope if o.route_scope else action_scope
    if want is None or want != o.scope:
        raise BnapError("WRONG_SCOPE", "scope-mismatch")
    if pay_scheme is not None and o.pay_entry(pay_scheme) is None:
        raise BnapError("NOT_OFFERED", "pay-scheme", pay_scheme)
    for s in attest_schemes:
        if o.attest_entry(s) is None:
            raise BnapError("NOT_OFFERED", "attest-scheme", s)
    return o
