"""The Credential (draft-00 section 5) and the identifiers of section 6.1.

parse_credential() applies the 5.1 MALFORMED rules. The envelope functions
compute Context, Digest and ReplayKey exactly as 5.2 and 6.1 write them,
taking the attestations in the credential's (sorted) order.
"""
from . import codec
from .codec import BnapError, malformed, parse_tu64, fixed, lp, tagged, H

DEFAULT_MAX_CREDENTIAL = 16384
HTTP_MAX_CREDENTIAL = 9216  # DECISIONS row 30: the HTTP carrier cap

CRED_TYPES = frozenset({0, 2, 4, 6, 8, 10, 12})
ITEM_TYPES = frozenset({0, 2, 4})


class SchemeItem:
    """A pay item or one attest item: scheme, body, witness."""

    def __init__(self, scheme, body, witness, ignored=()):
        self.scheme = scheme
        self.body = body
        self.witness = witness
        self.ignored = list(ignored)

    def encode(self):
        recs = [(0, self.scheme.encode())]
        if self.body is not None:
            recs.append((2, self.body))
        if self.witness is not None:
            recs.append((4, self.witness))
        return codec.tlv(recs)


class Credential:
    def __init__(self, raw, records):
        self.raw = raw
        self.records = records
        self.ignored = []
        self.version = None
        self.offer = None
        self.offer_id_ref = None
        self.pay = None
        self.attest = []
        self.binding = None
        self.ext = None

    @property
    def attest_schemes(self):
        return [a.scheme for a in self.attest]

    @property
    def pay_body(self):
        return self.pay.body if self.pay and self.pay.body is not None else b""

    @property
    def attest_bodies(self):
        return [a.body if a.body is not None else b"" for a in self.attest]


def _item(raw):
    recs = codec.parse_stream(raw)
    ignored = codec.check_known(recs, ITEM_TYPES, nested=True)
    d = codec.as_dict(recs)
    if 0 not in d:
        raise malformed("missing-record", "scheme")
    s = codec.utf8(d[0], "scheme")
    if not s:
        raise malformed("empty-scheme-id")
    return SchemeItem(s, d.get(2), d.get(4), ignored)


def parse_credential(raw, max_size=DEFAULT_MAX_CREDENTIAL, registry=None):
    """Parse and apply 5.1. With a registry, also the binding-class rule."""
    raw = bytes(raw)
    if len(raw) > max_size:
        raise BnapError("TOO_LARGE", "credential-size", f"{len(raw)} > {max_size}")
    recs = codec.parse_stream(raw)
    d = codec.as_dict(recs)
    if 0 not in d:
        raise malformed("missing-record", "version")
    version = parse_tu64(d[0])
    if version != 1:
        raise BnapError("VERSION", "unsupported-version", str(version))
    c = Credential(raw, recs)
    c.version = version
    c.ignored = codec.check_known(recs, CRED_TYPES)
    has_offer, has_id = 2 in d, 12 in d
    if has_offer == has_id:
        raise malformed("offer-xor-offer-id", "both" if has_offer else "neither")
    c.offer = d.get(2)
    if has_id:
        c.offer_id_ref = fixed(d[12], 32, "offer_id")
    if 4 in d:
        c.pay = _item(d[4])
    if 6 in d:
        c.attest = [_item(e) for e in codec.parse_entry_list(d[6])]
        names = [a.scheme.encode() for a in c.attest]
        for a, b in zip(names, names[1:]):
            if a == b:
                raise malformed("attest-duplicate", a.decode())
            if a > b:
                raise malformed("attest-order")
    if c.pay is None and not c.attest:
        raise malformed("no-pay-no-attest")
    if 8 in d:
        c.binding = fixed(d[8], 32, "binding")
    if 10 in d:
        c.ext = d[10]
        codec.check_known(codec.parse_stream(c.ext), set(), nested=True)
    if registry is not None and c.binding is not None:
        chosen = ([c.pay.scheme] if c.pay else []) + c.attest_schemes
        if not any(registry.binding(s) == "S" for s in chosen):
            raise malformed("binding-without-class-s")
    return c


def build_credential(*, offer=None, offer_id=None, pay=None, attest=(), binding=None, ext=None,
                     extra=(), version=1):
    recs = [(0, codec.tu64(version))]
    if offer is not None:
        recs.append((2, offer))
    if pay is not None:
        recs.append((4, pay.encode() if isinstance(pay, SchemeItem) else pay))
    if attest:
        items = list(attest)
        if all(isinstance(a, SchemeItem) for a in items):
            items = [a.encode() for a in sorted(items, key=lambda a: a.scheme.encode())]
        recs.append((6, codec.entry_list(items)))
    if binding is not None:
        recs.append((8, binding))
    if ext is not None:
        recs.append((10, ext))
    if offer_id is not None:
        recs.append((12, offer_id))
    recs.extend(extra)
    return codec.tlv(sorted(recs))

# ---------------------------------------------------------------- envelope (5.2, 6.1)


def context(offer_id, action_scope, pay_scheme, attest_schemes, ext):
    """attest_schemes in the credential's order; pay_scheme None or "" for none."""
    p = (pay_scheme or "").encode()
    a = [s.encode() for s in attest_schemes]
    return tagged("bnap/ctx", offer_id + action_scope + lp(p) + codec.bigsize(len(a))
                  + b"".join(lp(x) for x in a) + H(ext or b""))


def digest(ctx, binding, pay_body, attest_bodies):
    return tagged("bnap/cred", ctx + lp(binding or b"") + H(pay_body or b"")
                  + b"".join(H(b) for b in attest_bodies))


def use_id(scheme, local):
    return tagged("bnap/use", lp(scheme.encode()) + local)


def rail_id(kind, canonical):
    return tagged("bnap/rail", lp(kind.encode()) + canonical)


def replay_key(ctx, pay_body, attest_bodies, ids):
    s = sorted(ids)
    return tagged("bnap/replay", ctx + H(pay_body or b"") + b"".join(H(b) for b in attest_bodies)
                  + codec.bigsize(len(s)) + b"".join(s))


def native_context(offer_id, action_scope, scheme):
    return tagged("bnap/ctx-native", offer_id + action_scope + lp(scheme.encode()))


def native_digest(ctx, native_bytes):
    return tagged("bnap/cred-native", ctx + H(native_bytes))


def credential_envelope(c, offer_id, action_scope):
    """Return (Context, Digest) for a parsed credential."""
    ctx = context(offer_id, action_scope, c.pay.scheme if c.pay else None, c.attest_schemes, c.ext)
    return ctx, digest(ctx, c.binding, c.pay_body, c.attest_bodies)


# Canonical payment bytes per rail kind (6.1).
def canonical_ln(payment_hash):
    return fixed(payment_hash, 32, "payment hash")


def canonical_onchain(txid, vout):
    return fixed(txid, 32, "txid") + vout.to_bytes(4, "big")


def canonical_evm(chain_id, token, payer, nonce):
    return lp(chain_id.encode()) + fixed(token, 20, "token") + fixed(payer, 20, "payer") + fixed(nonce, 32, "nonce")


def canonical_card(processor, payment_id):
    return lp(processor.encode()) + lp(payment_id.encode())


def rate_key(uid, k, epoch, now):
    return tagged("bnap/rate", uid + codec.tu64(k) + codec.tu64(epoch) + codec.tu64(now // epoch))


def quota_key(uid, value, epoch, now):
    return tagged("bnap/quota", uid + codec.tu64(value) + codec.tu64(epoch) + codec.tu64(now // epoch))
