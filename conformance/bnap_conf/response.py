"""The Response and its ack (draft-00 section 8.1), and the client's receipt rules (9.3)."""
from . import codec
from .codec import BnapError, malformed, parse_tu64, fixed, flag, tagged, utf8
from .crypto import schnorr_sign, schnorr_verify
from .offer import SKEW, key_listed

DEFAULT_MAX_RESPONSE = 8192
RESP_TYPES = frozenset({0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 240})
ACK = 240
OK, FAILED = 0, 1


class Response:
    def __init__(self, raw, records):
        self.raw = raw
        self.records = records
        self.ignored = []
        self.version = None
        self.status = None
        self.replayed = False
        self.charged = None
        self.unit = None
        self.offer_id = None
        self.digest = None
        self.metered_units = None
        self.scheme_result = None
        self.receipt_key = None
        self.settled_at = None
        self.ack = None
        self.signed = codec.signed_bytes(records)

    @property
    def status_name(self):
        return {OK: "OK", FAILED: "FAILED"}.get(self.status, str(self.status))


def parse_response(raw, max_size=DEFAULT_MAX_RESPONSE):
    raw = bytes(raw)
    if len(raw) > max_size:
        raise BnapError("TOO_LARGE", "response-size", f"{len(raw)} > {max_size}")
    recs = codec.parse_stream(raw)
    d = codec.as_dict(recs)
    if 0 not in d:
        raise malformed("missing-record", "version")
    v = parse_tu64(d[0])
    if v != 1:
        raise BnapError("VERSION", "unsupported-version", str(v))
    r = Response(raw, recs)
    r.version = v
    r.ignored = codec.check_known(recs, RESP_TYPES)
    for t, name in ((2, "status"), (6, "charged"), (10, "offer_id"), (12, "digest"),
                    (18, "receipt_key"), (20, "settled_at"), (ACK, "ack")):
        if t not in d:
            raise malformed("missing-record", name)
    r.status = parse_tu64(d[2])
    if r.status not in (OK, FAILED):
        raise malformed("status-out-of-range", str(r.status))
    r.replayed = flag(d[4], "replayed") if 4 in d else False
    r.charged = parse_tu64(d[6])
    r.unit = utf8(d[8], "unit") if 8 in d else None
    r.offer_id = fixed(d[10], 32, "offer_id")
    r.digest = fixed(d[12], 32, "digest")
    r.metered_units = parse_tu64(d[14]) if 14 in d else None
    r.scheme_result = d.get(16)
    r.receipt_key = fixed(d[18], 32, "receipt_key")
    r.settled_at = parse_tu64(d[20])
    r.ack = fixed(d[ACK], 64, "ack")
    return r


def verify_ack(r):
    return schnorr_verify(r.receipt_key, tagged("bnap/ack", r.signed), r.ack)


def build_response(*, status, charged, offer_id, digest, receipt_sk, settled_at, unit=None,
                   replayed=False, metered_units=None, scheme_result=None, extra=(), ack_override=None,
                   receipt_key=None):
    from .crypto import schnorr_pub
    recs = [(0, codec.tu64(1)), (2, codec.tu64(status)), (6, codec.tu64(charged)),
            (10, offer_id), (12, digest),
            (18, receipt_key if receipt_key is not None else schnorr_pub(receipt_sk)),
            (20, codec.tu64(settled_at))]
    if replayed:
        recs.append((4, b""))
    if unit is not None:
        recs.append((8, unit.encode()))
    if metered_units is not None:
        recs.append((14, codec.tu64(metered_units)))
    if scheme_result is not None:
        recs.append((16, scheme_result))
    recs.extend(extra)
    recs.sort()
    body = b"".join(codec.bigsize(t) + codec.bigsize(len(v)) + v for t, v in recs if not codec.is_sig_range(t))
    ack = ack_override if ack_override is not None else schnorr_sign(receipt_sk, tagged("bnap/ack", body))
    return codec.tlv(sorted(recs + [(ACK, ack)]))


class ReceiptCheck:
    def __init__(self, ok, reason=None, response=None):
        self.ok = ok
        self.reason = reason
        self.response = response

    def __repr__(self):
        return f"ReceiptCheck(ok={self.ok}, reason={self.reason})"


def client_check_receipt(raw, *, now, pin_keys, digest=None, offer_id=None, has_pay=None,
                         metered=None, expected_charge=None, max_size=DEFAULT_MAX_RESPONSE):
    """9.3 "on a receipt" plus 8.1 presence rules and the request binding.

    pin_keys None skips the key check (no pin). digest and offer_id, when
    given, must match the request the client sent. has_pay and metered
    enable the conditional presence rules of 8.1. expected_charge, when
    given, is what the client computed from the offer (7).
    """
    try:
        r = parse_response(raw, max_size)
    except BnapError as e:
        return ReceiptCheck(False, f"{e.code}:{e.reason}")
    if not verify_ack(r):
        return ReceiptCheck(False, "ack", r)
    if pin_keys is not None and not key_listed(pin_keys, r.receipt_key, "receipt", r.settled_at):
        return ReceiptCheck(False, "receipt-key-not-pinned", r)
    if not r.replayed and abs(now - r.settled_at) > SKEW:
        return ReceiptCheck(False, "settled-at-skew", r)
    if digest is not None and r.digest != digest:
        return ReceiptCheck(False, "digest-mismatch", r)
    if offer_id is not None and r.offer_id != offer_id:
        return ReceiptCheck(False, "offer-id-mismatch", r)
    if has_pay and r.unit is None:
        return ReceiptCheck(False, "unit-missing", r)
    if metered and r.metered_units is None:
        return ReceiptCheck(False, "metered-units-missing", r)
    if expected_charge is not None and r.charged != expected_charge:
        return ReceiptCheck(False, "charge-mismatch", r)
    return ReceiptCheck(True, response=r)
