"""Strict codecs for the draft-00 conventions (section 2) and errors (8.2).

Everything here rejects what draft-00 calls MALFORMED: non-minimal BigSize
and tu64, TLV records out of order or duplicated, truncated values, unknown
even types, and type ranges a stream may not use. Constant time is not a
goal; this is a test tool.
"""
import base64
import hashlib
import re

from ._ref import ref

# ---------------------------------------------------------------- errors

# Section 8.2: code, HTTP status, whether a fresh offer comes with the 402,
# whether retry_after is part of the error.
ERRORS = {
    "VERSION": (1, 400),
    "MALFORMED": (2, 400),
    "TOO_LARGE": (3, 413),
    "BAD_OFFER": (4, 402),
    "STALE": (5, 402),
    "WRONG_SCOPE": (6, 402),
    "NOT_OFFERED": (7, 402),
    "POLICY": (8, 403),
    "UNDERPAID": (9, 402),
    "BAD_CREDENTIAL": (10, 402),
    "BINDING": (11, 400),
    "SPENT": (12, 409),
    "PENDING": (13, 409),
    "RATE_LIMITED": (14, 429),
    "UNAVAILABLE": (15, 503),
    "REQUIRED": (16, 402),
}
CODE_NAMES = {v[0]: k for k, v in ERRORS.items()}
FRESH_OFFER = frozenset({"BAD_OFFER", "STALE", "WRONG_SCOPE", "REQUIRED"})
NEEDS_RETRY_AFTER = frozenset({"PENDING", "RATE_LIMITED"})


def code_of(name):
    return ERRORS[name][0]


def http_status_of(name):
    return ERRORS[name][1]


class BnapError(Exception):
    """A rejection with a section 8.2 code name and a short reason label."""

    def __init__(self, code, reason, detail=""):
        if code not in ERRORS:
            raise ValueError("unknown error code name " + repr(code))
        self.code = code
        self.reason = reason
        self.detail = detail
        super().__init__(f"{code}: {reason}" + (f" ({detail})" if detail else ""))


def malformed(reason, detail=""):
    return BnapError("MALFORMED", reason, detail)

# ---------------------------------------------------------------- hashing


H = ref.H
tagged = ref.tagged


def hmac_sha256(key, msg):
    import hmac as _hmac
    return _hmac.new(key, msg, hashlib.sha256).digest()

# ---------------------------------------------------------------- integers

U64_MAX = (1 << 64) - 1


def bigsize(n):
    if not 0 <= n <= U64_MAX:
        raise ValueError("BigSize out of range")
    return ref.bigsize(n)


def read_bigsize(buf, i):
    """Decode one BigSize at buf[i]; return (value, next index)."""
    if i >= len(buf):
        raise malformed("truncated-bigsize")
    f = buf[i]
    if f < 0xFD:
        return f, i + 1
    w = {0xFD: 2, 0xFE: 4, 0xFF: 8}[f]
    if i + 1 + w > len(buf):
        raise malformed("truncated-bigsize")
    v = int.from_bytes(buf[i + 1:i + 1 + w], "big")
    if v < {2: 0xFD, 4: 0x10000, 8: 0x100000000}[w]:
        raise malformed("non-minimal-bigsize")
    return v, i + 1 + w


def decode_bigsize(buf):
    """Decode a buffer that holds exactly one BigSize."""
    v, j = read_bigsize(buf, 0)
    if j != len(buf):
        raise malformed("trailing-bytes")
    return v


def tu64(n):
    if not 0 <= n <= U64_MAX:
        raise ValueError("tu64 out of range")
    return ref.tu64(n)


def parse_tu64(b):
    if len(b) > 8:
        raise malformed("tu64-too-long")
    if b[:1] == b"\x00":
        raise malformed("non-minimal-tu64")
    return int.from_bytes(b, "big") if b else 0


def lp(b):
    return bigsize(len(b)) + b

# ---------------------------------------------------------------- TLV

SIG_RANGE = (240, 1000)
EXPERIMENTAL = (1_000_000_000, 1_999_999_999)
GREASE = (3_000_000_001, 3_000_000_999)


def is_sig_range(t):
    return SIG_RANGE[0] <= t <= SIG_RANGE[1]


def is_grease(t):
    return GREASE[0] <= t <= GREASE[1] and t % 2 == 1


def is_experimental(t):
    return EXPERIMENTAL[0] <= t <= EXPERIMENTAL[1]


def type_range(t):
    """Name the section 2 range of a top-level type."""
    if t <= 239:
        return "socket"
    if is_sig_range(t):
        return "signature"
    if 1001 <= t <= 999_999_999:
        return "future"
    if is_experimental(t):
        return "experimental"
    if is_grease(t):
        return "grease"
    return "reserved"


def nested_type_allowed(t):
    """Nested streams use only 0-239, the experimental range and GREASE."""
    return t <= 239 or is_experimental(t) or is_grease(t)


class Record:
    __slots__ = ("type", "value", "raw")

    def __init__(self, t, value, raw):
        self.type = t
        self.value = value
        self.raw = raw

    def __repr__(self):
        return f"Record({self.type}, {self.value.hex()})"


def tlv(records):
    """Build a stream from (type, value) pairs; types must strictly increase."""
    out, last = [], -1
    for t, v in records:
        if t <= last:
            raise ValueError("TLV types must be strictly increasing")
        last = t
        out.append(bigsize(t) + bigsize(len(v)) + bytes(v))
    return b"".join(out)


def tlv_unsorted(records):
    """Build a stream in the given order, for negative tests only."""
    return b"".join(bigsize(t) + bigsize(len(v)) + bytes(v) for t, v in records)


def parse_stream(buf):
    """Parse a TLV stream strictly; return a list of Record."""
    i, last, out = 0, -1, []
    while i < len(buf):
        start = i
        t, i = read_bigsize(buf, i)
        n, i = read_bigsize(buf, i)
        if t == last:
            raise malformed("duplicate-type", str(t))
        if t < last:
            raise malformed("type-order", f"{t} after {last}")
        if i + n > len(buf):
            raise malformed("truncated-value", str(t))
        out.append(Record(t, buf[i:i + n], buf[start:i + n]))
        last, i = t, i + n
    return out


def check_known(records, known, nested=False):
    """Apply the even/odd rule. Return the list of ignored (unknown odd) types.

    known: set of types this receiver understands. In a nested stream a type
    outside 0-239, the experimental range and GREASE is MALFORMED whatever
    its parity.
    """
    ignored = []
    for r in records:
        if r.type in known:
            continue
        if nested and not nested_type_allowed(r.type):
            raise malformed("nested-type-range", str(r.type))
        if r.type % 2 == 0:
            raise malformed("unknown-even-type", str(r.type))
        ignored.append(r.type)
    return ignored


def as_dict(records):
    return {r.type: r.value for r in records}


def entry_list(streams):
    return b"".join(lp(s) for s in streams)


def parse_entry_list(buf):
    i, out = 0, []
    while i < len(buf):
        n, i = read_bigsize(buf, i)
        if i + n > len(buf):
            raise malformed("truncated-entry")
        out.append(buf[i:i + n])
        i += n
    return out


def signed_bytes(records, exclude=()):
    """Concatenate every record outside the signature range, in stream order."""
    return b"".join(r.raw for r in records if not is_sig_range(r.type) and r.type not in exclude)


def utf8(b, what):
    try:
        return b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise malformed("bad-utf8", what) from None


def fixed(b, n, what):
    if len(b) != n:
        raise malformed("bad-length", f"{what} must be {n} bytes, is {len(b)}")
    return b


def flag(b, what):
    if b:
        raise malformed("flag-with-value", what)
    return True

# ---------------------------------------------------------------- base64url

_B64U = re.compile(r"\A[A-Za-z0-9_-]*\Z")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    """Strict RFC 4648 section 5, no padding, canonical trailing bits."""
    if isinstance(s, bytes):
        try:
            s = s.decode("ascii")
        except UnicodeDecodeError:
            raise malformed("bad-base64url") from None
    if not _B64U.match(s) or len(s) % 4 == 1:
        raise malformed("bad-base64url")
    out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(out) != s:
        raise malformed("non-canonical-base64url")
    return out

# ---------------------------------------------------------------- Error TLV (8.2)


def build_error(code, scheme_code=None, detail=None, retry_after=None):
    recs = [(0, tu64(1)), (2, tu64(code_of(code) if isinstance(code, str) else code))]
    if scheme_code is not None:
        recs.append((4, scheme_code.encode()))
    if detail is not None:
        d = detail.encode()[:256]
        recs.append((6, d))
    if retry_after is not None:
        recs.append((8, tu64(retry_after)))
    return tlv(recs)


class ErrorObject:
    def __init__(self, version, code, scheme_code, detail, retry_after, ignored):
        self.version = version
        self.code = code
        self.scheme_code = scheme_code
        self.detail = detail
        self.retry_after = retry_after
        self.ignored = ignored

    @property
    def name(self):
        return CODE_NAMES.get(self.code, f"code-{self.code}")


def parse_error(raw):
    recs = parse_stream(raw)
    d = as_dict(recs)
    if 0 not in d:
        raise malformed("missing-record", "version")
    version = parse_tu64(d[0])
    if version != 1:
        raise BnapError("VERSION", "unsupported-version", str(version))
    ignored = check_known(recs, {0, 2, 4, 6, 8})
    if 2 not in d:
        raise malformed("missing-record", "code")
    code = parse_tu64(d[2])
    sc = utf8(d[4], "scheme_code") if 4 in d else None
    detail = None
    if 6 in d:
        if len(d[6]) > 256:
            raise malformed("detail-too-long")
        detail = utf8(d[6], "detail")
    ra = parse_tu64(d[8]) if 8 in d else None
    return ErrorObject(version, code, sc, detail, ra, ignored)
