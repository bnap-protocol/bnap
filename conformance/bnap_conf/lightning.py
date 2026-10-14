"""Lightning-side artifacts the runner reads: BOLT 11 invoices, L402 macaroons
and the MPP Lightning challenge, plus the OfferID embeddings the registry
names for each native kind:

  bolt11         the invoice description hash (tag h) is the OfferID
  l402-macaroon  a first-party caveat bnap_offer=<hex OfferID>
  mpp-challenge  the challenge's HMAC'd id carries the OfferID

The MPP shapes here are the suite's profile "bnap-conf-mpp-1" (see
notes/n11-conformance.md): native entry data is the challenge as canonical
JSON; the credential is b64u(JSON {"challenge", "payload": {"preimage"}});
the id is b64u(OfferID || 16-byte tag). Real payers verify invoice
signatures; this module does not.
"""
import base64
import hashlib
import hmac
import json

from .codec import b64u, b64u_decode

# ---------------------------------------------------------------- bech32

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= _GEN[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_encode(hrp, data):
    values = _hrp_expand(hrp) + data
    pm = _polymod(values + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def bech32_decode(s):
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("bad separator")
    hrp, data = s[:pos], []
    for c in s[pos + 1:]:
        if c not in _CHARSET:
            raise ValueError("bad character")
        data.append(_CHARSET.index(c))
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad checksum")
    return hrp, data[:-6]


def convertbits(data, frombits, tobits, pad=True):
    acc, bits, out = 0, 0, []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("non-zero padding")
    return out

# ---------------------------------------------------------------- BOLT 11


class Invoice:
    def __init__(self, hrp, amount_msat, timestamp, tags):
        self.hrp = hrp
        self.amount_msat = amount_msat
        self.timestamp = timestamp
        self.tags = tags

    @property
    def payment_hash(self):
        return self.tags.get("p")

    @property
    def description_hash(self):
        return self.tags.get("h")

    @property
    def amount_sat(self):
        return None if self.amount_msat is None else self.amount_msat // 1000


_TAGS = {1: "p", 23: "h", 13: "d", 6: "x", 16: "s", 19: "n"}
_TAG_CODES = {v: k for k, v in _TAGS.items()}
_MULT = {"m": 10 ** 8, "u": 10 ** 5, "n": 10 ** 2}  # msat per unit; "p" handled apart


def _amount_msat(s):
    if not s:
        return None
    if s[-1] == "p":
        n = int(s[:-1])
        if n % 10:
            raise ValueError("sub-msat amount")
        return n // 10
    if s[-1] in _MULT:
        return int(s[:-1]) * _MULT[s[-1]]
    return int(s) * 10 ** 11


def decode_bolt11(s):
    hrp, data = bech32_decode(s.strip())
    if not hrp.startswith("ln"):
        raise ValueError("not a Lightning invoice")
    rest = hrp[2:]
    for net in ("bcrt", "bc", "tbs", "tb", "sb"):
        if rest.startswith(net):
            amt = rest[len(net):]
            break
    else:
        raise ValueError("unknown network prefix")
    if len(data) < 7 + 104:
        raise ValueError("invoice too short")
    ts = 0
    for w in data[:7]:
        ts = ts << 5 | w
    body = data[7:-104]
    tags, i = {}, 0
    while i + 3 <= len(body):
        t, ln = body[i], body[i + 1] << 5 | body[i + 2]
        words = body[i + 3:i + 3 + ln]
        i += 3 + ln
        name = _TAGS.get(t)
        if name in ("p", "h", "s", "n") and name not in tags:
            raw = bytes(convertbits(words, 5, 8, pad=False)) if ln == 52 or name == "n" else None
            if raw is not None:
                tags[name] = raw
        elif name == "x":
            v = 0
            for w in words:
                v = v << 5 | w
            tags["x"] = v
        elif name == "d":
            tags["d"] = bytes(convertbits(words, 5, 8, pad=False)).decode("utf-8", "replace")
    return Invoice(hrp, _amount_msat(amt), ts, tags)


def encode_bolt11(*, payment_hash, description_hash, amount_sat, timestamp, network="bcrt",
                  expiry=3600, payment_secret=None):
    """A structurally valid invoice with an all-zero node signature (test only)."""
    msat = amount_sat * 1000
    amt = f"{msat // 100}n" if msat % 100 == 0 else f"{msat * 10}p"
    hrp = "ln" + network + amt
    data = [(timestamp >> (5 * (6 - i))) & 31 for i in range(7)]

    def field(name, words):
        return [_TAG_CODES[name], len(words) >> 5, len(words) & 31] + words

    data += field("p", convertbits(payment_hash, 8, 5))
    data += field("h", convertbits(description_hash, 8, 5))
    if payment_secret is not None:
        data += field("s", convertbits(payment_secret, 8, 5))
    xw = []
    v = expiry
    while v:
        xw.insert(0, v & 31)
        v >>= 5
    data += field("x", xw or [0])
    data += convertbits(bytes(65), 8, 5)
    return bech32_encode(hrp, data)

# ---------------------------------------------------------------- macaroons (libmacaroons v2)


def _uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_uvarint(b, i):
    shift, v = 0, 0
    while True:
        if i >= len(b):
            raise ValueError("truncated varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


class Macaroon:
    def __init__(self, location, identifier, caveats, signature):
        self.location = location
        self.identifier = identifier
        self.caveats = caveats
        self.signature = signature

    @property
    def payment_hash(self):
        """L402 identifier: version (2 bytes, 0) || payment hash (32) || token ID (32)."""
        if len(self.identifier) >= 34 and self.identifier[:2] == b"\x00\x00":
            return self.identifier[2:34]
        return None

    def caveat_value(self, key):
        for c in self.caveats:
            k, sep, v = c.decode("utf-8", "replace").partition("=")
            if sep and k.strip() == key:
                return v.strip()
        return None


def _mac_key(root_key):
    return hmac.new(b"macaroons-key-generator", root_key, hashlib.sha256).digest()


def mint_macaroon(root_key, identifier, caveats, location=b""):
    sig = hmac.new(_mac_key(root_key), identifier, hashlib.sha256).digest()
    for c in caveats:
        sig = hmac.new(sig, c, hashlib.sha256).digest()
    out = bytearray(b"\x02")
    if location:
        out += b"\x01" + _uvarint(len(location)) + location
    out += b"\x02" + _uvarint(len(identifier)) + identifier + b"\x00"
    for c in caveats:
        out += b"\x02" + _uvarint(len(c)) + c + b"\x00"
    out += b"\x00" + b"\x06" + _uvarint(32) + sig
    return bytes(out)


def parse_macaroon(b):
    if not b or b[0] != 2:
        raise ValueError("not a v2 macaroon")
    i = 1

    def field(i):
        t = b[i]
        if t == 0:
            return 0, None, i + 1
        n, j = _read_uvarint(b, i + 1)
        if j + n > len(b):
            raise ValueError("truncated field")
        return t, b[j:j + n], j + n

    location = b""
    t, v, i = field(i)
    if t == 1:
        location = v
        t, v, i = field(i)
    if t != 2:
        raise ValueError("missing identifier")
    identifier = v
    t, v, i = field(i)
    if t != 0:
        raise ValueError("missing end of header")
    caveats = []
    while True:
        t, v, i = field(i)
        if t == 0:
            break
        if t == 1:
            t, v, i = field(i)
        if t != 2:
            raise ValueError("bad caveat")
        caveats.append(v)
        while True:
            t, v2, i = field(i)
            if t == 0:
                break
    t, sig, i = field(i)
    if t != 6 or len(sig) != 32:
        raise ValueError("bad signature field")
    return Macaroon(location, identifier, caveats, sig)


def verify_macaroon(root_key, m):
    sig = hmac.new(_mac_key(root_key), m.identifier, hashlib.sha256).digest()
    for c in m.caveats:
        sig = hmac.new(sig, c, hashlib.sha256).digest()
    return hmac.compare_digest(sig, m.signature)


def l402_token(macaroon, preimage):
    return base64.b64encode(macaroon).decode() + ":" + preimage.hex()


def parse_l402_token(token):
    mac_b64, sep, pre_hex = token.partition(":")
    if not sep:
        raise ValueError("no preimage")
    mac = base64.b64decode(mac_b64, validate=True)
    pre = bytes.fromhex(pre_hex)
    if len(pre) != 32:
        raise ValueError("preimage length")
    return mac, pre

# ---------------------------------------------------------------- MPP profile


def mpp_id(offer_id, tag16):
    return b64u(offer_id + tag16)


def mpp_offer_id(id_str):
    try:
        b = b64u_decode(id_str)
    except Exception:
        return None
    return b[:32] if len(b) >= 32 else None


def mpp_challenge_json(params):
    return json.dumps(params, separators=(",", ":"), sort_keys=True).encode()


def mpp_request_invoice(params):
    try:
        req = json.loads(b64u_decode(params["request"]))
        return req.get("invoice")
    except Exception:
        return None


def mpp_credential(params, preimage):
    return b64u(json.dumps({"challenge": params, "payload": {"preimage": preimage.hex()}},
                           separators=(",", ":"), sort_keys=True).encode())


def parse_mpp_credential(token68):
    obj = json.loads(b64u_decode(token68))
    return obj["challenge"], bytes.fromhex(obj["payload"]["preimage"])
