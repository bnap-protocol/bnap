"""Lightning-side artifacts the runner reads: BOLT 11 invoices, L402 macaroons
and the MPP Lightning challenge, plus the OfferID embeddings the registry
names for each native kind:

  bolt11         the invoice description hash (tag h) is the OfferID
  l402-macaroon  a first-party caveat bnap_offer=<hex OfferID>
  mpp-challenge  the challenge's HMAC'd id carries the OfferID

Native entry data is the artifact's bytes (draft-00 4.1), one entry per
registered kind: an L402 pay entry has an l402-macaroon entry (the binary V2
macaroon) and a bolt11 entry (the invoice string); a payment:lightning/charge
entry has an mpp-challenge entry, the Payment challenge exactly as the gate
sends it in WWW-Authenticate (draft-httpauth-payment-01 auth-params).

The MPP shapes are the suite's profile "bnap-conf-mpp-2" (see
notes/e2e-conformance.md): the challenge's opaque parameter is
b64u(JCS {"bnap_offer": hex(OfferID)}), which the HMAC'd id covers; the
request is b64u(JSON) with the invoice at methodDetails.invoice (the
lightning charge method) or at invoice; the credential is
b64u(JCS {"challenge": the challenge's parameters, "payload": {"preimage"}}).

decode_bolt11 is strict, because run.py caps its spending against this
decode while the payer parses the invoice on its own: any reading the two
could disagree on is refused. See decode_bolt11 for the rules.
"""
import base64
import hashlib
import hmac
import json
import re

from .codec import b64u, b64u_decode
from .crypto import k1_pub, k1_recover, k1_sign_recoverable, key_from_label

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
    def __init__(self, hrp, network, amount_msat, timestamp, tags, payee):
        self.hrp = hrp
        self.network = network
        self.amount_msat = amount_msat
        self.timestamp = timestamp
        self.tags = tags
        self.payee = payee

    @property
    def payment_hash(self):
        return self.tags.get("p")

    @property
    def description_hash(self):
        return self.tags.get("h")

    @property
    def features(self):
        """The feature bits of the 9 field, as an integer (bit i is 1 << i); 0 without one."""
        return self.tags.get("9", 0)

    @property
    def amp(self):
        """True when the invoice sets AMP (feature bits 30 or 31): one invoice, many payments."""
        return bool(self.features >> 30 & 3)

    @property
    def amount_sat(self):
        """The amount in whole satoshis, or None when the invoice has no amount or a fraction of one."""
        if self.amount_msat is None or self.amount_msat % 1000:
            return None
        return self.amount_msat // 1000


# The network part of the human-readable prefix, by the BOLT 11 and SLIP-0173 registry.
NETWORKS = {"bc": "bitcoin", "tb": "testnet", "tbs": "signet", "bcrt": "regtest", "sb": "simnet"}
MAX_MSAT = 21_000_000 * 10 ** 11  # every bitcoin there will be, in millisatoshi
_HRP = re.compile(r"ln(bcrt|bc|tbs|tb|sb)(?:([1-9][0-9]*)([munp]?))?", re.ASCII)
_MULT = {"": 10 ** 11, "m": 10 ** 8, "u": 10 ** 5, "n": 10 ** 2}  # msat per unit; "p" is a tenth of one
_TAGS = {1: "p", 23: "h", 13: "d", 6: "x", 16: "s", 19: "n", 24: "c", 5: "9"}
_TAG_CODES = {v: k for k, v in _TAGS.items()}
_FIXED_WORDS = {"p": 52, "h": 52, "s": 52, "n": 53}
DEFAULT_NODE_KEY = key_from_label("bnap conformance lightning node key")


def _amount_msat(digits, mult):
    if digits is None:
        return None
    n = int(digits)
    if mult == "p":
        if n % 10:
            raise ValueError("a p amount must end in 0: it would be a fraction of a millisatoshi")
        msat = n // 10
    else:
        msat = n * _MULT[mult]
    if msat > MAX_MSAT:
        raise ValueError(f"amount of {msat} msat is more than there will ever be")
    return msat


def _int_of(words):
    v = 0
    for w in words:
        v = v << 5 | w
    return v


def _signing_hash(hrp, data):
    return hashlib.sha256(hrp.encode() + bytes(convertbits(data, 5, 8))).digest()


def decode_bolt11(s):
    """Decode a BOLT 11 invoice strictly, or raise ValueError. The rules, beyond bech32:

    - the string is printable ASCII in one case, with no surrounding whitespace;
    - the prefix is exactly ln + one of the NETWORKS + an optional amount: a decimal with no
      leading zero and an optional multiplier m, u, n or p, where p needs a last digit 0 and the
      total may not exceed 21 million bitcoin;
    - tagged fields fill the data part exactly up to the 65-byte signature, with no partial field
      and no trailing words;
    - exactly one p field, at most one each of h, d, s, n, x, c and 9 (features, kept as an integer); p, h and s have 52 words and n
      53, with zero padding bits; exactly one of d (valid UTF-8) and h; unknown fields are skipped;
    - the signature has r and s in range and a recovery id 0 to 3, recovers a public key, and that
      key is the n field when there is one.
    """
    if not isinstance(s, str) or not s or any(not 33 <= ord(c) <= 126 for c in s):
        raise ValueError("an invoice is printable ASCII without whitespace")
    hrp, data = bech32_decode(s)
    m = _HRP.fullmatch(hrp)
    if m is None:
        raise ValueError(f"prefix {hrp!r} is not ln + a known network + a valid amount")
    net, digits, mult = m.group(1), m.group(2), m.group(3) or ""
    amount = _amount_msat(digits, mult)
    if len(data) < 7 + 104:
        raise ValueError("invoice too short")
    ts = _int_of(data[:7])
    body, sig_words = data[7:-104], data[-104:]
    tags, i, counts = {}, 0, {}
    while i < len(body):
        if i + 3 > len(body):
            raise ValueError("trailing words after the last tagged field")
        t, ln_ = body[i], body[i + 1] << 5 | body[i + 2]
        words = body[i + 3:i + 3 + ln_]
        if len(words) != ln_:
            raise ValueError("a tagged field runs past the signature")
        i += 3 + ln_
        name = _TAGS.get(t)
        if name is None:
            continue
        counts[name] = counts.get(name, 0) + 1
        if counts[name] > 1:
            raise ValueError(f"more than one {name} field")
        if name in _FIXED_WORDS:
            if ln_ != _FIXED_WORDS[name]:
                raise ValueError(f"{name} field of {ln_} words, not {_FIXED_WORDS[name]}")
            tags[name] = bytes(convertbits(words, 5, 8, pad=False))
        elif name in ("x", "c", "9"):
            tags[name] = _int_of(words)
        else:
            try:
                tags["d"] = bytes(convertbits(words, 5, 8, pad=False)).decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("d field is not UTF-8") from None
    if "p" not in tags:
        raise ValueError("no payment hash (p field)")
    if ("d" in tags) == ("h" in tags):
        raise ValueError("exactly one of d and h is required")
    sig = bytes(convertbits(sig_words, 5, 8, pad=False))
    payee = k1_recover(_signing_hash(hrp, data[:-104]), sig[:64], sig[64])
    if payee is None:
        raise ValueError("the signature recovers no public key")
    if "n" in tags and tags["n"] != payee:
        raise ValueError("the signature is not by the n field's key")
    return Invoice(hrp, NETWORKS[net], amount, ts, tags, payee)


def _amount_part(amount_msat):
    if amount_msat is None:
        return ""
    for mult in ("", "m", "u", "n"):
        if amount_msat % _MULT[mult] == 0:
            return f"{amount_msat // _MULT[mult]}{mult}"
    return f"{amount_msat * 10}p"


def sign_bolt11(hrp, data, node_sk=DEFAULT_NODE_KEY):
    """Append a recoverable signature by node_sk to the data words and bech32-encode (test helper)."""
    sig, recid = k1_sign_recoverable(node_sk, _signing_hash(hrp, data))
    return bech32_encode(hrp, data + convertbits(sig + bytes([recid]), 8, 5))


def bolt11_field(name, words):
    return [_TAG_CODES[name], len(words) >> 5, len(words) & 31] + words


def encode_bolt11(*, payment_hash, description_hash, amount_sat, timestamp, network="bcrt",
                  expiry=3600, payment_secret=None, node_sk=DEFAULT_NODE_KEY):
    """An invoice signed by node_sk (test only; the mock gate and the unit tests)."""
    hrp = "ln" + network + _amount_part(None if amount_sat is None else amount_sat * 1000)
    data = [(timestamp >> (5 * (6 - i))) & 31 for i in range(7)]
    data += bolt11_field("p", convertbits(payment_hash, 8, 5))
    data += bolt11_field("h", convertbits(description_hash, 8, 5))
    if payment_secret is not None:
        data += bolt11_field("s", convertbits(payment_secret, 8, 5))
    xw = []
    v = expiry
    while v:
        xw.insert(0, v & 31)
        v >>= 5
    data += bolt11_field("x", xw or [0])
    return sign_bolt11(hrp, data, node_sk)


def node_id(node_sk=DEFAULT_NODE_KEY):
    return k1_pub(node_sk)

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


def mpp_opaque(offer_id):
    """The opaque parameter that carries the OfferID."""
    return b64u(json.dumps({"bnap_offer": offer_id.hex()}, separators=(",", ":"), sort_keys=True).encode())


def mpp_offer_id(params):
    """The OfferID a challenge's opaque parameter carries, or None."""
    try:
        v = json.loads(b64u_decode(params["opaque"]))
        b = bytes.fromhex(v["bnap_offer"])
    except Exception:
        return None
    return b if len(b) == 32 else None


def mpp_challenge_header(params):
    """A Payment challenge as a WWW-Authenticate value, parameters in order."""
    return "Payment " + ", ".join('%s="%s"' % (k, v) for k, v in params.items())


def mpp_challenge_params(data):
    """The parameters of the one Payment challenge an mpp-challenge entry holds."""
    from .http import parse_challenges
    chs = parse_challenges(data.decode("ascii"))
    if len(chs) != 1 or chs[0].scheme != "Payment" or chs[0].raw != data.decode("ascii"):
        raise ValueError("an mpp-challenge entry is not one Payment challenge")
    return chs[0].params


def mpp_request_invoice(params):
    try:
        req = json.loads(b64u_decode(params["request"]))
        details = req.get("methodDetails")
        if isinstance(details, dict) and "invoice" in details:
            return details["invoice"]
        return req.get("invoice")
    except Exception:
        return None


def mpp_credential(params, preimage):
    return b64u(json.dumps({"challenge": params, "payload": {"preimage": preimage.hex()}},
                           separators=(",", ":"), sort_keys=True).encode())


def parse_mpp_credential(token68):
    obj = json.loads(b64u_decode(token68))
    return obj["challenge"], bytes.fromhex(obj["payload"]["preimage"])
