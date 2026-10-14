"""Signatures: BIP-340 from the reference encoder, ECDSA P-256 for DPoP.

BIP-340 signing uses 32 zero bytes of auxiliary randomness by default, as the
draft-00 vectors do. ECDSA uses RFC 6979 deterministic nonces so generated
cases are reproducible. Neither is constant time.
"""
import hashlib
import hmac

from ._ref import ref

# ---------------------------------------------------------------- BIP-340


def schnorr_pub(sk):
    return ref.pubkey(sk)


def schnorr_sign(sk, msg, aux=bytes(32)):
    return ref.schnorr_sign(sk, msg, aux)


def schnorr_verify(pk, msg, sig):
    if len(pk) != 32 or len(sig) != 64:
        return False
    try:
        return bool(ref.schnorr_verify(pk, msg, sig))
    except Exception:
        return False


def key_from_label(label):
    """Secret keys in the vectors are SHA-256 of a label."""
    return hashlib.sha256(label.encode() if isinstance(label, str) else label).digest()

# ---------------------------------------------------------------- P-256

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _inv(x, m):
    return pow(x, m - 2, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + _A) * _inv(2 * p1[1], _P) % _P
    else:
        lam = (p2[1] - p1[1]) * _inv(p2[0] - p1[0], _P) % _P
    x3 = (lam * lam - p1[0] - p2[0]) % _P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % _P)


def _mul(pt, k):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _on_curve(pt):
    x, y = pt
    return 0 <= x < _P and 0 <= y < _P and (y * y - (x * x * x + _A * x + _B)) % _P == 0


def p256_pub(sk):
    """Return (x, y) as 32-byte big-endian strings."""
    d = int.from_bytes(sk, "big") % _N
    if d == 0:
        raise ValueError("bad P-256 secret key")
    x, y = _mul(_G, d)
    return x.to_bytes(32, "big"), y.to_bytes(32, "big")


def _rfc6979_k(d, h1):
    x = d.to_bytes(32, "big")
    z = (int.from_bytes(h1, "big") % _N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + z, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + z, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < _N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def es256_sign(sk, msg):
    """ECDSA P-256 with SHA-256; return the 64-byte JWS form r || s."""
    d = int.from_bytes(sk, "big") % _N
    h1 = hashlib.sha256(msg).digest()
    e = int.from_bytes(h1, "big")
    while True:
        k = _rfc6979_k(d, h1)
        r = _mul(_G, k)[0] % _N
        s = _inv(k, _N) * (e + r * d) % _N
        if r and s:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        h1 = hashlib.sha256(h1).digest()  # unreachable in practice


def es256_verify(x, y, msg, sig):
    if len(sig) != 64 or len(x) != 32 or len(y) != 32:
        return False
    q = (int.from_bytes(x, "big"), int.from_bytes(y, "big"))
    if not _on_curve(q):
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = _inv(s, _N)
    pt = _add(_mul(_G, e * w % _N), _mul(q, r * w % _N))
    return pt is not None and pt[0] % _N == r
