"""Signatures: BIP-340 from the reference encoder, ECDSA P-256 for DPoP.

BIP-340 signing uses 32 zero bytes of auxiliary randomness by default, as the
draft-00 vectors do. ECDSA uses RFC 6979 deterministic nonces so generated
cases are reproducible. Neither is constant time.
"""
import hashlib
import hmac

from ._ref import ref

# ---------------------------------------------------------------- Jacobian arithmetic

class _Curve:
    """Short Weierstrass curve y^2 = x^3 + a x + b over F_p, Jacobian coordinates."""

    def __init__(self, p, a, b, n, g):
        self.p, self.a, self.b, self.n, self.g = p, a, b, n, g

    def double(self, pt):
        X, Y, Z = pt
        p = self.p
        if Z == 0 or Y == 0:
            return (0, 1, 0)
        YY = Y * Y % p
        S = 4 * X * YY % p
        M = (3 * X * X + self.a * pow(Z, 4, p)) % p
        X3 = (M * M - 2 * S) % p
        return (X3, (M * (S - X3) - 8 * YY * YY) % p, 2 * Y * Z % p)

    def add(self, p1, p2):
        if p1[2] == 0:
            return p2
        if p2[2] == 0:
            return p1
        p = self.p
        X1, Y1, Z1 = p1
        X2, Y2, Z2 = p2
        Z1Z1, Z2Z2 = Z1 * Z1 % p, Z2 * Z2 % p
        U1, U2 = X1 * Z2Z2 % p, X2 * Z1Z1 % p
        S1, S2 = Y1 * Z2 * Z2Z2 % p, Y2 * Z1 * Z1Z1 % p
        if U1 == U2:
            return self.double(p1) if S1 == S2 else (0, 1, 0)
        H_, R = (U2 - U1) % p, (S2 - S1) % p
        HH = H_ * H_ % p
        HHH = H_ * HH % p
        V = U1 * HH % p
        X3 = (R * R - HHH - 2 * V) % p
        return (X3, (R * (V - X3) - S1 * HHH) % p, H_ * Z1 * Z2 % p)

    def mul(self, affine, k):
        k %= self.n
        r, q = (0, 1, 0), (affine[0], affine[1], 1)
        for bit in bin(k)[2:] if k else "":
            r = self.double(r)
            if bit == "1":
                r = self.add(r, q)
        return r

    def affine(self, pt):
        if pt[2] == 0:
            return None
        p = self.p
        zi = pow(pt[2], p - 2, p)
        zi2 = zi * zi % p
        return (pt[0] * zi2 % p, pt[1] * zi2 * zi % p)


_K1 = _Curve(ref.P, 0, 7, ref.N, ref.G)

# ---------------------------------------------------------------- BIP-340
#
# The same algorithm as reference/python/bnap_ref.py (schnorr_sign,
# schnorr_verify, pubkey), with Jacobian arithmetic so a test run does not
# spend its time in modular inversions. tests/test_vectors.py checks both
# give identical bytes.


def _xb(x):
    return x.to_bytes(32, "big")


def schnorr_pub(sk):
    return _xb(_K1.affine(_K1.mul(_K1.g, int.from_bytes(sk, "big")))[0])


def schnorr_sign(sk, msg, aux=bytes(32)):
    tg = ref.tagged
    d0 = int.from_bytes(sk, "big")
    if not 1 <= d0 < ref.N:
        raise ValueError("bad secret key")
    Pt = _K1.affine(_K1.mul(_K1.g, d0))
    d = d0 if Pt[1] % 2 == 0 else ref.N - d0
    t = bytes(a ^ b for a, b in zip(_xb(d), tg("BIP0340/aux", aux)))
    k0 = int.from_bytes(tg("BIP0340/nonce", t + _xb(Pt[0]) + msg), "big") % ref.N
    if k0 == 0:
        raise ValueError("nonce is zero")
    R = _K1.affine(_K1.mul(_K1.g, k0))
    k = k0 if R[1] % 2 == 0 else ref.N - k0
    e = int.from_bytes(tg("BIP0340/challenge", _xb(R[0]) + _xb(Pt[0]) + msg), "big") % ref.N
    return _xb(R[0]) + _xb((k + e * d) % ref.N)


def schnorr_verify(pk, msg, sig):
    if len(pk) != 32 or len(sig) != 64:
        return False
    Pt = ref._lift_x(int.from_bytes(pk, "big"))
    r, s_ = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if Pt is None or r >= ref.P or s_ >= ref.N:
        return False
    e = int.from_bytes(ref.tagged("BIP0340/challenge", sig[:32] + pk + msg), "big") % ref.N
    R = _K1.affine(_K1.add(_K1.mul(_K1.g, s_), _K1.mul(Pt, ref.N - e)))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def ref_schnorr_sign(sk, msg, aux=bytes(32)):
    """The reference encoder's own implementation, for cross-checks."""
    return ref.schnorr_sign(sk, msg, aux)


def ref_schnorr_verify(pk, msg, sig):
    return bool(ref.schnorr_verify(pk, msg, sig))


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


_R1 = _Curve(_P, _A, _B, _N, _G)


def _mul(pt, k):
    return _R1.affine(_R1.mul(pt, k))


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    return _R1.affine(_R1.add((p1[0], p1[1], 1), (p2[0], p2[1], 1)))


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
