"""httpauth:DPoP attestations: the conformance adapter profile "bnap-conf-dpop-1".

draft-00 and the registry fix what a DPoP attestation does (class A, the
Context in a proof claim, use model reusable, local ID the JWK thumbprint)
but no adapter specification fixes the body bytes yet. This profile is the
suite's assumption, used by run.py and mock_gate.py alike:

  body    = TLV { 0: access token (UTF-8, may be empty), 2: DPoP proof (compact JWS) }
  proof   = RFC 9449 DPoP proof, alg ES256, typ dpop+jwt, jwk in the header;
            claims jti, htm, htu, iat, and bnap_ctx = b64u(Context);
            ath = b64u(SHA-256(access token)) when the token is not empty
  sig     = the JWS signature r || s (RFC 7518 3.4) with s <= n/2 (low-S). A
            proof whose s exceeds n/2 does not verify under this profile
  htm     = the request method; htu = manifest origin + request path, no query
  local ID = the raw 32-byte RFC 7638 JWK thumbprint (SHA-256)

Low-S is what makes the body canonical (draft-00 5.1, "a scheme MUST reject
a body that contains any byte it does not verify"): plain ECDSA also accepts
(r, n - s), so without it anyone on the path could turn one admitted proof
into a second body that verifies. Its hash differs, so would its ReplayKey,
and the gate would run the action again from one client proof.

The gate builds htm and htu from its own carrier inputs, never from raw
request fields (draft-00 5.1). A replay sends the same body, so a gate must
not refuse a proof because its jti was seen before: replays are recognized
by ReplayKey before any outcome is changed.
"""
import hashlib
import json

from . import codec
from .codec import b64u, b64u_decode, malformed
from .crypto import es256_sign, es256_verify, es256_low_s, es256_other_s, p256_pub, key_from_label

SCHEME = "httpauth:DPoP"
CLAIM = "bnap_ctx"
PROFILE = "bnap-conf-dpop-1"


class DpopKey:
    def __init__(self, sk):
        self.sk = sk
        self.x, self.y = p256_pub(sk)

    @classmethod
    def from_label(cls, label):
        return cls(key_from_label(label))

    def jwk(self):
        return {"kty": "EC", "crv": "P-256", "x": b64u(self.x), "y": b64u(self.y)}

    def thumbprint(self):
        return jwk_thumbprint(self.jwk())


def jwk_thumbprint(jwk):
    """RFC 7638 for an EC key: required members, lexicographic, no whitespace."""
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                       separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canon.encode()).digest()


def _seg(obj):
    return b64u(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def make_proof(key, *, method, htu, iat, jti, context=None, access_token="", omit_ctx=False,
               extra_claims=None):
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk()}
    claims = {"jti": jti, "htm": method, "htu": htu, "iat": iat}
    if not omit_ctx and context is not None:
        claims[CLAIM] = b64u(context)
    if access_token:
        claims["ath"] = b64u(hashlib.sha256(access_token.encode()).digest())
    if extra_claims:
        claims.update(extra_claims)
    signing = _seg(header) + "." + _seg(claims)
    sig = es256_low_s(es256_sign(key.sk, signing.encode()))
    return signing + "." + b64u(sig)


def make_body(key, *, method, htu, iat, jti, context=None, access_token="", omit_ctx=False):
    proof = make_proof(key, method=method, htu=htu, iat=iat, jti=jti, context=context,
                       access_token=access_token, omit_ctx=omit_ctx)
    return codec.tlv([(0, access_token.encode()), (2, proof.encode())])


class DpopVerified:
    def __init__(self, thumbprint, claims, access_token):
        self.thumbprint = thumbprint
        self.claims = claims
        self.access_token = access_token


class DpopReject(Exception):
    pass


def other_s_body(body):
    """The body with its proof's signature s replaced by n - s: the copy a party on the path could
    make of a proof under plain ECDSA. Under this profile it does not verify."""
    recs = codec.parse_stream(body)
    signing, _, sig = recs[1].value.decode().rpartition(".")
    proof = signing + "." + b64u(es256_other_s(b64u_decode(sig)))
    return codec.tlv([(r.type, proof.encode() if r.type == 2 else r.value) for r in recs])


def verify_body(body, *, context, method, htu, now, skew=60, accept_token=None, check_context=True,
                low_s=True):
    """Verify a profile body. accept_token(token, thumbprint) -> bool decides tokens.

    Raises MALFORMED for a non-canonical body (5.1 canonical bodies) and
    DpopReject when the attestation does not verify, a high-S signature
    included. low_s=False is only for the mock gate's high-s-accepted fault.
    """
    recs = codec.parse_stream(body)
    if [r.type for r in recs] != [0, 2]:
        raise malformed("dpop-body-records")
    token = codec.utf8(recs[0].value, "access token")
    proof = codec.utf8(recs[1].value, "proof")
    parts = proof.split(".")
    if len(parts) != 3:
        raise DpopReject("proof-not-jws")
    try:
        header = json.loads(b64u_decode(parts[0]))
        claims = json.loads(b64u_decode(parts[1]))
        sig = b64u_decode(parts[2])
    except Exception:
        raise DpopReject("proof-encoding") from None
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
        raise DpopReject("proof-header")
    jwk = header.get("jwk") or {}
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise DpopReject("proof-jwk")
    try:
        x, y = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
    except Exception:
        raise DpopReject("proof-jwk") from None
    if not es256_verify(x, y, (parts[0] + "." + parts[1]).encode(), sig, low_s=low_s):
        raise DpopReject("proof-signature")
    if check_context:
        if claims.get(CLAIM) is None:
            raise DpopReject("context-claim-missing")
        if claims.get(CLAIM) != b64u(context):
            raise DpopReject("context-claim-mismatch")
    if claims.get("htm") != method or claims.get("htu") != htu:
        raise DpopReject("htm-htu")
    iat = claims.get("iat")
    if not isinstance(iat, int) or iat > now + skew:
        raise DpopReject("iat")
    tp = jwk_thumbprint(jwk)
    if token:
        if claims.get("ath") != b64u(hashlib.sha256(token.encode()).digest()):
            raise DpopReject("ath")
    if accept_token is not None and not accept_token(token, tp):
        raise DpopReject("access-token")
    return DpopVerified(tp, claims, token)


def unverified_thumbprint(body):
    """The thumbprint a body claims, without verifying it (for diagnostics)."""
    try:
        recs = codec.parse_stream(body)
        proof = recs[1].value.decode()
        header = json.loads(b64u_decode(proof.split(".")[0]))
        return jwk_thumbprint(header["jwk"])
    except Exception:
        return None
