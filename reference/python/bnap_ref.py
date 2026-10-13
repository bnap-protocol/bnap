"""BNAP socket draft-00 reference encoder and test-vector generator.

Pure Python 3, standard library only. Not constant-time; for test vectors only.
"""
import hashlib
import hmac
import json

# ---------------------------------------------------------------- hashing

def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def tagged(tag: str, msg: bytes) -> bytes:
    t = H(tag.encode())
    return H(t + t + msg)

# ---------------------------------------------------------------- BIP-340 (reference algorithm)

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def _mul(p, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = _add(r, p)
        p = _add(p, p)
    return r


def _lift_x(x):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y & 1 == 0 else P - y)


def _i(b):
    return int.from_bytes(b, "big")


def _b(x):
    return x.to_bytes(32, "big")


def pubkey(sk: bytes) -> bytes:
    return _b(_mul(G, _i(sk))[0])


def schnorr_sign(sk: bytes, msg: bytes, aux: bytes = bytes(32)) -> bytes:
    d0 = _i(sk)
    Pt = _mul(G, d0)
    d = d0 if Pt[1] % 2 == 0 else N - d0
    t = bytes(a ^ b for a, b in zip(_b(d), tagged("BIP0340/aux", aux)))
    k0 = _i(tagged("BIP0340/nonce", t + _b(Pt[0]) + msg)) % N
    R = _mul(G, k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = _i(tagged("BIP0340/challenge", _b(R[0]) + _b(Pt[0]) + msg)) % N
    return _b(R[0]) + _b((k + e * d) % N)


def schnorr_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    Pt = _lift_x(_i(pk))
    r, s = _i(sig[:32]), _i(sig[32:])
    if Pt is None or r >= P or s >= N:
        return False
    e = _i(tagged("BIP0340/challenge", sig[:32] + pk + msg)) % N
    R = _add(_mul(G, s), _mul(Pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r

# ---------------------------------------------------------------- integers and TLV

def bigsize(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "big")
    return b"\xff" + n.to_bytes(8, "big")


def read_bigsize(buf: bytes, i: int):
    f = buf[i]
    if f < 0xFD:
        return f, i + 1
    w = {0xFD: 2, 0xFE: 4, 0xFF: 8}[f]
    v = int.from_bytes(buf[i + 1:i + 1 + w], "big")
    if v < {2: 0xFD, 4: 0x10000, 8: 0x100000000}[w]:
        raise ValueError("MALFORMED: non-minimal BigSize")
    return v, i + 1 + w


def tu64(n: int) -> bytes:
    return n.to_bytes(8, "big").lstrip(b"\x00")


def lp(b: bytes) -> bytes:
    return bigsize(len(b)) + b


def tlv(records) -> bytes:
    """records: list of (type, value bytes); must be strictly increasing."""
    out, last = b"", -1
    for t, v in records:
        assert t > last, "TLV types must be strictly increasing"
        last = t
        out += bigsize(t) + bigsize(len(v)) + v
    return out


def parse_tlv(buf: bytes):
    i, last, out = 0, -1, []
    while i < len(buf):
        t, i = read_bigsize(buf, i)
        n, i = read_bigsize(buf, i)
        if t <= last:
            raise ValueError("MALFORMED: TLV order")
        if i + n > len(buf):
            raise ValueError("MALFORMED: truncated")
        out.append((t, buf[i:i + n]))
        last, i = t, i + n
    return out


def entry_list(streams) -> bytes:
    return b"".join(lp(s) for s in streams)


def sig_range(t: int) -> bool:
    return 240 <= t <= 1000


def signed_bytes(records, exclude=()):
    return b"".join(bigsize(t) + bigsize(len(v)) + v for t, v in records
                    if not sig_range(t) and t not in exclude)

# ---------------------------------------------------------------- socket objects

OFFER_SIG, MAC, NATIVE = 240, 242, 26


def build_offer(fields, offer_sk, mac_key):
    """fields: list of (type, value) without 240/242. Returns (offer bytes, offer_id)."""
    recs = sorted(fields)
    S = signed_bytes(recs)
    offer_id = tagged("bnap/offer", signed_bytes(recs, exclude=(NATIVE,)))
    sig = schnorr_sign(offer_sk, tagged("bnap/offer-sig", S))
    mac = hmac.new(mac_key, S, hashlib.sha256).digest()
    return tlv(sorted(recs + [(OFFER_SIG, sig), (MAC, mac)])), offer_id


def offer_id_of(offer: bytes) -> bytes:
    return tagged("bnap/offer", signed_bytes(parse_tlv(offer), exclude=(NATIVE,)))


def context(offer_id, action_scope, pay_scheme, attest_schemes, ext):
    a = sorted(s.encode() for s in attest_schemes)
    assert len(set(a)) == len(a)
    return tagged("bnap/ctx", offer_id + action_scope + lp(pay_scheme.encode())
                  + bigsize(len(a)) + b"".join(lp(x) for x in a) + H(ext))


def digest(ctx, binding, pay_body, attest_bodies_sorted):
    return tagged("bnap/cred", ctx + lp(binding) + H(pay_body)
                  + b"".join(H(b) for b in attest_bodies_sorted))


def use_id(scheme: str, local: bytes) -> bytes:
    return tagged("bnap/use", lp(scheme.encode()) + local)


def rail_id(kind: str, canonical: bytes) -> bytes:
    return tagged("bnap/rail", lp(kind.encode()) + canonical)


def replay_key(ctx, pay_body, attest_bodies_sorted, ids):
    s = sorted(ids)
    return tagged("bnap/replay", ctx + H(pay_body) + b"".join(H(b) for b in attest_bodies_sorted)
                  + bigsize(len(s)) + b"".join(s))


def native_context(offer_id, action_scope, scheme):
    return tagged("bnap/ctx-native", offer_id + action_scope + lp(scheme.encode()))


def native_digest(ctx, native_bytes):
    return tagged("bnap/cred-native", ctx + H(native_bytes))


def http_scope(method, uri, content, headers=()):
    """headers: (lower-case name, value as received) for the fields the route lists, in its order."""
    cd = H(content) if content else b""
    hs = bigsize(len(headers)) + b"".join(lp(n.encode()) + lp(v.encode()) for n, v in headers)
    return tagged("bnap/scope/http", lp(method.encode()) + lp(uri.encode()) + lp(cd) + hs)


def http_route_scope(origin, route):
    return tagged("bnap/route/http", lp(origin.encode()) + lp(route.encode()))


def build_response(fields, receipt_sk):
    recs = sorted(fields)
    ack = schnorr_sign(receipt_sk, tagged("bnap/ack", signed_bytes(recs)))
    return tlv(sorted(recs + [(240, ack)]))


def jcs(obj) -> bytes:
    # RFC 8785 for objects holding only strings, integers, booleans, lists and objects
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

# ---------------------------------------------------------------- vectors

def hx(b):
    return b.hex()


def main():
    V = {}
    offer_sk = H(b"bnap test offer key")
    receipt_sk = H(b"bnap test receipt key")
    root_sk = H(b"bnap test root key")
    note_sk = H(b"bnap test note key")
    mac_key = H(b"bnap test mac key")

    V["tagged_hash"] = {"tag": "bnap/offer", "msg": "", "out": hx(tagged("bnap/offer", b""))}
    V["bigsize"] = {str(n): hx(bigsize(n)) for n in (0, 252, 253, 65535, 65536, 4294967296)}
    V["tu64"] = {str(n): hx(tu64(n)) for n in (0, 1, 256, 1791700000)}

    # HTTP scopes for the LLM-proxy example
    origin = "https://api.example"
    body = b'{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}'
    act = http_scope("POST", origin + "/v1/chat/completions", body)
    route = http_route_scope(origin, "chat")
    V["http_scope"] = {"method": "POST", "uri": origin + "/v1/chat/completions",
                       "content": body.decode(), "action_scope": hx(act),
                       "route": "chat", "route_scope": hx(route)}

    # Offer: route scope, metered, notes 2100 sat max, Web Bot Auth 20 % discount
    pay = entry_list([
        tlv([(0, b"bnap:notes"), (2, tu64(2100)), (4, b"sat"), (10, tu64(500))]),
    ])
    attest = entry_list([
        tlv([(0, b"httpsig:web-bot-auth"), (2, tu64(2)), (4, tu64(2000))]),
    ])
    fields = [(0, tu64(1)), (2, route), (4, b""), (8, b""), (10, tu64(1791700300)),
              (12, b"https://api.example/.well-known/bnap"), (14, pubkey(offer_sk)),
              (16, bytes(range(16))), (18, pay), (20, attest),
              (3000000001, b"\x0a\x0a")]  # GREASE
    offer, oid = build_offer(fields, offer_sk, mac_key)
    recs = parse_tlv(offer)
    sig = dict(recs)[OFFER_SIG]
    assert schnorr_verify(pubkey(offer_sk), tagged("bnap/offer-sig", signed_bytes(recs)), sig)
    assert offer_id_of(offer) == oid
    V["offer"] = {"offer_sk": hx(offer_sk), "offer_key": hx(pubkey(offer_sk)),
                  "mac_key": hx(mac_key), "bytes": hx(offer), "len": len(offer),
                  "offer_id": hx(oid), "offer_sig": hx(sig)}

    # Exact-scope offer with a native invoice record: OfferID ignores it, signature covers it
    nat = entry_list([tlv([(0, b""), (2, b"bolt11"), (4, b"lnbc210n1...placeholder")])])
    f2 = [(0, tu64(1)), (2, act), (10, tu64(1791700300)), (14, pubkey(offer_sk)),
          (16, bytes(16)), (18, entry_list([tlv([(0, b"payment:lightning/charge"),
                                                   (2, tu64(21)), (4, b"sat")])]))]
    o_a, id_a = build_offer(f2, offer_sk, mac_key)
    o_b, id_b = build_offer(f2 + [(NATIVE, nat)], offer_sk, mac_key)
    assert id_a == id_b and o_a != o_b
    V["offer_native"] = {"offer_id": hx(id_a), "without_native": hx(o_a), "with_native": hx(o_b)}

    # Credential: notes (class S) plus Web Bot Auth attestation
    ext = b""
    wba_body = b"sig1=:...placeholder web bot auth signature over the Context...:"
    ctx = context(oid, act, "bnap:notes", ["httpsig:web-bot-auth"], ext)
    note_Y = H(b"note secret 1")  # stands in for Y = hash_to_curve(secret)
    notes_body = tlv([(0, note_Y), (2, b"proofs+outputs placeholder")])
    binding = H(b"tls-exporter placeholder")
    dg = digest(ctx, binding, notes_body, [wba_body])
    witness = schnorr_sign(note_sk, dg)
    cred = tlv([(0, tu64(1)), (2, offer),
                (4, tlv([(0, b"bnap:notes"), (2, notes_body), (4, witness)])),
                (6, entry_list([tlv([(0, b"httpsig:web-bot-auth"), (2, wba_body)])])),
                (8, binding)])
    u_note = use_id("bnap:notes", note_Y)
    u_wba = use_id("httpsig:web-bot-auth", H(b"bot key thumbprint"))
    rk = replay_key(ctx, notes_body, [wba_body], [u_note, u_wba])
    V["credential"] = {"note_sk": hx(note_sk), "context": hx(ctx), "digest": hx(dg),
                       "witness": hx(witness), "bytes_len": len(cred),
                       "use_ids": [hx(u_note), hx(u_wba)], "replay_key": hx(rk)}
    # binding is outside the Context and ReplayKey: a new connection changes only the Digest
    dg2 = digest(ctx, H(b"other connection"), notes_body, [wba_body])
    assert dg2 != dg
    V["credential"]["digest_other_binding"] = hx(dg2)

    # Attestation-only credential: no pay, no ext, no binding (every "or empty" form)
    dpop_body = b"DPoP proof placeholder with claim bnap_ctx"
    f3 = [(0, tu64(1)), (2, act), (10, tu64(1791700300)), (14, pubkey(offer_sk)),
          (16, bytes([1]) * 16),
          (20, entry_list([tlv([(0, b"httpauth:DPoP"), (2, tu64(1))])]))]  # waive
    o3, id3 = build_offer(f3, offer_sk, mac_key)
    ctx_a = context(id3, act, "", ["httpauth:DPoP"], b"")
    dg_a = digest(ctx_a, b"", b"", [dpop_body])
    u_dpop = use_id("httpauth:DPoP", H(b"client key thumbprint"))
    V["attest_only"] = {"offer": hx(o3), "offer_id": hx(id3), "context": hx(ctx_a), "digest": hx(dg_a), "use_id": hx(u_dpop),
                        "replay_key": hx(replay_key(ctx_a, b"", [dpop_body], [u_dpop]))}

    # Native credential: synthetic envelope for an MPP Lightning credential on the exact offer
    nctx = native_context(id_a, act, "payment:lightning/charge")
    V["native"] = {"scheme": "payment:lightning/charge", "native_bytes": "MPP credential placeholder",
                   "context": hx(nctx),
                   "digest": hx(native_digest(nctx, b"MPP credential placeholder"))}

    # Rail ID: one Lightning payment hash, the same whichever scheme reports it
    ph = H(b"preimage")
    V["rail_id"] = {"kind": "ln", "payment_hash": hx(ph), "rail_id": hx(rail_id("ln", ph))}

    # Response: metered, 340 sat charged of 2100
    resp = build_response([(0, tu64(1)), (2, b""), (6, tu64(340)), (8, b"sat"),
                           (10, oid), (12, dg), (14, tu64(850)), (16, b"change signatures placeholder"),
                           (18, pubkey(receipt_sk)), (20, tu64(1791700042))], receipt_sk)
    rr = parse_tlv(resp)
    assert schnorr_verify(pubkey(receipt_sk), tagged("bnap/ack", signed_bytes(rr)), dict(rr)[240])
    V["response"] = {"receipt_sk": hx(receipt_sk), "bytes": hx(resp), "ack": hx(dict(rr)[240])}

    # Manifest
    man = {"bnap": 1, "origin": origin, "seq": 1, "issued": 1791700000, "max_age": 604800,
           "root": hx(pubkey(root_sk)), "backup": hx(pubkey(H(b"bnap test backup key"))),
           "required": True,
           "keys": [{"kid": hx(pubkey(offer_sk)), "use": "offer", "not_after": 1792304800},
                    {"kid": hx(pubkey(receipt_sk)), "use": "receipt", "not_after": 1792304800}],
           "limits": {"replay_window": 86400, "pending_timeout": 300,
                      "max_offer": 4096, "max_credential": 16384, "max_response": 8192},
           "carriers": ["http"],
           "routes": [{"id": "chat", "match": "POST /v1/chat/completions", "scope": "route",
                       "metered": True, "meter": "tokens", "price": {"sat": 2100}, "headers": [],
                       "pay": ["bnap:notes", "httpauth:L402"],
                       "attest": [{"scheme": "httpsig:web-bot-auth", "effect": "discount",
                                   "value": 2000}]}]}
    msig = schnorr_sign(root_sk, tagged("bnap/manifest", jcs(man)))
    V["manifest"] = {"root_sk": hx(root_sk), "jcs": jcs(man).decode(), "sig": hx(msig)}
    return V


if __name__ == "__main__":
    print(json.dumps(main(), indent=1))
