#!/usr/bin/env python3
"""The notes route offer of spec/schemes/bnap-notes-draft-00.md section 18.1.

The socket vectors' route offer (socket draft-00 section 14) has a bnap:notes
pay entry without params, so no valid notes credential exists for it. This
script builds the offer the notes vectors use instead, and whose OfferID the
X-Cashu example of nuts/xx-http-402-self-issued-mint.md carries:

    python3 -I nuts/tools/notes_offer_vector.py reference/python

Standard library only. It reuses the BNAP reference encoder for TLV, BIP-340,
the OfferID and the Context, and checks its NUT-02 version-01 keyset ID code
against a known ID before printing anything.
"""
import hashlib
import json
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else "reference/python")
import bnap_ref as r  # noqa: E402


def sha(b):
    return hashlib.sha256(b).digest()


def comp(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def keyset_id_v01(keys, unit, input_fee_ppk, final_expiry):
    """NUT-02 version-01 keyset ID. keys: {amount: 33-byte compressed key}."""
    pre = ",".join(f"{amt}:{keys[amt].hex()}" for amt in sorted(keys)).encode()
    pre += f"|unit:{unit}".encode()
    if input_fee_ppk:
        pre += f"|input_fee_ppk:{input_fee_ppk}".encode()
    if final_expiry:
        pre += f"|final_expiry:{final_expiry}".encode()
    return bytes([1]) + sha(pre)


# A version-01 ID with fee and expiry: the four-key keyset of the cashu 0.18.1
# crate's NUT-02 tests, whose ID also appears in the NUT-02 response examples.
NUT02_KEYS = {
    1: "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc",
    2: "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de",
    4: "02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303",
    8: "02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528",
}
NUT02_ID = "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a"

AMOUNTS = [2 ** i for i in range(16)]
KEYSETS = [  # label, input_fee_ppk, final_expiry, active
    ("A", 100, 1830000000, True),
    ("B", 0, 1800000000, False),
]
ISSUER = "https://api.example/cashu"
EXPIRES = 1791703600
SOCKET_OFFER_ID = "5c8640261f6f1de3206a2e9cd1c2599a2e9256547242061c95f9d2e06cf6696d"


def main():
    known = {a: bytes.fromhex(k) for a, k in NUT02_KEYS.items()}
    assert keyset_id_v01(known, "sat", 100, 2059210353).hex() == NUT02_ID, "NUT-02 ID disagrees"

    keysets, entries = [], []
    for label, fee, final_expiry, active in KEYSETS:
        keys = {}
        for amt in AMOUNTS:
            a = int.from_bytes(sha(f"bnap notes test keyset {label} {amt}".encode()), "big")
            assert 0 < a < r.N
            keys[amt] = comp(r._mul(r.G, a))
        kid = keyset_id_v01(keys, "sat", fee, final_expiry)
        keysets.append({"label": label, "input_fee_ppk": fee, "final_expiry": final_expiry,
                        "active": active, "id": kid.hex(),
                        "keys": {str(amt): keys[amt].hex() for amt in AMOUNTS}})
        rec = [(0, kid)]
        if fee:
            rec.append((2, r.tu64(fee)))
        if active:
            rec.append((4, b""))
        entries.append((kid, r.tlv(rec)))
    entries.sort()
    params = r.tlv([(0, ISSUER.encode()), (2, r.entry_list([e for _, e in entries]))])

    # The socket vectors' route offer, with params in the notes pay entry and a later expiry.
    offer_sk = r.H(b"bnap test offer key")
    mac_key = r.H(b"bnap test mac key")
    origin = "https://api.example"
    body = b'{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}'
    act = r.http_scope("POST", origin + "/v1/chat/completions", body)
    route = r.http_route_scope(origin, "chat")
    pay = r.entry_list([
        r.tlv([(0, b"bnap:notes"), (2, r.tu64(2100)), (4, b"sat"), (8, params), (10, r.tu64(500))]),
    ])
    attest = r.entry_list([
        r.tlv([(0, b"httpsig:web-bot-auth"), (2, r.tu64(2)), (4, r.tu64(2000))]),
    ])
    def fields(expires, pay):
        return [(0, r.tu64(1)), (2, route), (4, b""), (8, b""), (10, r.tu64(expires)),
                (12, b"https://api.example/.well-known/bnap"), (14, r.pubkey(offer_sk)),
                (16, bytes(range(16))), (18, pay), (20, attest),
                (3000000001, b"\x0a\x0a")]  # GREASE

    # Without params and with the socket vectors' expiry, these fields are the socket route offer.
    socket_pay = r.entry_list([
        r.tlv([(0, b"bnap:notes"), (2, r.tu64(2100)), (4, b"sat"), (10, r.tu64(500))]),
    ])
    _, socket_oid = r.build_offer(fields(1791700300, socket_pay), offer_sk, mac_key)
    assert socket_oid.hex() == SOCKET_OFFER_ID, "the base fields are not the socket route offer"

    offer, oid = r.build_offer(fields(EXPIRES, pay), offer_sk, mac_key)
    recs = dict(r.parse_tlv(offer))
    assert r.schnorr_verify(r.pubkey(offer_sk),
                            r.tagged("bnap/offer-sig", r.signed_bytes(r.parse_tlv(offer))),
                            recs[r.OFFER_SIG])
    assert r.offer_id_of(offer) == oid
    ctx = r.context(oid, act, "bnap:notes", ["httpsig:web-bot-auth"], b"")

    print(json.dumps({
        "issuer": ISSUER,
        "keysets": keysets,
        "params": {"bytes": params.hex(), "len": len(params)},
        "offer": {"expires": EXPIRES, "bytes": offer.hex(), "len": len(offer),
                  "offer_id": oid.hex(), "offer_sig": recs[r.OFFER_SIG].hex(),
                  "mac": recs[r.MAC].hex()},
        "context": ctx.hex(),
    }, indent=1))


if __name__ == "__main__":
    main()
