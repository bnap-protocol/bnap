#!/usr/bin/env python3
"""Test vectors for nuts/xx-key-secret-proofs.md.

Standard library only. Reuses the BIP-340 code of the BNAP reference encoder:

    python3 -I nuts/tools/key_secret_vectors.py reference/python

Prints the vectors as JSON. hash_to_curve is NUT-00's; the script checks it
against the three NUT-00 test vectors before printing anything.
"""
import hashlib
import json
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else "reference/python")
import bnap_ref as r  # noqa: E402


def sha(b):
    return hashlib.sha256(b).digest()


def lift_even(x):
    if x >= r.P:
        return None
    y2 = (pow(x, 3, r.P) + 7) % r.P
    y = pow(y2, (r.P + 1) // 4, r.P)
    if pow(y, 2, r.P) != y2:
        return None
    return (x, y if y % 2 == 0 else r.P - y)


def hash_to_curve(msg):
    mh = sha(b"Secp256k1_HashToCurve_Cashu_" + msg)
    for c in range(2 ** 16):
        pt = lift_even(int.from_bytes(sha(mh + c.to_bytes(4, "little")), "big"))
        if pt:
            return pt
    raise ValueError("no point found")


def comp(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


NUT00 = {
    "00" * 32: "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725",
    "00" * 31 + "01": "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf",
    "00" * 31 + "02": "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f",
}


def main():
    for x, y in NUT00.items():
        assert comp(hash_to_curve(bytes.fromhex(x))).hex() == y, "hash_to_curve disagrees with NUT-00"

    k = sha(b"key-secret test note key")
    K = r.pubkey(k)
    secret = K.hex()
    Y = hash_to_curve(secret.encode())

    # External context: the digest is whatever the relying protocol defines.
    D_ext = sha(b"example context digest")
    sig_ext = r.schnorr_sign(k, D_ext)
    assert r.schnorr_verify(K, D_ext, sig_ext)

    # Swap context: one input, one output.
    a = int.from_bytes(sha(b"key-secret test mint key"), "big")
    C = comp(r._mul(Y, a))
    keyset_id = bytes([1]) + sha(b"key-secret test keyset")
    rr = int.from_bytes(sha(b"key-secret test blinding factor"), "big")
    B_ = comp(r._add(hash_to_curve(b"key-secret test output secret"), r._mul(r.G, rr)))
    msg = ((1).to_bytes(2, "big") + secret.encode() + C
           + (1).to_bytes(2, "big") + (8).to_bytes(8, "big") + keyset_id + B_)
    D_swap = r.tagged("Cashu_KeySecret_Swap_v1", msg)
    sig_swap = r.schnorr_sign(k, D_swap)
    assert r.schnorr_verify(K, D_swap, sig_swap)

    print(json.dumps({
        "note": {"k": k.hex(), "K": K.hex(), "secret": secret, "Y": comp(Y).hex()},
        "external": {"D": D_ext.hex(), "signature": sig_ext.hex()},
        "swap": {"mint_key_A": comp(r._mul(r.G, a)).hex(), "C": C.hex(),
                 "output": {"amount": 8, "id": keyset_id.hex(), "B_": B_.hex()},
                 "message_len": len(msg), "D": D_swap.hex(), "signature": sig_swap.hex()},
    }, indent=1))


if __name__ == "__main__":
    main()
