#!/usr/bin/env python3
"""Rechecks the sizes and arithmetic that spec/schemes/bnap-notes-draft-00.md states.

    python3 -I nuts/tools/notes_sizes.py reference/python

Covers the credential sizes of notes section 3.6 and the amounts, prices,
change, signed indices and scheme_result sizes of the vectors of section 18.2,
items 3 and 6. Points, keys and signatures are filled with fixed bytes of the
right length: only sizes and arithmetic are checked here, not the vector bytes.
Every assert holds the number the notes text publishes; a failure means the
text and this script disagree. Standard library only.
"""
import base64
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else "reference/python")
import bnap_ref as r  # noqa: E402

KEYSET_ID = b"\x01" + bytes(32)  # 33 bytes, as notes 3.2 and 3.3 require
POINT = b"\x02" + bytes(32)      # a compressed point, 33 bytes
KEY = bytes(32)                  # an x-only key
SIG = bytes(64)                  # a BIP-340 signature
FEE_PPK = {"A": 100, "B": 0}     # keysets A and B of notes 18.1
GREASE = (3000000001, bytes(8))  # 5-byte type, 1-byte length, 8-byte value: 14 bytes
# The Web Bot Auth attest body of socket draft-00 section 14, a 64-byte placeholder.
WBA_BODY = b"sig1=:...placeholder web bot auth signature over the Context...:"


def body(inputs, n_outputs, fund=None):
    """inputs: list of (keyset label, amount); outputs: the canonical ladder."""
    recs = []
    if inputs:
        recs.append((0, r.entry_list([
            r.tlv([(0, KEYSET_ID), (2, r.tu64(amt)), (4, KEY), (6, POINT)]) for _, amt in inputs])))
    if n_outputs:
        recs.append((2, r.entry_list([
            r.tlv([(0, KEYSET_ID), (2, r.tu64(2 ** i)), (4, POINT)]) for i in range(n_outputs)])))
    if fund is not None:
        recs.append((4, fund))
    return r.tlv(recs)


def witness(n_inputs, fund):
    recs = []
    if n_inputs:
        recs.append((0, SIG * n_inputs))
    if fund:
        recs.append((2, SIG))
    return r.tlv(recs)


def credential(b, w, attest):
    """Names its offer by offer_id and carries a binding and a 14-byte GREASE record."""
    recs = [(0, r.tu64(1)), (4, r.tlv([(0, b"bnap:notes"), (2, b), (4, w)]))]
    if attest:
        recs.append((6, r.entry_list([r.tlv([(0, b"httpsig:web-bot-auth"), (2, WBA_BODY)])])))
    recs += [(8, bytes(32)), (12, bytes(32)), GREASE]
    return r.tlv(recs)


def value(inputs, fund_amount=0):
    i_sum = sum(amt for _, amt in inputs)
    fee = (sum(FEE_PPK[ks] for ks, _ in inputs) + 999) // 1000
    return i_sum + fund_amount - fee


def ladder_outputs(v):
    return v.bit_length()  # notes 6.3: outputs 1, 2, ..., 2^(b-1)


def b64u_len(n):
    return len(base64.urlsafe_b64encode(bytes(n)).rstrip(b"="))


def price(base, discount_verified):
    """Socket draft-00 7 for the notes route offer: one 20% Web Bot Auth discount."""
    return base - base * 2000 // 10000 if discount_verified else base


def select(amounts, change):
    """Notes 7.2."""
    rest, chosen = change, []
    for i in sorted(range(len(amounts)), key=lambda j: (-amounts[j], j)):
        if amounts[i] <= rest:
            chosen.append(i)
            rest -= amounts[i]
    assert rest == 0
    return sorted(chosen)


def scheme_result_len(indices):
    """Notes 7.3: the signatures record, entries written canonically."""
    if not indices:
        return 0
    return len(r.tlv([(0, r.entry_list([
        r.tlv([(0, r.tu64(i)), (2, POINT), (4, bytes(32)), (6, bytes(32))]) for i in indices]))]))


def check_sizes():
    """Notes 3.6."""
    # Entry sizes, length prefix included.
    in1 = len(r.lp(r.tlv([(0, KEYSET_ID), (2, r.tu64(1)), (4, KEY), (6, POINT)])))
    out1 = len(r.lp(r.tlv([(0, KEYSET_ID), (2, r.tu64(1)), (4, POINT)])))
    assert (in1, out1) == (108, 74), (in1, out1)  # 109 and 75 with a 2-byte amount

    # The largest case: 16 inputs on keyset B, 1, 2, ..., 16,384 and a second 16,384.
    big = [("B", 2 ** i) for i in range(15)] + [("B", 16384)]
    assert sum(1 for _, a in big if a < 256) == 8 and len(big) == 16
    i_sum = sum(a for _, a in big)
    assert i_sum == 49151 and value(big) == 49151
    for f in (1, 16384):  # any quote of 1 to 16,384 sat
        v = value(big, f)
        assert 49152 <= v <= 65535 and ladder_outputs(v) == 16
    assert value(big, 16385) == 65536  # one more sat needs a 17th output
    # The earlier example, 1, 2, ..., 32,768 (I = 65,535) plus any quote, cannot fit 16 outputs.
    assert sum(2 ** i for i in range(16)) + 1 > 2 ** 16 - 1
    b = body(big, 16, fund=b"q" * 36)
    w = witness(16, True)
    c = credential(b, w, attest=False)
    assert (len(b), len(w), len(c), b64u_len(len(c))) == (2974, 1094, 4177, 5570)
    # The same credential with a 4,096-byte offer inline instead of offer_id.
    inline = len(c) - len(r.tlv([(12, bytes(32))])) + len(r.tlv([(2, bytes(4096))]))
    assert inline == 8243 and inline <= 9216

    # The 10.3 price, 1,680 sat, needs the verified Web Bot Auth discount: with the attest record.
    attest_rec = len(r.tlv([(6, r.entry_list([r.tlv([(0, b"httpsig:web-bot-auth"), (2, WBA_BODY)])]))]))
    assert attest_rec == 91
    assert price(2100, True) == 1680 and price(2100, False) == 2100
    sizes = {}
    for name, inputs in (("four on B", [("B", 1024), ("B", 512), ("B", 128), ("B", 16)]),
                         ("one 2,048 on B", [("B", 2048)]),
                         ("four on A", [("A", 1024), ("A", 512), ("A", 128), ("A", 16)]),
                         ("one 2,048 on A", [("A", 2048)])):
        v = value(inputs)
        n = ladder_outputs(v)
        c = credential(body(inputs, n), witness(len(inputs), False), attest=True)
        c0 = credential(body(inputs, n), witness(len(inputs), False), attest=False)
        assert len(c) == len(c0) + attest_rec
        sizes[name] = (v, n, len(c), len(c0))
    assert sizes["four on B"] == (1680, 11, 1719, 1628), sizes
    assert sizes["one 2,048 on B"] == (2048, 12, 1271, 1180), sizes
    assert sizes["four on A"][0] == 1679 and 1679 < price(2100, True)  # UNDERPAID
    assert sizes["one 2,048 on A"] == (2047, 11, 1196, 1105), sizes
    assert max(s[2] for s in sizes.values()) < 2048  # under the 2 KiB of draft-00 section 2
    return sizes


def check_vectors():
    """Notes 18.2 items 3 and 6, under the stub verifier of item 3."""
    p = price(2100, True)
    assert p == 1680
    c3a = [("A", 1024), ("B", 1024)]
    c3b = [("B", 1024), ("B", 512), ("B", 128), ("B", 16)]
    v3a, v3b = value(c3a), value(c3b)
    assert (v3a, v3b) == (2047, 1680)
    ladder = [2 ** i for i in range(ladder_outputs(v3a))]
    assert ladder_outputs(v3b) == 11 and sum(ladder) == 2047

    def charged(units):
        return min(price(-(-units * 500 // 1000), True), p)

    # 3a OK, 850 tokens.
    assert -(-850 * 500 // 1000) == 425 and charged(850) == 340
    s = select(ladder, v3a - 340)
    assert v3a - 340 == 1707 and s == [0, 1, 3, 5, 7, 9, 10]
    assert scheme_result_len(s) == 752 == 4 + 106 + 6 * 107
    # 3a FAILED: charged 0, metered_units 0.
    assert charged(0) == 0
    s = select(ladder, v3a)
    assert s == list(range(11)) and scheme_result_len(s) == 1180 == 4 + 106 + 10 * 107
    # 3b OK, 4,200 tokens: charged equals the value, no change.
    assert -(-4200 * 500 // 1000) == 2100 and charged(4200) == 1680 == v3b
    assert select(ladder, 0) == [] and scheme_result_len([]) == 0
    # Without the stub, the placeholder body does not verify and has no effect (draft-00 7):
    # both credentials are below price(amount) = 2,100 and are UNDERPAID.
    assert v3a < price(2100, False) and v3b < price(2100, False)
    # No two-input credential has the value 1,680 on keysets A and B.
    pairs = [(x, y, kx, ky) for x in range(16) for y in range(x, 16) for kx in "AB" for ky in "AB"]
    assert not any(value([(kx, 2 ** x), (ky, 2 ** y)]) == p for x, y, kx, ky in pairs)


def main():
    sizes = check_sizes()
    check_vectors()
    for name, (v, n, with_attest, without) in sizes.items():
        print(f"{name}: value {v}, {n} outputs, {with_attest} bytes with the attest record, "
              f"{without} without")
    print("notes 3.6 and 18.2 items 3 and 6: all numbers hold")


if __name__ == "__main__":
    main()
