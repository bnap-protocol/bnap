"""Edge cases of the strict codecs, the HTTP helpers and the test profiles."""
import json
import pathlib
import sys
import unittest

CONF = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONF))

from bnap_conf import codec, crypto, http as hp, manifest as mf, dpop, lightning as ln, pricing as pr  # noqa: E402
from bnap_conf.codec import BnapError  # noqa: E402


class CodecTest(unittest.TestCase):
    def test_bigsize_roundtrip_edges(self):
        for n in (0, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, (1 << 64) - 1):
            self.assertEqual(codec.decode_bigsize(codec.bigsize(n)), n)
        with self.assertRaises(ValueError):
            codec.bigsize(1 << 64)

    def test_stream_rejects(self):
        for h in ("0100" "0000", "0000" "0000", "0002" "00", "fd00fc00"):
            with self.assertRaises(BnapError):
                codec.parse_stream(bytes.fromhex(h))

    def test_even_odd(self):
        recs = codec.parse_stream(codec.tlv([(0, b""), (5, b"x")]))
        self.assertEqual(codec.check_known(recs, {0}), [5])
        with self.assertRaises(BnapError):
            codec.check_known(codec.parse_stream(codec.tlv([(6, b"")])), {0})
        with self.assertRaises(BnapError):
            codec.check_known(codec.parse_stream(codec.tlv([(241, b"")])), set(), nested=True)

    def test_type_ranges(self):
        self.assertEqual(codec.type_range(239), "socket")
        self.assertEqual(codec.type_range(240), "signature")
        self.assertEqual(codec.type_range(1000), "signature")
        self.assertEqual(codec.type_range(1001), "future")
        self.assertEqual(codec.type_range(1_000_000_000), "experimental")
        self.assertEqual(codec.type_range(3_000_000_001), "grease")
        self.assertEqual(codec.type_range(3_000_000_002), "reserved")

    def test_b64u(self):
        self.assertEqual(codec.b64u_decode("AAEBAgEQ"), bytes.fromhex("000101020110"))
        for bad in ("AA==", "A", "AB", "a+b", "a b"):
            with self.assertRaises(BnapError):
                codec.b64u_decode(bad)

    def test_error_roundtrip(self):
        e = codec.parse_error(codec.build_error("PENDING", retry_after=3))
        self.assertEqual((e.name, e.retry_after), ("PENDING", 3))
        self.assertEqual(codec.http_status_of("RATE_LIMITED"), 429)


class HttpTest(unittest.TestCase):
    def test_challenges(self):
        cs = hp.parse_challenges('BNAP offer="AAEB", L402 macaroon="ab+/=", invoice="lnx", Payment eyJh')
        self.assertEqual([c.scheme for c in cs], ["BNAP", "L402", "Payment"])
        self.assertEqual(cs[0].params["offer"], "AAEB")
        self.assertEqual(cs[1].params, {"macaroon": "ab+/=", "invoice": "lnx"})
        self.assertEqual(cs[2].token68, "eyJh")
        self.assertEqual(hp.parse_challenges('BNAP offer=AAEB_-x')[0].params["offer"], "AAEB_-x")

    def test_sse(self):
        ev = hp.parse_sse(b"data: a\n\nevent: bnap-receipt\ndata: X\n\n: comment\n\n")
        self.assertEqual(ev, [("message", "a"), ("bnap-receipt", "X")])

    def test_listed_headers(self):
        got = hp.listed_headers(["accept", "x-a"], [("Accept", "a"), ("ACCEPT", "b")])
        self.assertEqual(got, [("accept", "a, b"), ("x-a", "")])


class ManifestJsonTest(unittest.TestCase):
    def test_duplicates_at_every_depth(self):
        for text in ('{"a":1,"a":2}', '{"r":[{"p":1,"p":1}]}', '{"a":1,"\\u0061":1}'):
            with self.assertRaises(mf.ManifestReject):
                mf.parse_json_strict(text.encode())

    def test_numbers_and_null(self):
        for text in ('{"a":1.0}', '{"a":1e2}', '{"a":NaN}', '{"a":null}', '{"a":9007199254740993}'):
            with self.assertRaises(mf.ManifestReject):
                mf.parse_json_strict(text.encode())
        self.assertEqual(mf.parse_json_strict(b'{"a":9007199254740992}'), {"a": 9007199254740992})

    def test_jcs(self):
        self.assertEqual(mf.jcs({"b": [1, True], "a": "é\u001f"}), '{"a":"é\\u001f","b":[1,true]}'.encode())


class ProfilesTest(unittest.TestCase):
    def test_dpop_profile(self):
        k = dpop.DpopKey.from_label("conformance test key")
        ctx = bytes(range(32))
        body = dpop.make_body(k, method="GET", htu="https://a.example/x", iat=1000, jti="j", context=ctx)
        v = dpop.verify_body(body, context=ctx, method="GET", htu="https://a.example/x", now=1000)
        self.assertEqual(v.thumbprint, k.thumbprint())
        for kw in ({"context": bytes(32)}, {"method": "POST"}, {"htu": "https://a.example/y"}):
            args = dict(context=ctx, method="GET", htu="https://a.example/x", now=1000)
            args.update(kw)
            with self.assertRaises(dpop.DpopReject):
                dpop.verify_body(body, **args)
        bare = dpop.make_body(k, method="GET", htu="https://a.example/x", iat=1000, jti="j", context=ctx,
                              omit_ctx=True)
        with self.assertRaises(dpop.DpopReject):
            dpop.verify_body(bare, context=ctx, method="GET", htu="https://a.example/x", now=1000)
        with self.assertRaises(BnapError):
            dpop.verify_body(body + b"\x01\x00", context=ctx, method="GET", htu="https://a.example/x", now=1000)
        # Low-S: make_body signs with s <= n/2, and the (r, n - s) copy, a second encoding plain ECDSA
        # accepts, is refused under the profile.
        for i in range(8):
            b_i = dpop.make_body(k, method="GET", htu="https://a.example/x", iat=1000, jti=f"j{i}", context=ctx)
            sig = codec.b64u_decode(codec.parse_stream(b_i)[1].value.decode().rsplit(".", 1)[1])
            self.assertTrue(crypto.es256_is_low_s(sig))
            copy = dpop.other_s_body(b_i)
            self.assertNotEqual(copy, b_i)
            args = dict(context=ctx, method="GET", htu="https://a.example/x", now=1000)
            with self.assertRaises(dpop.DpopReject):
                dpop.verify_body(copy, **args)
            self.assertEqual(dpop.verify_body(copy, low_s=False, **args).thumbprint, k.thumbprint())

    def test_bolt11_and_macaroon(self):
        inv = ln.encode_bolt11(payment_hash=bytes(range(32)), description_hash=bytes(32), amount_sat=21,
                               timestamp=1791700000)
        d = ln.decode_bolt11(inv)
        self.assertEqual((d.amount_sat, d.payment_hash, d.description_hash, d.timestamp),
                         (21, bytes(range(32)), bytes(32), 1791700000))
        mac = ln.mint_macaroon(b"root", b"\x00\x00" + bytes(64), [b"bnap_offer=ab"])
        m = ln.parse_macaroon(mac)
        self.assertTrue(ln.verify_macaroon(b"root", m))
        self.assertFalse(ln.verify_macaroon(b"other", m))
        self.assertEqual((m.caveat_value("bnap_offer"), m.payment_hash), ("ab", bytes(32)))
        tok = ln.l402_token(mac, bytes(32))
        self.assertEqual(ln.parse_l402_token(tok), (mac, bytes(32)))

    def test_no_pay_reading(self):
        """The 7 reading this suite takes for a credential without pay."""
        self.assertFalse(pr.admit([], amount=None).ok)
        self.assertTrue(pr.admit([{"effect": "waive", "verified": True}], amount=None).ok)
        self.assertEqual(pr.admit([{"effect": "discount", "value": 2000, "verified": True}], amount=None).code,
                         "UNDERPAID")


if __name__ == "__main__":
    unittest.main()
