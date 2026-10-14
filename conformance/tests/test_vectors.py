"""The client library against vectors/vectors.json and the reference encoder."""
import hashlib
import json
import pathlib
import sys
import unittest

CONF = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONF))

from bnap_conf import codec, crypto, offer as of, credential as cr, response as rs, manifest as mf  # noqa: E402
from bnap_conf import http as hp, registry  # noqa: E402
from bnap_conf._ref import ref, REPO_ROOT  # noqa: E402

V = json.loads((REPO_ROOT / "vectors" / "vectors.json").read_text())
REG = registry.default()
ORIGIN = "https://api.example"
BODY = V["http_scope"]["content"].encode()


class ReferenceTest(unittest.TestCase):
    def test_reference_regenerates_vectors(self):
        text = json.dumps(ref.main(), indent=1) + "\n"
        self.assertEqual(text, (REPO_ROOT / "vectors" / "vectors.json").read_text())

    def test_fast_schnorr_matches_reference(self):
        for i in range(8):
            sk = hashlib.sha256(b"k%d" % i).digest()
            msg = hashlib.sha256(b"m%d" % i).digest()
            self.assertEqual(crypto.schnorr_pub(sk), ref.pubkey(sk))
            sig = crypto.schnorr_sign(sk, msg)
            self.assertEqual(sig, crypto.ref_schnorr_sign(sk, msg))
            self.assertTrue(crypto.schnorr_verify(crypto.schnorr_pub(sk), msg, sig))
            self.assertTrue(crypto.ref_schnorr_verify(crypto.schnorr_pub(sk), msg, sig))
            bad = sig[:-1] + bytes([sig[-1] ^ 1])
            self.assertFalse(crypto.schnorr_verify(crypto.schnorr_pub(sk), msg, bad))

    def test_bip340_official_vector_0(self):
        sk = (3).to_bytes(32, "big")
        self.assertEqual(crypto.schnorr_pub(sk).hex().upper(),
                         "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        sig = crypto.schnorr_sign(sk, bytes(32), bytes(32))
        self.assertEqual(sig.hex().upper(),
                         "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                         "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")

    def test_es256_rfc6979_sample(self):
        sk = bytes.fromhex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
        sig = crypto.es256_sign(sk, b"sample")
        self.assertEqual(sig.hex().upper(),
                         "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
                         "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
        x, y = crypto.p256_pub(sk)
        self.assertTrue(crypto.es256_verify(x, y, b"sample", sig))
        self.assertFalse(crypto.es256_verify(x, y, b"other", sig))


class PrimitiveTest(unittest.TestCase):
    def test_tagged_hash(self):
        self.assertEqual(codec.tagged("bnap/offer", b"").hex(), V["tagged_hash"]["out"])

    def test_bigsize_and_tu64(self):
        for n, h in V["bigsize"].items():
            self.assertEqual(codec.bigsize(int(n)).hex(), h)
            self.assertEqual(codec.decode_bigsize(bytes.fromhex(h)), int(n))
        for n, h in V["tu64"].items():
            self.assertEqual(codec.tu64(int(n)).hex(), h)
            self.assertEqual(codec.parse_tu64(bytes.fromhex(h)), int(n))

    def test_http_scopes(self):
        self.assertEqual(hp.action_scope("POST", ORIGIN, "/v1/chat/completions", BODY).hex(),
                         V["http_scope"]["action_scope"])
        self.assertEqual(hp.route_scope(ORIGIN, "chat").hex(), V["http_scope"]["route_scope"])


class OfferTest(unittest.TestCase):
    def test_route_offer(self):
        raw = bytes.fromhex(V["offer"]["bytes"])
        self.assertEqual(len(raw), V["offer"]["len"])
        o = of.parse_offer(raw)
        self.assertEqual(o.offer_id.hex(), V["offer"]["offer_id"])
        self.assertEqual(o.offer_sig.hex(), V["offer"]["offer_sig"])
        self.assertEqual(o.offer_key.hex(), V["offer"]["offer_key"])
        self.assertTrue(of.verify_offer_sig(o))
        self.assertTrue(of.verify_mac(o, [bytes.fromhex(V["offer"]["mac_key"])]))
        self.assertEqual(of.offer_rule_violations(o, REG), [])
        self.assertTrue(o.route_scope and o.metered)
        self.assertEqual([(e.scheme, e.amount, e.unit, e.rate) for e in o.pay], [("bnap:notes", 2100, "sat", 500)])
        self.assertEqual([(a.scheme, a.effect_name, a.value) for a in o.attest],
                         [("httpsig:web-bot-auth", "discount", 2000)])
        self.assertEqual(o.ignored, [3000000001])

    def test_native_invariance(self):
        a = of.parse_offer(bytes.fromhex(V["offer_native"]["without_native"]))
        b = of.parse_offer(bytes.fromhex(V["offer_native"]["with_native"]))
        self.assertEqual(a.offer_id.hex(), V["offer_native"]["offer_id"])
        self.assertEqual(a.offer_id, b.offer_id)
        self.assertNotEqual(a.offer_sig, b.offer_sig)
        self.assertTrue(of.verify_offer_sig(a) and of.verify_offer_sig(b))
        self.assertEqual(b.native[0].kind, "bolt11")

    def test_client_and_gate_checks_accept_the_vector(self):
        raw = bytes.fromhex(V["offer"]["bytes"])
        keys = json.loads(V["manifest"]["jcs"])["keys"]
        act = bytes.fromhex(V["http_scope"]["action_scope"])
        rt = bytes.fromhex(V["http_scope"]["route_scope"])
        chk = of.client_check_offer(raw, now=1791700100, origin=ORIGIN, pin_keys=keys, scope=act, route_scope=rt,
                                    registry=REG)
        self.assertTrue(chk.ok, chk)
        st = of.GateOfferState([bytes.fromhex(V["offer"]["mac_key"])], [bytes.fromhex(V["offer"]["offer_key"])])
        o = of.gate_check_offer(st, now=1791700100, action_scope=act, route_scope=rt, offer_raw=raw,
                                pay_scheme="bnap:notes", attest_schemes=["httpsig:web-bot-auth"])
        self.assertEqual(o.offer_id.hex(), V["offer"]["offer_id"])

    def test_attest_only_offer(self):
        o = of.parse_offer(bytes.fromhex(V["attest_only"]["offer"]))
        self.assertEqual(o.offer_id.hex(), V["attest_only"]["offer_id"])
        self.assertEqual(o.pay, [])
        self.assertTrue(o.has_waive())


class CredentialTest(unittest.TestCase):
    def setUp(self):
        self.offer = bytes.fromhex(V["offer"]["bytes"])
        self.oid = bytes.fromhex(V["offer"]["offer_id"])
        self.act = bytes.fromhex(V["http_scope"]["action_scope"])
        self.wba = b"sig1=:...placeholder web bot auth signature over the Context...:"
        self.y = hashlib.sha256(b"note secret 1").digest()
        self.notes_body = codec.tlv([(0, self.y), (2, b"proofs+outputs placeholder")])
        self.binding = hashlib.sha256(b"tls-exporter placeholder").digest()

    def test_envelope(self):
        c = V["credential"]
        ctx = cr.context(self.oid, self.act, "bnap:notes", ["httpsig:web-bot-auth"], b"")
        self.assertEqual(ctx.hex(), c["context"])
        dg = cr.digest(ctx, self.binding, self.notes_body, [self.wba])
        self.assertEqual(dg.hex(), c["digest"])
        other = cr.digest(ctx, hashlib.sha256(b"other connection").digest(), self.notes_body, [self.wba])
        self.assertEqual(other.hex(), c["digest_other_binding"])
        sk = bytes.fromhex(c["note_sk"])
        self.assertEqual(crypto.schnorr_sign(sk, dg).hex(), c["witness"])
        u1 = cr.use_id("bnap:notes", self.y)
        u2 = cr.use_id("httpsig:web-bot-auth", hashlib.sha256(b"bot key thumbprint").digest())
        self.assertEqual([u1.hex(), u2.hex()], c["use_ids"])
        self.assertEqual(cr.replay_key(ctx, self.notes_body, [self.wba], [u2, u1]).hex(), c["replay_key"])

    def test_credential_bytes_and_parse(self):
        c = V["credential"]
        ctx = cr.context(self.oid, self.act, "bnap:notes", ["httpsig:web-bot-auth"], b"")
        dg = cr.digest(ctx, self.binding, self.notes_body, [self.wba])
        w = crypto.schnorr_sign(bytes.fromhex(c["note_sk"]), dg)
        raw = cr.build_credential(offer=self.offer, pay=cr.SchemeItem("bnap:notes", self.notes_body, w),
                                  attest=[cr.SchemeItem("httpsig:web-bot-auth", self.wba, None)], binding=self.binding)
        self.assertEqual(len(raw), c["bytes_len"])
        p = cr.parse_credential(raw, registry=REG)
        self.assertEqual(cr.credential_envelope(p, of.offer_id_of(p.offer), self.act), (ctx, dg))

    def test_attest_only(self):
        a = V["attest_only"]
        body = b"DPoP proof placeholder with claim bnap_ctx"
        ctx = cr.context(bytes.fromhex(a["offer_id"]), self.act, None, ["httpauth:DPoP"], None)
        self.assertEqual(ctx.hex(), a["context"])
        self.assertEqual(cr.digest(ctx, None, None, [body]).hex(), a["digest"])
        u = cr.use_id("httpauth:DPoP", hashlib.sha256(b"client key thumbprint").digest())
        self.assertEqual(u.hex(), a["use_id"])
        self.assertEqual(cr.replay_key(ctx, None, [body], [u]).hex(), a["replay_key"])

    def test_native_and_rail(self):
        n = V["native"]
        ctx = cr.native_context(bytes.fromhex(V["offer_native"]["offer_id"]), self.act, n["scheme"])
        self.assertEqual(ctx.hex(), n["context"])
        self.assertEqual(cr.native_digest(ctx, n["native_bytes"].encode()).hex(), n["digest"])
        ph = bytes.fromhex(V["rail_id"]["payment_hash"])
        self.assertEqual(ph, hashlib.sha256(b"preimage").digest())
        self.assertEqual(cr.rail_id("ln", cr.canonical_ln(ph)).hex(), V["rail_id"]["rail_id"])


class ResponseAndManifestTest(unittest.TestCase):
    def test_response(self):
        raw = bytes.fromhex(V["response"]["bytes"])
        r = rs.parse_response(raw)
        self.assertTrue(rs.verify_ack(r))
        self.assertEqual(r.ack.hex(), V["response"]["ack"])
        self.assertEqual((r.status, r.charged, r.unit, r.metered_units, r.settled_at), (0, 340, "sat", 850, 1791700042))
        self.assertEqual(r.offer_id.hex(), V["offer"]["offer_id"])
        self.assertEqual(r.digest.hex(), V["credential"]["digest"])
        keys = json.loads(V["manifest"]["jcs"])["keys"]
        chk = rs.client_check_receipt(raw, now=1791700050, pin_keys=keys, digest=r.digest, offer_id=r.offer_id,
                                      has_pay=True, metered=True, expected_charge=340)
        self.assertTrue(chk.ok, chk)
        rebuilt = rs.build_response(status=0, charged=340, unit="sat", offer_id=r.offer_id, digest=r.digest,
                                    metered_units=850, scheme_result=b"change signatures placeholder",
                                    receipt_sk=bytes.fromhex(V["response"]["receipt_sk"]), settled_at=1791700042)
        self.assertEqual(rebuilt, raw)

    def test_manifest(self):
        obj = mf.parse_json_strict(V["manifest"]["jcs"])
        self.assertEqual(mf.jcs(obj).decode(), V["manifest"]["jcs"])
        obj["sig"] = V["manifest"]["sig"]
        self.assertTrue(mf.sig_valid(obj))
        self.assertEqual(mf.document_problems(obj, origin=ORIGIN, now=1791700100), [])
        pin = mf.fetch_accept(mf.jcs(obj), origin=ORIGIN, now=1791700100)
        self.assertEqual(pin.until, 1791700000 + 604800)
        signed = mf.sign_manifest({k: v for k, v in obj.items() if k != "sig"},
                                  bytes.fromhex(V["manifest"]["root_sk"]))
        self.assertEqual(signed["sig"], V["manifest"]["sig"])


if __name__ == "__main__":
    unittest.main()
