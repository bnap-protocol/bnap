"""The spend path: the strict BOLT 11 decoder, run.py pay() and conformance/payers/lncli-payer.sh.

run.py caps spending against its own decode while the payer parses the invoice on its own, so
these tests craft invoices two decoders could read differently (pico amounts, huge multipliers,
unknown networks, missing amounts, trailing data, bad signatures) and check that none is paid.
"""
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import types
import unittest

CONF = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONF))

import mock_gate  # noqa: E402
import run  # noqa: E402
from bnap_conf import crypto, lightning as ln  # noqa: E402
from bnap_conf.crypto import key_from_label  # noqa: E402

PAYER = CONF / "payers" / "lncli-payer.sh"
FAKE_LNCLI = CONF / "tests" / "fake_lncli.py"
TS = 1791700000
PRE = bytes(range(32))
PH = hashlib.sha256(PRE).digest()
NODE = key_from_label("bnap conformance test node")


def words(b):
    return ln.convertbits(b, 8, 5)


def ts_words(t=TS):
    return [(t >> (5 * (6 - i))) & 31 for i in range(7)]


def craft(hrp, fields=None, *, sk=NODE, tail=(), sig=None):
    """An invoice with the given prefix and tagged fields (default: p and h), signed by sk."""
    if fields is None:
        fields = ln.bolt11_field("p", words(PH)) + ln.bolt11_field("h", words(bytes(32)))
    data = ts_words() + list(fields) + list(tail)
    if sig is not None:
        return ln.bech32_encode(hrp, data + sig)
    return ln.sign_bolt11(hrp, data, sk)


class StrictDecoderTest(unittest.TestCase):
    def test_official_bolt11_vectors(self):
        # The BOLT 11 examples live in fixtures/: real invoices look like secrets to ops/leak-guard.sh.
        vecs = json.loads((CONF / "tests" / "fixtures" / "bolt11.json").read_text())["vectors"]
        self.assertEqual(len(vecs), 2)
        for v in vecs:
            with self.subTest(source=v["source"][:60]):
                d = ln.decode_bolt11(v["invoice"])
                self.assertEqual((d.network, d.amount_msat), (v["network"], v["amount_msat"]))
                self.assertEqual((d.payment_hash.hex(), d.payee.hex()), (v["payment_hash"], v["payee"]))
                self.assertEqual((d.tags["d"], d.tags.get("x")), (v["description"], v["expiry"]))
        self.assertEqual(ln.decode_bolt11(vecs[1]["invoice"]).amount_sat, 250_000)

    def test_own_invoices_round_trip(self):
        inv = ln.encode_bolt11(payment_hash=PH, description_hash=bytes(32), amount_sat=21, timestamp=TS,
                               node_sk=NODE)
        d = ln.decode_bolt11(inv)
        self.assertEqual((d.amount_sat, d.payment_hash, d.payee, d.network), (21, PH, crypto.k1_pub(NODE), "regtest"))
        with_n = craft("lnbcrt210n", ln.bolt11_field("p", words(PH)) + ln.bolt11_field("h", words(bytes(32)))
                       + ln.bolt11_field("n", words(crypto.k1_pub(NODE))))
        self.assertEqual(ln.decode_bolt11(with_n).payee, crypto.k1_pub(NODE))

    def test_amounts(self):
        self.assertEqual(ln.decode_bolt11(craft("lnbcrt10p")).amount_msat, 1)          # one millisatoshi
        self.assertIsNone(ln.decode_bolt11(craft("lnbcrt10p")).amount_sat)             # not a whole sat
        self.assertIsNone(ln.decode_bolt11(craft("lnbcrt19990p")).amount_sat)          # 1,999 msat
        self.assertEqual(ln.decode_bolt11(craft("lnbcrt20000p")).amount_sat, 2)
        self.assertIsNone(ln.decode_bolt11(craft("lnbcrt")).amount_msat)               # no amount
        self.assertEqual(ln.decode_bolt11(craft("lnbc21000000")).amount_msat, ln.MAX_MSAT)
        for hrp, why in (("lnbcrt15p", "p amount not ending in 0"),
                         ("lnbcrt" + "9" * 20 + "m", "huge multiplier"),
                         ("lnbc21000001", "more than 21 million bitcoin"),
                         ("lnbcrt0210n", "leading zero"),
                         ("lnbcrt0n", "zero amount"),
                         ("lnbcrt210k", "unknown multiplier"),
                         ("lnbcrt-210n", "negative amount"),
                         ("lnbcrt+210n", "signed amount"),
                         ("lnbcrt2_10n", "underscore"),
                         ("lnbcrt210nn", "two multipliers")):
            with self.subTest(why=why):
                with self.assertRaises(ValueError):
                    ln.decode_bolt11(craft(hrp))

    def test_networks(self):
        for hrp, net in (("lnbc210n", "bitcoin"), ("lntb210n", "testnet"), ("lntbs210n", "signet"),
                         ("lnbcrt210n", "regtest"), ("lnsb210n", "simnet")):
            self.assertEqual(ln.decode_bolt11(craft(hrp)).network, net)
        for hrp in ("lnxy210n", "lnbcr210n", "lntbx210n", "ln210n", "bc210n", "lnltc210n"):
            with self.subTest(hrp=hrp):
                with self.assertRaises(ValueError):
                    ln.decode_bolt11(craft(hrp))

    def test_structure(self):
        p_, h_ = ln.bolt11_field("p", words(PH)), ln.bolt11_field("h", words(bytes(32)))
        bad = {
            "trailing words after the fields": craft("lnbcrt210n", tail=[0, 0]),
            "a field running into the signature": craft("lnbcrt210n", p_ + h_ + [13, 1, 0]),
            "two p fields": craft("lnbcrt210n", p_ + p_ + h_),
            "a p field of 53 words": craft("lnbcrt210n", ln.bolt11_field("p", words(PH) + [0]) + h_),
            "no p field": craft("lnbcrt210n", h_),
            "neither d nor h": craft("lnbcrt210n", p_),
            "both d and h": craft("lnbcrt210n", p_ + h_ + ln.bolt11_field("d", words(b"x"))),
            "d that is not UTF-8": craft("lnbcrt210n", p_ + ln.bolt11_field("d", words(b"\xff"))),
            "n field of another key": craft("lnbcrt210n", p_ + h_ + ln.bolt11_field(
                "n", words(crypto.k1_pub(key_from_label("someone else"))))),
            "an all-zero signature": craft("lnbcrt210n", sig=[0] * 104),
            "recovery id 4": craft("lnbcrt210n", sig=ln.convertbits(bytes(range(1, 65)) + b"\x04", 8, 5)),
        }
        for why, inv in bad.items():
            with self.subTest(why=why):
                with self.assertRaises(ValueError):
                    ln.decode_bolt11(inv)
        good = craft("lnbcrt210n")
        for why, inv in (("whitespace", " " + good), ("newline", good + "\n"), ("mixed case", good[:5].upper()
                                                                                + good[5:])):
            with self.subTest(why=why):
                with self.assertRaises(ValueError):
                    ln.decode_bolt11(inv)
        self.assertEqual(ln.decode_bolt11(good.upper()).payment_hash, PH)  # one case throughout is fine


def entry(amount, unit="sat"):
    return types.SimpleNamespace(scheme="httpauth:L402", amount=amount, unit=unit)


class PayTest(unittest.TestCase):
    """run.py pay(): what reaches the payer command, and what never does."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.marker = pathlib.Path(self.tmp.name) / "paid"
        self.envfile = pathlib.Path(self.tmp.name) / "env"
        cmd = ("touch %s; printf '%%s %%s' \"$BNAP_EXPECT_AMOUNT_SAT\" \"$BNAP_EXPECT_PAYMENT_HASH\" > %s; echo %s; :"
               % (shlex.quote(str(self.marker)), shlex.quote(str(self.envfile)), PRE.hex()))
        self.ctx = run.Ctx(run.parse_args(["--target", "http://127.0.0.1:9", "--allow-http", "--payer", "cmd:" + cmd,
                                           "--max-spend-sat", "100"]))

    def tearDown(self):
        self.tmp.cleanup()

    def refused(self, inv, ent, exc):
        with self.assertRaises(exc):
            self.ctx.pay(inv, ent)
        self.assertFalse(self.marker.exists(), "the payer ran")
        self.assertEqual(self.ctx.spent_sat, 0)

    def test_exact_amount_is_paid_with_expectations(self):
        self.assertEqual(self.ctx.pay(craft("lnbcrt210n"), entry(21)), PRE)
        self.assertTrue(self.marker.exists())
        self.assertEqual(self.envfile.read_text(), f"21 {PH.hex()}")
        self.assertEqual(self.ctx.spent_sat, 21)

    def test_refusals(self):
        cases = [
            ("1 msat (pico)", craft("lnbcrt10p"), entry(1), run.Fail),
            ("1,999 msat: rounds down to 1 sat", craft("lnbcrt19990p"), entry(1), run.Fail),
            ("more than the offer's entry", craft("lnbcrt220n"), entry(21), run.Fail),
            ("less than the offer's entry", craft("lnbcrt200n"), entry(21), run.Fail),
            ("no amount", craft("lnbcrt"), entry(21), run.Skip),
            ("unknown network", craft("lnxy210n"), entry(21), run.Skip),
            ("huge multiplier", craft("lnbcrt" + "9" * 20 + "m"), entry(21), run.Skip),
            ("p amount not ending in 0", craft("lnbcrt215p"), entry(21), run.Skip),
            ("an all-zero signature", craft("lnbcrt210n", sig=[0] * 104), entry(21), run.Skip),
            ("trailing data", craft("lnbcrt210n", tail=[1]), entry(21), run.Skip),
            ("over --max-spend-sat", craft("lnbcrt2u"), entry(200), run.Skip),
            ("an entry priced in another unit", craft("lnbcrt210n"), entry(21, "usd"), run.Skip),
            ("no invoice at all", None, entry(21), run.Fail),
        ]
        for why, inv, ent, exc in cases:
            with self.subTest(why=why):
                self.refused(inv, ent, exc)


class LncliPayerTest(unittest.TestCase):
    """conformance/payers/lncli-payer.sh against a fake lncli that settles through the mock gate."""

    def setUp(self):
        self.gate = mock_gate.MockGate().start()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = pathlib.Path(self.tmp.name) / "lncli.log"
        self.env = {"LNCLI": f"{shlex.quote(sys.executable)} -I {shlex.quote(str(FAKE_LNCLI))}",
                    "PYTHON": sys.executable, "FAKE_LNCLI_LOG": str(self.log), "FAKE_LNCLI_GATE": self.gate.url}

    def tearDown(self):
        self.gate.stop()
        self.tmp.cleanup()

    def invoice(self):
        """An invoice the mock gate minted, from a 402 of its free route."""
        rr = run.run(mock_gate.runner_args(self.gate, extra=["--max-wait", "0", "--only", "OFR-402"]), quiet=True)
        p = rr.ctx.probe(rr.ctx.route("free"))
        o = next(o for _, o in p.offers if o.pay_entry("httpauth:L402"))
        return next(n.data.decode() for n in o.native if n.kind == "bolt11")

    def payer(self, inv, **env):
        e = dict(os.environ, **self.env)
        e.update(env)
        return subprocess.run(["sh", str(PAYER), inv], capture_output=True, text=True, env=e, timeout=60)

    def test_pays_what_run_py_expects(self):
        inv = self.invoice()
        d = ln.decode_bolt11(inv)
        out = self.payer(inv, BNAP_INVOICE=inv, BNAP_EXPECT_AMOUNT_SAT=str(d.amount_sat),
                         BNAP_EXPECT_PAYMENT_HASH=d.payment_hash.hex())
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(hashlib.sha256(bytes.fromhex(out.stdout.strip())).digest(), d.payment_hash)
        self.assertIn("payinvoice", self.log.read_text())

    def test_refuses_any_mismatch(self):
        inv = self.invoice()
        d = ln.decode_bolt11(inv)
        ok = dict(BNAP_INVOICE=inv, BNAP_EXPECT_AMOUNT_SAT=str(d.amount_sat),
                  BNAP_EXPECT_PAYMENT_HASH=d.payment_hash.hex())
        cases = {
            "run.py expects another amount": dict(ok, BNAP_EXPECT_AMOUNT_SAT=str(d.amount_sat - 1)),
            "run.py expects another payment hash": dict(ok, BNAP_EXPECT_PAYMENT_HASH="00" * 32),
            "lnd reads another amount": dict(ok, FAKE_LNCLI_MSAT=str(d.amount_msat * 1000)),
            "lnd reads a fraction of a sat more": dict(ok, FAKE_LNCLI_MSAT=str(d.amount_msat + 1)),
            "lnd reads another payment hash": dict(ok, FAKE_LNCLI_HASH="11" * 32),
            "no expectations set": {"BNAP_INVOICE": inv},
            "BNAP_INVOICE differs from the argument": dict(ok, BNAP_INVOICE=craft("lnbcrt210n")),
        }
        for why, env in cases.items():
            with self.subTest(why=why):
                self.log.write_text("")
                base = {k: v for k, v in os.environ.items() if not k.startswith(("BNAP_", "FAKE_LNCLI_M",
                                                                                  "FAKE_LNCLI_H"))}
                e = dict(base, **self.env)
                e.update(env)
                out = subprocess.run(["sh", str(PAYER), inv], capture_output=True, text=True, env=e, timeout=60)
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("payinvoice", self.log.read_text(), "paid despite the mismatch")
                self.assertEqual(out.stdout.strip(), "")

    def test_run_py_pays_through_the_wrapper(self):
        cmd = "cmd:sh " + shlex.quote(str(PAYER))
        args = mock_gate.runner_args(self.gate, extra=["--max-wait", "0", "--only", "PAY-L402,PAY-NATIVE"])
        args[args.index("--payer") + 1] = cmd
        saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        try:
            rr = run.run(args, quiet=True)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        st = {r.case.id: r for r in rr.results}
        for cid in ("PAY-L402", "PAY-NATIVE"):
            self.assertEqual(st[cid].status, "pass", f"{cid}: {st[cid].detail}")
        self.assertEqual(self.log.read_text().count("decodepayreq"), 2)


if __name__ == "__main__":
    unittest.main()
