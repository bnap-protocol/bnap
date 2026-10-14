"""run.py against mock_gate.py: green when clean, and each injected fault caught."""
import json
import pathlib
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

CONF = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONF))

import mock_gate  # noqa: E402
import run  # noqa: E402


class MutationSelfCheck(unittest.TestCase):
    """The stop condition: clean mock green, every fault detected by its case."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        # Full --max-wait default, so the clean run also exercises the STALE wait.
        cls.ok, cls.rows, cls.results = mock_gate.selftest(cls.tmp.name, with_payer=False, max_wait=None)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_clean_mock_is_green(self):
        clean = self.results[None]
        bad = [(r.case.id, r.detail) for r in clean.results if r.status in ("fail", "error")]
        self.assertEqual(bad, [])
        stale = [r for r in clean.results if r.case.id == "ATT-STALE"][0]
        self.assertEqual(stale.status, "pass", stale.detail)
        skipped = {r.case.id for r in clean.results if r.status == "skip"}
        self.assertLessEqual(skipped, {"MAN-HTTPS", "PAY-L402", "PAY-OFFER-BINDING", "PAY-TWO-SCHEMES", "PAY-MPP",
                                       "PAY-NATIVE", "PAY-METERED", "NOTES-VALUE"})

    def test_each_fault_is_caught_by_its_case(self):
        for fault, case_id in mock_gate.FAULT_CASES.items():
            with self.subTest(fault=fault):
                r = [x for x in self.results[fault].results if x.case.id == case_id][0]
                self.assertEqual(r.status, "fail", f"{case_id} under {fault}: {r.status} {r.detail}")
        self.assertTrue(self.ok, self.rows)

    def test_reports(self):
        out = pathlib.Path(self.tmp.name) / "clean"
        data = json.loads((out / "report.json").read_text())
        self.assertEqual(data["summary"]["must_fail"], 0)
        self.assertEqual(len(data["results"]), len(self.results[None].results))
        root = ET.parse(out / "junit.xml").getroot()
        self.assertEqual(root.tag, "testsuites")
        self.assertTrue(all(s.get("name")[0].isdigit() for s in root))
        page = (out / "report.html").read_text()
        self.assertIn("<title>BNAP conformance report</title>", page)
        self.assertNotIn("\u2014", page)
        faulty = json.loads((pathlib.Path(self.tmp.name) / "bad-ack" / "report.json").read_text())
        self.assertGreater(faulty["summary"]["must_fail"], 0)


class PayerAndProfiles(unittest.TestCase):
    def setUp(self):
        self.gate = mock_gate.MockGate().start()

    def tearDown(self):
        self.gate.stop()

    def test_value_flows_with_the_fake_payer(self):
        rr = run.run(mock_gate.runner_args(self.gate, with_payer=True, extra=["--max-wait", "0"]), quiet=True)
        st = {r.case.id: r for r in rr.results}
        for cid in ("PAY-L402", "PAY-OFFER-BINDING", "PAY-TWO-SCHEMES", "PAY-MPP", "PAY-NATIVE"):
            self.assertEqual(st[cid].status, "pass", f"{cid}: {st[cid].detail}")
        self.assertEqual(st["NOTES-VALUE"].status, "skip")
        self.assertLessEqual(rr.ctx.spent_sat, 200)
        self.assertEqual(rr.must_failures(), [])

    def test_spend_cap(self):
        args = mock_gate.runner_args(self.gate, with_payer=True, extra=["--max-wait", "0", "--only", "PAY-L402"])
        args[args.index("--max-spend-sat") + 1] = "5"
        rr = run.run(args, quiet=True)
        self.assertEqual(rr.results[0].status, "skip")
        self.assertIn("max-spend-sat", rr.results[0].detail)

    def test_client_profile_sends_no_credential(self):
        args = mock_gate.runner_args(self.gate, extra=["--max-wait", "0"])
        args[args.index("--profile") + 1] = "client"
        rr = run.run(args, quiet=True)
        self.assertTrue(rr.results)
        self.assertFalse(any(x.carried_credential for x in rr.ctx.log))
        self.assertEqual([r.case.id for r in rr.results if r.status in ("fail", "error")], [])

    def test_exit_codes(self):
        self.assertEqual(run.main(mock_gate.runner_args(self.gate, extra=["--max-wait", "0", "--only", "MAN-SIG"])), 0)
        bad = mock_gate.MockGate(faults=["bad-ack"]).start()
        try:
            self.assertEqual(run.main(mock_gate.runner_args(bad, extra=["--max-wait", "0", "--only", "RCPT-ACK"])), 1)
        finally:
            bad.stop()
        with self.assertRaises(SystemExit) as cm:
            run.parse_args(["--target", "http://example.test"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
