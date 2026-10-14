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
        clean = self.results["clean"]
        bad = [(r.case.id, r.detail) for r in clean.results if r.status in ("fail", "error")]
        self.assertEqual(bad, [])
        stale = [r for r in clean.results if r.case.id == "ATT-STALE"][0]
        self.assertEqual(stale.status, "pass", stale.detail)
        skipped = {r.case.id for r in clean.results if r.status == "skip"}
        self.assertLessEqual(skipped, {"MAN-HTTPS", "PAY-L402", "PAY-OFFER-BINDING", "PAY-TWO-SCHEMES", "PAY-MPP",
                                       "PAY-NATIVE", "PAY-METERED", "NOTES-VALUE"})

    def test_clean_without_payer_is_incomplete_not_conformant(self):
        # The value flows and MAN-HTTPS did not run, so the verdict must not be "conformant".
        clean = self.results["clean"]
        self.assertEqual(clean.must_failures(), [])
        self.assertTrue(clean.verdict().startswith("incomplete: "), clean.verdict())
        self.assertEqual(clean.exit_status(), run.EXIT_INCOMPLETE)
        self.assertIn("PAY-L402", {r.case.id for r in clean.must_skips()})

    def test_skipped_must_cases_are_never_conformant(self):
        # A gate that offers no DPoP waive leaves the replay and receipt cases unrun:
        # with no-replay, status-flip and bad-ack it must still not pass as conformant.
        for name, (faults, must) in mock_gate.INCOMPLETE_PLANS.items():
            with self.subTest(plan=name):
                rr = self.results[name]
                self.assertEqual([r.case.id for r in rr.results if r.status in ("fail", "error")], [])
                self.assertTrue(rr.verdict().startswith("incomplete: "), rr.verdict())
                self.assertEqual(rr.exit_status(), run.EXIT_INCOMPLETE)
                self.assertLessEqual(set(must), {r.case.id for r in rr.must_skips()})
                data = json.loads((pathlib.Path(self.tmp.name) / name / "report.json").read_text())
                self.assertEqual(data["exit_status"], run.EXIT_INCOMPLETE)
                self.assertTrue(data["verdict"].startswith("incomplete: "))
                listed = {x["id"] for x in data["must_skipped"]}
                self.assertLessEqual(set(must), listed)
                self.assertEqual(data["summary"]["must_skip"], len(listed))
                page = (pathlib.Path(self.tmp.name) / name / "report.html").read_text()
                self.assertNotIn("conformant for this profile", page)
                self.assertIn("MUST cases not run", page)
                for cid in must:
                    self.assertIn(f"<code>{cid}</code>", page)

    def test_each_fault_is_caught_by_its_case(self):
        for fault, case_id in mock_gate.FAULT_CASES.items():
            with self.subTest(fault=fault):
                rr = self.results[fault]
                r = [x for x in rr.results if x.case.id == case_id][0]
                self.assertEqual(r.status, "fail", f"{case_id} under {fault}: {r.status} {r.detail}")
                self.assertEqual(rr.exit_status(), run.EXIT_FAIL)
                self.assertEqual(rr.verdict(), "not conformant")
        for fault in mock_gate.NO_ROLE_FAULTS:
            with self.subTest(fault=fault, roles=False):
                case_id = mock_gate.FAULT_CASES[fault]
                r = [x for x in self.results[fault + "/no-roles"].results if x.case.id == case_id][0]
                self.assertEqual(r.status, "fail", f"{case_id} under {fault} without roles: {r.status} {r.detail}")
        self.assertTrue(self.ok, self.rows)

    def test_reports(self):
        out = pathlib.Path(self.tmp.name) / "clean"
        data = json.loads((out / "report.json").read_text())
        self.assertEqual(data["summary"]["must_fail"], 0)
        self.assertEqual(len(data["results"]), len(self.results["clean"].results))
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
        # The notes draft-00 text is on develop: the skip names the missing wallet, not a missing spec.
        self.assertTrue(run.notes.available())
        self.assertEqual(st["NOTES-VALUE"].detail, run.notes.SKIP_REASON)
        self.assertIn("not built yet", st["NOTES-VALUE"].detail)
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
        # --only that leaves out MUST cases of the profile is incomplete, never conformant.
        only = mock_gate.runner_args(self.gate, extra=["--max-wait", "0", "--only", "MAN-SIG"])
        self.assertEqual(run.main(only), run.EXIT_INCOMPLETE)
        self.assertEqual(run.main(only + ["--allow-skips"]), 0)
        bad = mock_gate.MockGate(faults=["bad-ack"]).start()
        try:
            self.assertEqual(run.main(mock_gate.runner_args(bad, extra=["--max-wait", "0", "--only", "RCPT-ACK"])), 1)
        finally:
            bad.stop()
        # MAN-HTTPS skips over plain HTTP: a skipped MUST case is exit 3, unless --allow-skips.
        only_skip = mock_gate.runner_args(self.gate, extra=["--max-wait", "0", "--only", "MAN-HTTPS"])
        self.assertEqual(run.main(only_skip), run.EXIT_INCOMPLETE)
        self.assertEqual(run.main(only_skip + ["--allow-skips"]), 0)
        rr = run.run(only_skip + ["--allow-skips"], quiet=True)
        self.assertIn("--allow-skips", rr.verdict())
        with self.assertRaises(SystemExit) as cm:
            run.parse_args(["--target", "http://example.test"])
        self.assertEqual(cm.exception.code, 2)

    def test_only_is_never_conformant(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = mock_gate.runner_args(self.gate, report=tmp, extra=["--max-wait", "0", "--only", "OFR-402,MAN-SIG"])
            rr = run.run(args, quiet=True)
            self.assertEqual([r.status for r in rr.results], ["pass", "pass"])
            self.assertEqual(rr.must_skips(), [])
            profile_must = [c.id for c in run.CASES if "gateway" in c.profiles and c.level == "MUST"]
            left = [c.id for c in rr.must_not_selected()]
            self.assertEqual(sorted(left), sorted(set(profile_must) - {"OFR-402", "MAN-SIG"}))
            self.assertEqual(rr.verdict(), f"incomplete: {len(left)} MUST cases not selected")
            self.assertEqual(rr.exit_status(), run.EXIT_INCOMPLETE)
            data = json.loads((pathlib.Path(tmp) / "report.json").read_text())
            self.assertEqual(data["verdict"], rr.verdict())
            self.assertEqual(data["exit_status"], run.EXIT_INCOMPLETE)
            self.assertEqual(data["only"], "OFR-402,MAN-SIG")
            self.assertEqual(sorted(x["id"] for x in data["must_not_selected"]), sorted(left))
            self.assertEqual(data["summary"]["must_not_selected"], len(left))
            page = (pathlib.Path(tmp) / "report.html").read_text()
            self.assertNotIn("conformant for this profile", page)
            self.assertIn("MUST cases not selected", page)
            self.assertIn("<code>ATT-ADMIT</code>", page)
        # Selecting every MUST case of the profile leaves nothing out.
        everything = ",".join(c.id for c in run.CASES if "client" in c.profiles)
        args = mock_gate.runner_args(self.gate, extra=["--max-wait", "0", "--only", everything])
        args[args.index("--profile") + 1] = "client"
        self.assertEqual(run.run(args, quiet=True).must_not_selected(), [])


if __name__ == "__main__":
    unittest.main()
