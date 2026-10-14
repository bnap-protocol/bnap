"""COVERAGE.md maps every normative sentence of draft-00 to existing tests."""
import contextlib
import importlib.util
import io
import pathlib
import re
import unittest

CONF = pathlib.Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location("coverage_check", CONF / "coverage_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()

    def test_coverage_complete(self):
        reqs, errors = self.mod.check()
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(reqs), 48)

    def test_status_is_read_from_the_start_of_the_cell(self):
        # A partial row that only mentions the phrase is partial, not untestable.
        row = ["R-9-99", "9", "MUST", '"x"', "", "`MAN-SIG`", "partial: the rest is untestable black-box: no access"]
        self.assertEqual(self.mod.status_of(row), "partial")
        errors = []
        self.mod.check_status("R-9-99", row, False, errors)
        self.assertEqual(len(errors), 1, errors)
        errors = []
        self.mod.check_status("R-9-99", row[:6] + ["untestable black-box"], False, errors)
        self.assertIn("needs a reason", errors[0])
        errors = []
        self.mod.check_status("R-9-99", row[:6] + ["mostly fine"], True, errors)
        self.assertIn("status must start with", errors[0])

    def test_summary_counts_match_the_table(self):
        reqs = self.mod.requirements()
        rows = self.mod.coverage_rows()
        want = {k: sum(1 for r in reqs if rows[r["id"]][6].startswith(k)) for k in self.mod.STATUSES}
        self.assertEqual(sum(want.values()), len(reqs))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.mod.main([]), 0)
        for k, n in want.items():
            self.assertRegex(out.getvalue(), rf"\b{n} {re.escape(k)}\b")


if __name__ == "__main__":
    unittest.main()
