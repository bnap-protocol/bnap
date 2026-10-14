"""COVERAGE.md maps every normative sentence of draft-00 to existing tests."""
import importlib.util
import pathlib
import unittest

CONF = pathlib.Path(__file__).resolve().parents[1]


class CoverageTest(unittest.TestCase):
    def test_coverage_complete(self):
        spec = importlib.util.spec_from_file_location("coverage_check", CONF / "coverage_check.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        reqs, errors = mod.check()
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(reqs), 48)


if __name__ == "__main__":
    unittest.main()
