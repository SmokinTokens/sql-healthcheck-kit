"""Offline tests for lab/assert-integrity.py (the S22/S23 lab proof gate)."""
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("assert_integrity", os.path.join(ROOT, "lab", "assert-integrity.py"))
assert _spec is not None and _spec.loader is not None
ai = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai)

GOOD = {"S22": {"rows": [["DemoShop", "1", "312", "bad checksum", "3", "2026-11-24 01:00:00"]]},
        "S23": {"rows": [["model", "NEVER"], ["msdb", "NEVER"], ["DemoShop", "NEVER"]]}}


class AssertIntegrityTests(unittest.TestCase):
    def run_on(self, server):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"results": {"server": server, "db": {}}}, f)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ai.main(p)
        return rc, buf.getvalue()

    def test_pass(self):
        rc, out = self.run_on(GOOD)
        self.assertEqual(rc, 0, out)
        self.assertIn("proof:", out)

    def test_permission_error_fails(self):
        rc, out = self.run_on(dict(GOOD, S22={"error": "The SELECT permission was denied"}))
        self.assertEqual(rc, 1)
        self.assertIn("S22 errored", out)

    def test_missing_check_fails(self):
        rc, _ = self.run_on({"S22": GOOD["S22"]})
        self.assertEqual(rc, 1)

    def test_missed_defects_fail(self):
        self.assertEqual(self.run_on(dict(GOOD, S22={"rows": []}))[0], 1)
        self.assertEqual(self.run_on(dict(GOOD, S23={"rows": [["model", "NEVER"]]}))[0], 1)
        self.assertEqual(self.run_on(dict(GOOD, S23={"rows": [["master", "NEVER"], ["DemoShop", "NEVER"]]}))[0], 1)
        self.assertEqual(self.run_on(dict(GOOD, S23={"rows": [["DemoShop", "UNKNOWN"]]}))[0], 1)

    def test_shipped_sample_matches_the_lab_seed(self):
        # docs/sample-results.json must show what the seeded lab is expected to produce.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ai.main(os.path.join(ROOT, "docs", "sample-results.json"))
        self.assertEqual(rc, 0, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
