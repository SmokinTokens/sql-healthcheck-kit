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

    def test_malformed_input_is_one_fail_line(self):
        documents = [None, [], {}, {"results": []}, {"results": {"server": []}}]
        for cid in ("S22", "S23"):
            for entry in (None, [], {}, {"rows": None}, {"rows": {}},
                          {"rows": [None]}, {"rows": ["DemoShop"]},
                          {"rows": [["DemoShop"]]}, {"rows": [[{}] * 6]}):
                documents.append({"results": {"server": dict(GOOD, **{cid: entry})}})
        documents.append({"results": {"server": dict(GOOD, S22={"error": "line one\nline two"})}})
        for doc in documents:
            with self.subTest(doc=doc), tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "results.json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(doc, f)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = ai.main(p)
                self.assertEqual(rc, 1)
                self.assertEqual(len(buf.getvalue().splitlines()), 1)
                self.assertTrue(buf.getvalue().startswith("FAIL:"))

    def test_unreadable_or_invalid_json_is_one_fail_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            for raw in (None, b"{", b"\xff"):
                if raw is not None:
                    with open(p, "wb") as f:
                        f.write(raw)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = ai.main(p)
                self.assertEqual(rc, 1)
                self.assertEqual(len(buf.getvalue().splitlines()), 1)
                self.assertTrue(buf.getvalue().startswith("FAIL:"))

    def test_deeply_nested_json_is_one_fail_line(self):
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            # Construct valid JSON without using the recursive JSON encoder.
            depth = 1000000
            with open(p, "w", encoding="utf-8") as f:
                f.write("[" * depth + "0" + "]" * depth)
            result = subprocess.run(
                [sys.executable, os.path.join(ROOT, "lab", "assert-integrity.py"), p],
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "FAIL: cannot read results JSON\n")
        self.assertEqual(result.stderr, "")

    def test_shipped_sample_matches_the_lab_seed(self):
        # docs/sample-results.json must show what the seeded lab is expected to produce.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ai.main(os.path.join(ROOT, "docs", "sample-results.json"))
        self.assertEqual(rc, 0, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
