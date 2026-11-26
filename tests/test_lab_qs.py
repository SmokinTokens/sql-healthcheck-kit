"""Offline tests for lab/assert-qs.py (the D11 lab proof gate)."""
import copy
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("assert_qs", os.path.join(ROOT, "lab", "assert-qs.py"))
assert _spec is not None and _spec.loader is not None
aq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aq)

GOOD = {"QsReadOnly": {"D11": {"rows": [["READ_ONLY", "READ_ONLY", "0", "0", "1000"]]}},
        "DemoShop": {"D11": {"rows": []}}}


class AssertQsTests(unittest.TestCase):
    def run_on(self, db, raw=None):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write(raw if raw is not None else json.dumps({"results": {"server": {}, "db": db}}))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = aq.main(p)
        return rc, buf.getvalue()

    def mutate(self, db, value):
        g = copy.deepcopy(GOOD)
        g[db]["D11"] = value
        return g

    def test_pass(self):
        rc, out = self.run_on(GOOD)
        self.assertEqual(rc, 0, out)
        self.assertIn("QsReadOnly READ_ONLY listed", out)

    def test_error_fails(self):
        rc, out = self.run_on(self.mutate("QsReadOnly", {"error": "VIEW DATABASE STATE permission denied"}))
        self.assertEqual(rc, 1)
        self.assertIn("D11 errored", out)

    def test_missed_defect_fails(self):
        rc, out = self.run_on(self.mutate("QsReadOnly", {"rows": []}))
        self.assertEqual(rc, 1)
        self.assertIn("QsReadOnly", out)

    def test_wrong_state_fails(self):
        rc, _ = self.run_on(self.mutate("QsReadOnly", {"rows": [["READ_WRITE", "READ_ONLY", "65536", "1000", "1000"]]}))
        self.assertEqual(rc, 1)

    def test_negative_control_fails(self):
        rc, out = self.run_on(self.mutate("DemoShop", {"rows": [["OFF", "OFF", "0", "0", "1000"]]}))
        self.assertEqual(rc, 1)
        self.assertIn("negative control", out)

    def test_missing_db_fails(self):
        g = copy.deepcopy(GOOD)
        del g["QsReadOnly"]
        rc, out = self.run_on(g)
        self.assertEqual(rc, 1)
        self.assertIn("QsReadOnly missing", out)

    def test_malformed_input_fails_cleanly(self):
        for raw in ("not json", "[]", json.dumps({"results": {"db": []}})):
            rc, out = self.run_on(None, raw=raw)
            self.assertEqual(rc, 1, raw)
            self.assertEqual(len(out.splitlines()), 1, raw)
        for bad in ({"rows": [["READ_ONLY", "READ_ONLY", "\u00b2", "0", "1000"]]},
                    {"rows": [["READ_ONLY", "READ_ONLY", "9" * 5000, "0", "1000"]]},
                    {"rows": [["READ_ONLY", "READ_ONLY", "0", "0"]]},
                    {"rows": [["READ_ONLY", "READ_ONLY", 0, "0", "1000"]]},
                    {"rows": "x"}, "x"):
            rc, out = self.run_on(self.mutate("QsReadOnly", bad))
            self.assertEqual(rc, 1, bad)
            self.assertTrue(out.startswith("FAIL:"), bad)


if __name__ == "__main__":
    unittest.main()
