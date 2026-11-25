"""Offline tests for lab/assert-security.py (the D07/D08 lab proof gate)."""
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("assert_security", os.path.join(ROOT, "lab", "assert-security.py"))
assert _spec is not None and _spec.loader is not None
asec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(asec)

GOOD = {"D07": {"rows": [["lab_orphan", "SQL_USER"]]}, "D08": {"rows": [["guest", "GRANT"]]}}


class AssertSecurityTests(unittest.TestCase):
    def run_on(self, db, raw=None):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                if raw is not None:
                    f.write(raw)
                else:
                    json.dump({"results": {"server": {}, "db": {"DemoShop": db}}}, f)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = asec.main(p)
        return rc, buf.getvalue()

    def test_pass(self):
        rc, out = self.run_on(GOOD)
        self.assertEqual(rc, 0, out)
        self.assertIn("proof:", out)

    def test_error_fails(self):
        rc, out = self.run_on(dict(GOOD, D07={"error": "The SELECT permission was denied"}))
        self.assertEqual(rc, 1)
        self.assertIn("D07 errored", out)

    def test_missing_orphan_fails(self):
        rc, out = self.run_on(dict(GOOD, D07={"rows": []}))
        self.assertEqual(rc, 1)
        self.assertIn("D07", out)

    def test_extra_orphan_fails(self):
        rc, _ = self.run_on(dict(GOOD, D07={"rows": [["lab_orphan", "SQL_USER"], ["dbo", "SQL_USER"]]}))
        self.assertEqual(rc, 1)

    def test_missing_guest_fails(self):
        rc, out = self.run_on(dict(GOOD, D08={"rows": []}))
        self.assertEqual(rc, 1)
        self.assertIn("D08", out)

    def test_bad_shapes_fail(self):
        for bad in ({"D07": GOOD["D07"]}, dict(GOOD, D08={"rows": [["guest"]]}),
                    dict(GOOD, D08={"rows": [["guest", 1]]}), dict(GOOD, D07="x")):
            rc, _ = self.run_on(bad)
            self.assertEqual(rc, 1, bad)

    def test_garbage_and_deep_json_fail_cleanly(self):
        for raw in ("not json", "[]", "[" * 100000 + "]" * 100000, '{"results": {"db": []}}'):
            rc, out = self.run_on(None, raw=raw)
            self.assertEqual(rc, 1)
            self.assertIn("FAIL", out)


if __name__ == "__main__":
    unittest.main()
