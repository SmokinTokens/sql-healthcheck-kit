"""Offline tests for lab/assert-tlog.py (the D09/D10 lab proof gate)."""
import copy
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("assert_tlog", os.path.join(ROOT, "lab", "assert-tlog.py"))
assert _spec is not None and _spec.loader is not None
at = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(at)

GOOD = {"LogSprawl": {"D09": {"rows": [["2531", "158.2"]]}, "D10": {"rows": [["LOG_BACKUP", "FULL"]]}},
        "DemoShop": {"D09": {"rows": []}, "D10": {"rows": [["LOG_BACKUP", "FULL"]]}}}


class AssertTlogTests(unittest.TestCase):
    def run_on(self, db, raw=None):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write(raw if raw is not None else json.dumps({"results": {"server": {}, "db": db}}))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = at.main(p)
        return rc, buf.getvalue()

    def mutate(self, db, cid, value):
        g = copy.deepcopy(GOOD)
        g[db][cid] = value
        return g

    def test_pass(self):
        rc, out = self.run_on(GOOD)
        self.assertEqual(rc, 0, out)
        self.assertIn("LogSprawl 2531 VLFs", out)

    def test_permission_error_fails(self):
        rc, out = self.run_on(self.mutate("LogSprawl", "D09", {"error": "VIEW SERVER STATE permission was denied"}))
        self.assertEqual(rc, 1)
        self.assertIn("D09 errored", out)

    def test_demoshop_error_fails_even_without_assertion(self):
        rc, out = self.run_on(self.mutate("DemoShop", "D10", {"error": "denied"}))
        self.assertEqual(rc, 1)

    def test_count_at_threshold_fails(self):
        rc, _ = self.run_on(self.mutate("LogSprawl", "D09", {"rows": [["1000", "60.0"]]}))
        self.assertEqual(rc, 1)

    def test_missed_vlf_defect_fails(self):
        rc, out = self.run_on(self.mutate("LogSprawl", "D09", {"rows": []}))
        self.assertEqual(rc, 1)
        self.assertIn("more than 1000", out)

    def test_negative_control_flagged_fails(self):
        rc, out = self.run_on(self.mutate("DemoShop", "D09", {"rows": [["1500", "90.0"]]}))
        self.assertEqual(rc, 1)
        self.assertIn("negative control", out)

    def test_wrong_wait_fails(self):
        rc, _ = self.run_on(self.mutate("LogSprawl", "D10", {"rows": [["ACTIVE_TRANSACTION", "FULL"]]}))
        self.assertEqual(rc, 1)

    def test_missing_database_fails(self):
        g = copy.deepcopy(GOOD)
        del g["LogSprawl"]
        rc, out = self.run_on(g)
        self.assertEqual(rc, 1)
        self.assertIn("LogSprawl missing", out)

    def test_malformed_inputs_fail_cleanly(self):
        for raw in ("not json", "[]", '{"results": {"db": []}}', "[" * 100000):
            rc, out = self.run_on(None, raw=raw)
            self.assertEqual(rc, 1, raw[:20])
            self.assertTrue(out.startswith("FAIL:"), out)
        for bad in ({"rows": [["2531"]]}, {"rows": [[2531, "1"]]}, {"rows": "x"}, []):
            rc, _ = self.run_on(self.mutate("LogSprawl", "D09", bad))
            self.assertEqual(rc, 1, bad)


class LabSeedContractTests(unittest.TestCase):
    """Static contract for the D09 seed: loop on the real count, capped, loud, and logged."""

    def read(self, *parts):
        with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
            return f.read()

    def test_seed_loops_on_real_vlf_count_with_cap_and_loud_failure(self):
        sql = self.read("lab", "seed-tlog.sql")
        loop = sql.index("WHILE @vlfs <= 1000 AND @steps < ")
        self.assertIn("sys.dm_db_log_info(DB_ID())", sql[loop:])   # re-measured inside the loop
        self.assertIn("IF @vlfs <= 1000", sql[loop:])
        self.assertIn("THROW 50010", sql[loop:])
        self.assertIn("PRINT CONCAT('seed-tlog: LogSprawl VLF count '", sql[loop:])
        self.assertNotIn("sp_executesql", sql)  # Msg 17750 on BIN2 servers

    def test_run_lab_logs_real_count_before_proof5(self):
        sh = self.read("lab", "run-lab.sh")
        logged = sh.index("ok: LogSprawl VLF count")
        self.assertIn("sys.dm_db_log_info(DB_ID('LogSprawl'))", sh[:logged])
        self.assertLess(logged, sh.index('assert-tlog.py" "$OUT/results.json"'))
        self.assertLess(sh.index("as_sa \"$HERE/seed-tlog.sql\""), logged)


if __name__ == "__main__":
    unittest.main()
