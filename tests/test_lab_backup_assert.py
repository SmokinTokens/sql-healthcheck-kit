"""Offline tests for lab/assert-backup-quality.py (the S26/S27 lab proof gate)."""
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("assert_backup_quality",
                                               os.path.join(ROOT, "lab", "assert-backup-quality.py"))
assert _spec is not None and _spec.loader is not None
ab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ab)

GOOD = {"S26": {"rows": [["DemoShop", "2026-11-25 01:50:00", "no CHECKSUM; "],
                         ["msdb", "2026-11-25 01:50:01", "copy-only fulls only; "]]},
        "S27": {"rows": [["DemoShop", "2026-11-25 01:50:00"], ["master", "2026-11-25 01:50:00"],
                         ["msdb", "2026-11-25 01:50:01"]]}}


class AssertBackupQualityTests(unittest.TestCase):
    def run_on(self, server):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"results": {"server": server, "db": {}}}, f)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ab.main(p)
        return rc, buf.getvalue()

    def test_pass(self):
        rc, out = self.run_on(GOOD)
        self.assertEqual(rc, 0, out)
        self.assertIn("proof:", out)

    def test_permission_error_fails(self):
        rc, out = self.run_on(dict(GOOD, S26={"error": "The SELECT permission was denied"}))
        self.assertEqual(rc, 1)
        self.assertIn("S26 errored", out)

    def test_missing_check_fails(self):
        self.assertEqual(self.run_on({"S26": GOOD["S26"]})[0], 1)

    def test_wrong_judgements_fail(self):
        s26 = GOOD["S26"]["rows"]
        bad = [
            dict(GOOD, S26={"rows": [s26[1]]}),                                  # missed plain DemoShop
            dict(GOOD, S26={"rows": [["DemoShop", "2026-11-25 01:50:00", "no CHECKSUM; copy-only fulls only; "], s26[1]]}),
            dict(GOOD, S26={"rows": s26 + [["master", "2026-11-25 01:50:00", "no CHECKSUM; "]]}),  # CHECKSUM control
            dict(GOOD, S26={"rows": [s26[0]]}),                                  # missed copy-only msdb
            dict(GOOD, S26={"rows": [s26[0], ["msdb", "2026-11-25 01:50:01", "no CHECKSUM; copy-only fulls only; "]]}),
            dict(GOOD, S26={"rows": s26 + [["model", "2026-11-25 01:50:00", "no CHECKSUM; "]]}),
            dict(GOOD, S27={"rows": GOOD["S27"]["rows"][:2]}),
            dict(GOOD, S27={"rows": GOOD["S27"]["rows"] + [["model", "2026-11-25 01:50:00"]]}),
            # Review r1 false accepts:
            dict(GOOD, S26={"rows": [s26[0], ["msdb", "2026-11-25 01:50:01", "DAMAGED (taken despite errors); copy-only fulls only; "]]}),
            dict(GOOD, S26={"rows": [["DemoShop", "2026-11-25 01:50:00", "no CHECKSUM; copy-only fulls only; "]] + s26}),
            dict(GOOD, S26={"rows": s26 + [["tempdb", "2026-11-25 01:50:00", "no CHECKSUM; "]]}),
            dict(GOOD, S27={"rows": GOOD["S27"]["rows"] + [GOOD["S27"]["rows"][0]]}),
            dict(GOOD, S27={"rows": GOOD["S27"]["rows"] + [["tempdb", "2026-11-25 01:50:00"]]}),
            dict(GOOD, S26={"rows": [["DemoShop", "", "no CHECKSUM; "], s26[1]]}),
            dict(GOOD, S27={"rows": [["DemoShop", "2026-11-24 09:00:00"]] + GOOD["S27"]["rows"][1:]}),
        ]
        for server in bad:
            with self.subTest(server=server):
                self.assertEqual(self.run_on(server)[0], 1)

    def test_malformed_input_is_one_fail_line(self):
        documents = [None, [], {}, {"results": []}, {"results": {"server": []}}]
        for cid in ("S26", "S27"):
            for entry in (None, [], {}, {"rows": None}, {"rows": [None]}, {"rows": [["DemoShop"]]},
                          {"rows": [[{}] * 3]}):
                documents.append({"results": {"server": dict(GOOD, **{cid: entry})}})
        for doc in documents:
            with self.subTest(doc=doc), tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "results.json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(doc, f)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = ab.main(p)
                self.assertEqual(rc, 1)
                self.assertEqual(len(buf.getvalue().splitlines()), 1)
                self.assertTrue(buf.getvalue().startswith("FAIL:"))


if __name__ == "__main__":
    unittest.main()
