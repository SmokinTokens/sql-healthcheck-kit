"""S29: certificates a restore depends on (TDE protector or backup encryptor).

Offline proof only; lab/assert-certs.py is the lab gate for the real SQL.
"""
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sqlhc.checks import SERVER_CHECKS  # noqa: E402
from sqlhc.compare import KEY_COLS, WINDOWED, compare  # noqa: E402
from sqlhc.runner import guard  # noqa: E402
from sqlhc.summary import IMPACT  # noqa: E402

_spec = importlib.util.spec_from_file_location("assert_certs", os.path.join(ROOT, "lab", "assert-certs.py"))
assert _spec is not None and _spec.loader is not None
ac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ac)

S29 = next(c for c in SERVER_CHECKS if c["id"] == "S29")


class S29CheckTests(unittest.TestCase):
    def test_shape_and_guard(self):
        guard(S29["sql"])
        self.assertEqual(S29["severity"], "medium")
        self.assertEqual(S29["area"], "Recoverability")
        self.assertEqual(S29["cols"], ["certificate", "tde_databases", "last_encrypted_backup",
                                       "key_exported", "expiry_utc", "issues"])

    def test_sits_after_s27(self):
        ids = [c["id"] for c in SERVER_CHECKS]
        self.assertEqual(ids[ids.index("S27") + 1], "S29")

    def test_reads_only_expected_sources(self):
        sql = S29["sql"]
        self.assertEqual(set(re.findall(r"\bmsdb\.dbo\.(\w+)", sql)), {"backupset"})
        self.assertEqual(set(re.findall(r"\bsys\.(\w+)", sql)), {"certificates", "dm_database_encryption_keys"})
        self.assertIn("FROM master.sys.certificates c", sql)  # TDE/backup certs live in master
        self.assertNotRegex(sql, r"SELECT\s+\*")
        # No certificate contents, thumbprints or SIDs reach the report.
        select_list = sql.split("FROM master.sys.certificates", 1)[0]
        for col in ("thumbprint", "sid", "subject", "issuer_name", "cert_serial_number"):
            self.assertNotRegex(select_list, r"\bc\." + col + r"\b")

    def test_dependency_by_thumbprint_and_tempdb_excluded(self):
        sql = S29["sql"]
        self.assertIn("k.encryptor_thumbprint = c.thumbprint AND k.database_id <> 2", sql)
        self.assertIn("b.encryptor_thumbprint = c.thumbprint", sql)
        self.assertIn("WHERE (t.n > 0 OR u.last_used IS NOT NULL)", sql)  # unused certs left out

    def test_expiry_only_for_recent_backup_encryption(self):
        # TDE ignores expiry; backup encryption with an expired cert fails (Msg 3096).
        sql = S29["sql"]
        self.assertEqual(sql.count("u.last_used >= DATEADD(day, -30, GETDATE())"), 3)
        self.assertNotIn("t.n > 0 AND c.expiry_date", sql)
        self.assertIn("c.pvt_key_last_backup_date IS NULL", sql)

    def test_expiry_compared_in_utc(self):
        # expiry_date is UTC; backup_finish_date is server-local. Mixing them shifts the
        # EXPIRED label and the 30-day boundary by the server's UTC offset.
        sql = S29["sql"]
        expiry_cmp = re.findall(r"c\.expiry_date\s*<\s*([^\n)]*\)?)", sql)
        self.assertEqual(len(expiry_cmp), 3)
        for rhs in expiry_cmp:
            self.assertIn("GETUTCDATE()", rhs)
        self.assertNotRegex(sql, r"c\.expiry_date\s*<\s*(DATEADD\(day, 30, )?GETDATE\(\)")
        self.assertNotRegex(sql, r"u\.last_used\s*>=\s*DATEADD\(day, -30, GETUTCDATE\(\)\)")

    def test_advice_never_destructive(self):
        fix = S29["fix"]
        self.assertTrue(fix.startswith("Do not drop, replace or renew a listed certificate in place"))
        self.assertIn("a copy may still exist", fix)
        self.assertIn("first ask the owner", fix)
        self.assertIn("BACKUP CERTIFICATE ... TO FILE ... WITH PRIVATE KEY", fix)
        self.assertIn("access-controlled copies of both files off this server", fix)
        self.assertIn("away from the database backups", fix)
        self.assertIn("TDE ignores the date", fix)
        self.assertIn("keep the old certificate for as long as any backup taken with it is kept", fix)
        # Ask-first comes before the backup command.
        self.assertLess(fix.index("first ask the owner"), fix.index("back them up now"))
        for bad in ("DROP CERTIFICATE", "ALTER DATABASE ENCRYPTION KEY", "SET ENCRYPTION OFF"):
            self.assertNotIn(bad, fix)

    def test_impact_hedged(self):
        text = IMPACT["S29"]
        self.assertIn("no recorded private-key export", text)
        self.assertIn("expiry blocks new encrypted backups but not restores", text)
        self.assertNotIn("never been backed up", text)
        self.assertNotIn("an expiry that blocks", text)  # expiring is not yet blocking

    def test_compare_keys_and_vanish_is_unknown(self):
        self.assertEqual(KEY_COLS["S29"], ["certificate"])
        self.assertIn("30-day window", WINDOWED["S29"])

        def run(rows):
            server = {c["id"]: {"rows": []} for c in SERVER_CHECKS}
            server["S29"] = {"rows": rows}
            return {"tool": "sqlhc", "version": "x", "server": "lab", "started": "2026-11-26 01:00:00",
                    "secs": 1, "dbs": [], "skipped_dbs": [], "results": {"server": server, "db": {}},
                    "full_query_text": False}

        row = ["LabTdeCert", "1", "NONE", "NOT RECORDED", "2027-11-26 00:00:00", "private key export not recorded; "]
        items = [x for x in compare(run([row]), run([]))["items"] if x["check"] == "S29"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["status"], "unknown")


GOOD = {"S29": {"rows": [
    ["LabTdeCert", "1", "NONE", "NOT RECORDED", "2027-11-26 01:00:00", "private key export not recorded; "],
    ["LabBackupCert", "0", "2026-11-26 01:00:00", "2026-11-26 00:59:00", "2026-12-06 00:00:00",
     "expires within 30 days: new encrypted backups with it will fail; "],
]}}


class AssertCertsTests(unittest.TestCase):
    def run_on(self, server):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"results": {"server": server, "db": {}}}, f)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ac.main(p)
        return rc, buf.getvalue()

    def test_pass(self):
        rc, out = self.run_on(GOOD)
        self.assertEqual(rc, 0, out)
        self.assertIn("proof:", out)

    def test_error_and_missing_fail(self):
        self.assertEqual(self.run_on({"S29": {"error": "permission denied"}})[0], 1)
        self.assertEqual(self.run_on({})[0], 1)

    def test_bad_inputs_fail(self):
        tde, bak = GOOD["S29"]["rows"]
        safe = ["LabSafeCert", "0", "2026-11-26 01:00:01", "2026-11-26 00:59:00", "2027-11-26 00:00:00", ""]
        unused = ["LabUnusedCert", "0", "NONE", "NOT RECORDED", "2027-11-26 00:00:00", "private key export not recorded; "]
        cases = [
            [tde],                                          # missed expiring backup cert
            [bak],                                          # missed unexported TDE cert
            [tde, bak, safe],                               # negative control listed
            [tde, bak, unused],                             # unused cert listed
            [tde, bak, tde],                                # duplicate
            [tde[:1] + ["0"] + tde[2:], bak],               # TDE count wrong
            [tde[:3] + ["2026-11-26 00:00:00"] + tde[4:], bak],  # export recorded on TDE cert
            [tde, bak[:2] + ["NONE"] + bak[3:]],            # backup use missing
            [tde, bak[:4] + ["soon"] + bak[5:]],            # expiry not a time
            [tde, bak[:5] + ["EXPIRED: new encrypted backups with it fail; "]],  # wrong label
            [tde[:5], bak],                                 # wrong width
            [tde[:5] + [5], bak],                           # non-string cell
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                self.assertEqual(self.run_on({"S29": {"rows": rows}})[0], 1)

    def test_unreadable_json_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "results.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{not json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(ac.main(p), 1)


class SeedCertsTests(unittest.TestCase):
    """The seed plants exactly the controls the gate expects, with no literal secrets."""

    def setUp(self):
        with open(os.path.join(ROOT, "lab", "seed-certs.sql"), encoding="utf-8") as f:
            self.sql = f.read()

    def test_controls_planted(self):
        for name in ("LabTdeCert", "LabBackupCert", "LabSafeCert", "LabUnusedCert"):
            self.assertIn("CREATE CERTIFICATE " + name, self.sql)
        self.assertIn("BACKUP CERTIFICATE LabBackupCert", self.sql)
        self.assertIn("BACKUP CERTIFICATE LabSafeCert", self.sql)
        self.assertNotIn("BACKUP CERTIFICATE LabTdeCert", self.sql)
        self.assertNotIn("BACKUP CERTIFICATE LabUnusedCert", self.sql)
        self.assertIn("ENCRYPTION BY SERVER CERTIFICATE LabTdeCert", self.sql)
        self.assertIn("SERVER CERTIFICATE = LabBackupCert", self.sql)
        self.assertIn("DATEADD(day, 10, GETUTCDATE())", self.sql)

    def test_no_literal_passwords(self):
        for m in re.finditer(r"PASSWORD\s*=\s*N?'([^']*)'", self.sql):
            self.assertEqual(m.group(1), "$(HC_PW)")

    def test_wired_into_lab(self):
        with open(os.path.join(ROOT, "lab", "run-lab.sh"), encoding="utf-8") as f:
            sh = f.read()
        self.assertLess(sh.index('as_sa "$HERE/seed-certs.sql"'), sh.index('as_sa "$ROOT/sql/grant-reader.sql"'))
        self.assertIn('python3 "$HERE/assert-certs.py" "$OUT/results.json"', sh)


if __name__ == "__main__":
    unittest.main()
