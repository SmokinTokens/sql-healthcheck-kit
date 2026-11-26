"""LAB ONLY: check that S29 ran as hc_reader and judged the planted certificates correctly.

lab/seed-certs.sql plants in master: LabTdeCert (protects TDE database CertTde, private key
never exported), LabBackupCert (encrypted a CertBak backup, exported, expires in 10 days),
and two controls that must NOT be listed: LabSafeCert (encrypted a backup, exported,
expires in 1 year) and LabUnusedCert (never exported, protects nothing).

Usage: python3 lab/assert-certs.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = invalid input, the check errored or a planted control failed.
"""
import datetime
import json
import sys

WIDTH = 6
# certificate -> (tde_databases, last_encrypted_backup is a time?, key exported?, issues)
EXPECT = {
    "LabTdeCert": ("1", False, False, "private key export not recorded;"),
    "LabBackupCert": ("0", True, True, "expires within 30 days: new encrypted backups with it will fail;"),
}


def _is_time(s):
    try:
        datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return True


def main(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, RecursionError):
        print("FAIL: cannot read results JSON")
        return 1
    if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
        print("FAIL: expected results object")
        return 1
    server = data["results"].get("server")
    if not isinstance(server, dict):
        print("FAIL: expected results.server object")
        return 1
    check = server.get("S29")
    if not isinstance(check, dict):
        print("FAIL: S29 missing or invalid check object")
        return 1
    if "error" in check:
        print("FAIL: S29 errored as hc_reader")
        return 1
    rows = check.get("rows")
    if not isinstance(rows, list) or any(
        not isinstance(row, list) or len(row) != WIDTH
        or any(not isinstance(cell, str) for cell in row) for row in rows
    ):
        print(f"FAIL: S29 expected rows of {WIDTH} strings")
        return 1
    names = [r[0] for r in rows]
    if len(names) != len(set(names)):
        print("FAIL: S29 listed a certificate more than once")
        return 1
    if set(names) != set(EXPECT):
        print("FAIL: S29 did not list exactly LabTdeCert and LabBackupCert "
              "(LabSafeCert and LabUnusedCert are negative controls)")
        return 1
    for name, tde, used, exported, expiry, issues in rows:
        want_tde, want_used, want_exported, want_issues = EXPECT[name]
        if tde != want_tde:
            print(f"FAIL: S29 {name} tde_databases is not {want_tde}")
            return 1
        if (_is_time(used) if want_used else used == "NONE") is not True:
            print(f"FAIL: S29 {name} last_encrypted_backup is not " + ("a time" if want_used else "NONE"))
            return 1
        if (_is_time(exported) if want_exported else exported == "NOT RECORDED") is not True:
            print(f"FAIL: S29 {name} key_exported is not " + ("a time" if want_exported else "NOT RECORDED"))
            return 1
        if not _is_time(expiry):
            print(f"FAIL: S29 {name} expiry is not a yyyy-mm-dd hh:mm:ss time")
            return 1
        if issues.strip() != want_issues:
            print(f"FAIL: S29 {name} issues label is wrong")
            return 1
    print("proof: hc_reader read master.sys.certificates, sys.dm_database_encryption_keys and "
          "backupset encryptor_thumbprint (S29): TDE key not exported and expiring backup cert listed, "
          "exported/unused controls not listed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("FAIL: expected one results.json path")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
