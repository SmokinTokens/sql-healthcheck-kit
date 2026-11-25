"""LAB ONLY: check that S26/S27 ran as hc_reader and judged the planted backups correctly.

lab/seed-demo.sql takes: a plain uncompressed DemoShop full (no CHECKSUM, last), a master
full WITH CHECKSUM, and only a copy-only msdb full WITH CHECKSUM. None is encrypted.

Usage: python3 lab/assert-backup-quality.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = invalid input, a check errored or a planted control failed.
"""
import datetime
import json
import sys

EXPECT_S26 = {"DemoShop": "no CHECKSUM;", "msdb": "copy-only fulls only;"}
EXPECT_S27 = {"DemoShop", "master", "msdb"}


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
    for cid, width in (("S26", 3), ("S27", 2)):
        check = server.get(cid)
        if not isinstance(check, dict):
            print(f"FAIL: {cid} missing or invalid check object")
            return 1
        if "error" in check:
            print(f"FAIL: {cid} errored as hc_reader")
            return 1
        rows = check.get("rows")
        if not isinstance(rows, list) or any(
            not isinstance(row, list) or len(row) != width
            or any(not isinstance(cell, str) for cell in row) for row in rows
        ):
            print(f"FAIL: {cid} expected rows of {width} strings")
            return 1
    for cid in ("S26", "S27"):
        names = [r[0] for r in server[cid]["rows"]]
        if len(names) != len(set(names)):
            print(f"FAIL: {cid} listed a database more than once")
            return 1
        for r in server[cid]["rows"]:
            try:
                datetime.datetime.strptime(r[1], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                print(f"FAIL: {cid} last_full is not a yyyy-mm-dd hh:mm:ss time")
                return 1
    s26 = {r[0]: r[2].strip() for r in server["S26"]["rows"]}
    # Isolated fixture: exactly these rows, exactly these issue labels.
    if s26 != EXPECT_S26:
        print("FAIL: S26 did not list exactly DemoShop 'no CHECKSUM;' and msdb 'copy-only fulls only;' "
              "(master has a regular full WITH CHECKSUM; model has no full)")
        return 1
    s27 = {r[0]: r[1] for r in server["S27"]["rows"]}
    if set(s27) != EXPECT_S27:
        print("FAIL: S27 did not list exactly the unencrypted fulls (DemoShop, master, msdb)")
        return 1
    if any(s27[r[0]] != r[1] for r in server["S26"]["rows"]):
        print("FAIL: S26 and S27 disagree on which full backup is the latest")
        return 1
    print("proof: hc_reader read msdb.dbo.backupset quality columns (S26, S27); plain, "
          "CHECKSUM and copy-only controls judged correctly")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("FAIL: expected one results.json path")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
