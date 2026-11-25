"""LAB ONLY: check that D07/D08 ran as hc_reader and found the planted defects.

Usage: python3 lab/assert-security.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = invalid input, a check errored or a planted defect was missed.
"""
import json
import sys

DB = "DemoShop"


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
    dbs = data["results"].get("db")
    if not isinstance(dbs, dict) or not isinstance(dbs.get(DB), dict):
        print(f"FAIL: expected results.db.{DB} object")
        return 1
    for cid in ("D07", "D08"):
        check = dbs[DB].get(cid)
        if not isinstance(check, dict):
            print(f"FAIL: {cid} missing or invalid check object")
            return 1
        if "error" in check:
            print(f"FAIL: {cid} errored as hc_reader")
            return 1
        rows = check.get("rows")
        if not isinstance(rows, list) or any(
            not isinstance(row, list) or len(row) != 2
            or any(not isinstance(cell, str) for cell in row) for row in rows
        ):
            print(f"FAIL: {cid} expected rows of 2 strings")
            return 1
    d07 = dbs[DB]["D07"]["rows"]
    if d07 != [["lab_orphan", "SQL_USER"]]:
        print(f"FAIL: D07 expected only the planted lab_orphan user, got {len(d07)} row(s)")
        return 1
    d08 = dbs[DB]["D08"]["rows"]
    if d08 != [["guest", "GRANT"]]:
        print(f"FAIL: D08 expected one guest GRANT row, got {len(d08)} row(s)")
        return 1
    print("proof: hc_reader found the orphaned user lab_orphan (D07) and guest CONNECT (D08) in DemoShop")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("FAIL: expected one results.json path")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
