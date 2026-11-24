"""LAB ONLY: check that S22/S23 ran as hc_reader and found the planted defects.

Usage: python3 lab/assert-integrity.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = invalid input, a check errored or a planted defect was missed.
"""
import json
import sys


def main(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        print("FAIL: cannot read results JSON")
        return 1
    if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
        print("FAIL: expected results object")
        return 1
    server = data["results"].get("server")
    if not isinstance(server, dict):
        print("FAIL: expected results.server object")
        return 1
    for cid, width in (("S22", 6), ("S23", 2)):
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
    s22 = server["S22"]["rows"]
    if not any(r[0] == "DemoShop" and r[2] == "312" and r[3] == "bad checksum" for r in s22):
        print("FAIL: S22 missed the planted DemoShop page 312")
        return 1
    s23 = {r[0]: r[1] for r in server["S23"]["rows"]}
    if s23.get("DemoShop") != "NEVER":
        print("FAIL: S23 did not flag DemoShop as NEVER")
        return 1
    if "master" in s23:
        print("FAIL: S23 flagged master after a clean CHECKDB")
        return 1
    if "UNKNOWN" in s23.values():
        print("FAIL: S23 returned UNKNOWN on SQL Server 2022")
        return 1
    print("proof: hc_reader read msdb.dbo.suspect_pages (S22) and LastGoodCheckDbTime (S23); planted defects found")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("FAIL: expected one results.json path")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
