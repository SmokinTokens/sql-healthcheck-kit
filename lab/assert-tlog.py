"""LAB ONLY: check that D09/D10 ran as hc_reader and found the planted log defects.

lab/seed-tlog.sql builds LogSprawl (tiny log growth, FULL recovery, no log backup).
Usage: python3 lab/assert-tlog.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = invalid input, a check errored or a planted defect was missed.
"""
import json
import sys

WIDTH = {"D09": 2, "D10": 2}


def _rows(db_results, db, cid):
    """Rows of one check in one database, or an error string."""
    if not isinstance(db_results.get(db), dict):
        return f"{db} missing from results.db (was it checked?)"
    check = db_results[db].get(cid)
    if not isinstance(check, dict):
        return f"{cid} missing or invalid in {db}"
    if "error" in check:
        return f"{cid} errored as hc_reader in {db}"
    rows = check.get("rows")
    if not isinstance(rows, list) or any(
        not isinstance(row, list) or len(row) != WIDTH[cid]
        or any(not isinstance(cell, str) for cell in row) for row in rows
    ):
        return f"{cid} expected rows of {WIDTH[cid]} strings in {db}"
    return rows


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
    dbr = data["results"].get("db")
    if not isinstance(dbr, dict):
        print("FAIL: expected results.db object")
        return 1
    got = {}
    for db in ("LogSprawl", "DemoShop"):
        for cid in ("D09", "D10"):
            r = _rows(dbr, db, cid)
            if isinstance(r, str):
                print("FAIL: " + r)
                return 1
            got[db, cid] = r
    d07 = got["LogSprawl", "D09"]
    if len(d07) != 1 or not d07[0][0].isdigit() or int(d07[0][0]) <= 1000:
        print("FAIL: D09 did not flag LogSprawl with more than 1000 VLFs")
        return 1
    if got["DemoShop", "D09"]:
        print("FAIL: D09 flagged DemoShop, whose log grows in large steps (negative control)")
        return 1
    # DemoShop D10 is not asserted: it is also FULL with no log backup (planted S03 defect),
    # so LOG_BACKUP there is correct too. It only has to run without an error (checked above).
    if got["LogSprawl", "D10"] != [["LOG_BACKUP", "FULL"]]:
        print("FAIL: D10 did not report LOG_BACKUP for LogSprawl")
        return 1
    print(f"proof: hc_reader read sys.dm_db_log_info (D09: LogSprawl {d07[0][0]} VLFs, DemoShop not flagged) "
          "and log_reuse_wait_desc (D10: LogSprawl LOG_BACKUP)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("FAIL: expected one results.json path")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
