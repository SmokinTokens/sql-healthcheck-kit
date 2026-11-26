"""LAB ONLY: check that D11 ran as hc_reader and judged the planted Query Store states.

lab/seed-qs.sql builds QsReadOnly (Query Store READ_ONLY) and sets DemoShop READ_WRITE.
Usage: python3 lab/assert-qs.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = invalid input, a check errored or a planted state was misjudged.
"""
import json
import sys

WIDTH = 6


def _digits(s):
    """1-9 ASCII digits only (str.isdigit() accepts superscripts that int() rejects)."""
    return isinstance(s, str) and 0 < len(s) <= 9 and all(c in "0123456789" for c in s)


def _rows(db_results, db):
    """D11 rows of one database, or an error string."""
    if not isinstance(db_results.get(db), dict):
        return f"{db} missing from results.db (was it checked?)"
    check = db_results[db].get("D11")
    if not isinstance(check, dict):
        return f"D11 missing or invalid in {db}"
    if "error" in check:
        return f"D11 errored as hc_reader in {db}"
    rows = check.get("rows")
    if not isinstance(rows, list) or any(
        not isinstance(row, list) or len(row) != WIDTH
        or any(not isinstance(cell, str) for cell in row) for row in rows
    ):
        return f"D11 expected rows of {WIDTH} strings in {db}"
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
    for db in ("QsReadOnly", "DemoShop"):
        r = _rows(dbr, db)
        if isinstance(r, str):
            print("FAIL: " + r)
            return 1
        got[db] = r
    ro = got["QsReadOnly"]
    if (len(ro) != 1 or ro[0][:2] != ["READ_ONLY", "READ_ONLY"]
            or not all(_digits(ro[0][i]) for i in (2, 4, 5))):
        print("FAIL: D11 did not list QsReadOnly as desired READ_ONLY / actual READ_ONLY")
        return 1
    if got["DemoShop"]:
        print("FAIL: D11 listed DemoShop, whose Query Store is READ_WRITE (negative control)")
        return 1
    print("proof: hc_reader read sys.database_query_store_options (D11: QsReadOnly READ_ONLY listed, "
          "DemoShop READ_WRITE not listed)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("FAIL: expected one results.json path")
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
