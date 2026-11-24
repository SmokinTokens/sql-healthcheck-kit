"""LAB ONLY: check that S22/S23 ran as hc_reader and found the planted defects.

Usage: python3 lab/assert-integrity.py OUT_DIR/results.json
Exit 0 = proof holds; 1 = a check errored or missed a planted defect.
"""
import json
import sys


def main(path):
    with open(path, encoding="utf-8") as f:
        server = json.load(f)["results"]["server"]
    bad = []
    for cid in ("S22", "S23"):
        if "error" in server.get(cid, {"error": "missing"}):
            bad.append(f"{cid} errored as hc_reader: {server.get(cid)}")
    if not bad:
        s22 = server["S22"]["rows"]
        if not any(r[0] == "DemoShop" and r[2] == "312" and r[3] == "bad checksum" for r in s22):
            bad.append(f"S22 missed the planted DemoShop page 312: {s22}")
        s23 = {r[0]: r[1] for r in server["S23"]["rows"]}
        if s23.get("DemoShop") != "NEVER":
            bad.append(f"S23 did not flag DemoShop as NEVER: {s23}")
        if "master" in s23:
            bad.append(f"S23 flagged master after a clean CHECKDB: {s23}")
        if "UNKNOWN" in s23.values():
            bad.append(f"S23 returned UNKNOWN on SQL Server 2022: {s23}")
    for b in bad:
        print("FAIL:", b)
    if bad:
        return 1
    print("proof: hc_reader read msdb.dbo.suspect_pages (S22) and LastGoodCheckDbTime (S23); planted defects found")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
