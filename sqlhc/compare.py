"""Compare two sqlhc results.json runs: a before/after (re-check) report.

Usage: python3 -m sqlhc.compare BEFORE.json AFTER.json [--out DIR]

Each finding row is one item. An item is matched across runs by its check id,
its scope (instance or database) and the check's key columns (for example the
login name, or table + index). Values outside the key (sizes, counts, dates)
may move without making an item new.

Status per item:
  fixed      - in BEFORE, absent in AFTER, and AFTER really ran that check there
  new        - absent in BEFORE, present in AFTER, and BEFORE really ran it there
  unchanged  - in both, same values
  changed    - in both (same key), but some non-key value differs (still open)
  unknown    - the check errored or the database was not checked in one run, so
               the tool cannot say. An error is never reported as a fix.

Read-only: it reads two JSON files and writes two new files. It never connects
to a server. It refuses to overwrite an existing report.
"""
import argparse
import json
import os
import sys

from .checks import DB_CHECKS, SERVER_CHECKS
from .runner import SEV_ORDER, esc

INSTANCE = "(instance)"
NOT_IN_RUN = "check not in this run (older kit version?)"
MAX_INPUT = 64 * 1024 * 1024

# Key columns per check: they say WHICH thing a row is about. Other columns are
# measurements and may change between runs. Unknown check ids use the whole row.
KEY_COLS = {
    "S02": ["database"], "S03": ["database"], "S04": ["database"], "S05": ["database"],
    "S06": ["database", "file"], "S07": ["setting"], "S08": ["login"], "S09": ["login"],
    "S10": ["login"], "S11": [], "S13": ["database", "table", "equality", "inequality", "include"],
    "D01": ["table"], "D02": ["table", "index_a", "index_b"], "D03": ["table", "narrower_index", "covered_by"],
    "D04": ["table", "constraint"], "D05": ["table", "index"], "S21": ["database", "file"],
}
# Checks that return only the top N rows. An item missing from a full top-N list may
# just have been ranked out, so it is unknown, not fixed.
CAPPED = {"S13": 10, "S21": 15}
# System databases are not in the 'dbs' list (database_id <= 4) but always exist.
SYSTEM_DBS = {"master", "model", "msdb", "tempdb"}
STATUSES = ("new", "fixed", "changed", "unchanged", "unknown")


class CompareError(Exception):
    pass


def _checks():
    return [(c, True) for c in SERVER_CHECKS] + [(c, False) for c in DB_CHECKS]


def _validate(data, label):
    if not isinstance(data, dict):
        raise CompareError(f"{label}: not a sqlhc results object")
    res = data.get("results")
    if not isinstance(res, dict) or not isinstance(res.get("server"), dict) or not isinstance(res.get("db"), dict):
        raise CompareError(f"{label}: missing results.server / results.db")
    if not isinstance(data.get("dbs"), list):
        raise CompareError(f"{label}: missing dbs list")
    for db in data["dbs"]:
        if not isinstance(db, str) or not isinstance(res["db"].get(db), dict):
            raise CompareError(f"{label}: database entry missing or malformed")


def load(path, label):
    with open(path, "rb") as f:
        raw = f.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise CompareError(f"{label}: file too large")

    def no_dupes(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise CompareError(f"{label}: duplicate JSON key")
        return dict(pairs)
    def no_constants(name):
        raise CompareError(f"{label}: non-finite number {name}")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes, parse_constant=no_constants)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CompareError(f"{label}: not valid UTF-8 JSON") from None
    _validate(data, label)
    return data


def _result(data, chk, is_server, scope):
    """Return (rows, status) where status is 'ok' or 'unknown' with a reason."""
    res = data["results"]
    if is_server:
        r = res["server"].get(chk["id"])
    else:
        if scope not in data["dbs"]:
            return None, "database not checked in this run"
        r = res["db"][scope].get(chk["id"])
    if r is None:
        return None, NOT_IN_RUN
    if not isinstance(r, dict):
        return None, "result malformed"
    if "error" in r:
        # Partial rows next to an error are not a complete picture: never a basis for 'fixed'.
        return None, "check error: " + str(r["error"])[:200]
    rows = r.get("rows")
    n = len(chk["cols"])
    # Every row must have exactly the check's columns, all strings (as runner writes them).
    # One bad row makes the whole check unknown: partial rows are not complete evidence.
    if not isinstance(rows, list) or not all(
            isinstance(x, list) and len(x) == n and all(isinstance(v, str) for v in x) for x in rows):
        return None, "rows malformed"
    return [list(x) for x in rows], None


def _key(chk, row):
    names = KEY_COLS.get(chk["id"])
    if names is None:
        return tuple(row)
    return tuple(row[chk["cols"].index(n)] for n in names)


def _index(chk, rows):
    out = {}
    for row in rows:
        out.setdefault(_key(chk, row), []).append(row)
    return out


def _pair(bl, al):
    """Pair rows that share one key. Identical rows pair first (order does not
    matter), then the rest pair in sorted order. Returns [(before, after)]."""
    bl, al, pairs = sorted(bl), sorted(al), []
    rest_a = list(al)
    rest_b = []
    for b in bl:
        if b in rest_a:
            rest_a.remove(b)
            pairs.append((b, b))
        else:
            rest_b.append(b)
    for i in range(max(len(rest_b), len(rest_a))):
        pairs.append((rest_b[i] if i < len(rest_b) else None, rest_a[i] if i < len(rest_a) else None))
    return pairs


def _db_of(chk, row):
    if "database" in chk["cols"]:
        return row[chk["cols"].index("database")]
    return None


def _why_not_fixed(chk, row, before, after, a_rows):
    """Reason a vanished instance-level row cannot count as fixed, or None."""
    db = _db_of(chk, row)
    if db is not None and db not in SYSTEM_DBS:
        if "error" in (after["results"]["server"].get("DBLIST") or {}):
            return "after: database list could not be read"
        if db in before["dbs"] and db not in after["dbs"]:
            return f"after: database {db} not checked in this run"
    cap = CAPPED.get(chk["id"])
    if cap is not None and len(a_rows) >= cap:
        return f"after: list is a full top {cap}; the item may only have been ranked out"
    return None


def compare(before, after):
    items = []
    for chk, is_server in _checks():
        if chk.get("severity", "info") == "info":
            continue
        scopes = [INSTANCE] if is_server else list(dict.fromkeys(before["dbs"] + after["dbs"]))
        for scope in scopes:
            b_rows, b_why = _result(before, chk, is_server, scope)
            a_rows, a_why = _result(after, chk, is_server, scope)
            if b_why == a_why == NOT_IN_RUN:
                continue  # both runs came from a kit version without this check
            if not is_server and scope not in before["dbs"] and a_why is None:
                # A database first seen in the after run: its findings were not in the
                # first report, so they are new. (The reverse case stays unknown, never fixed.)
                b_rows, b_why = [], None
            base = {"check": chk["id"], "title": chk["title"], "severity": chk["severity"],
                    "area": chk["area"], "scope": scope, "cols": chk["cols"]}
            if b_why or a_why:
                # Still list what the readable side saw, so nothing silently vanishes.
                # A check-level item is always emitted, so the gap shows in the report.
                reason = "; ".join(x for x in (b_why and "before: " + b_why, a_why and "after: " + a_why) if x)
                seen_before = b_rows is not None
                rows = (b_rows if seen_before else a_rows) or [None]
                for row in rows:
                    items.append(dict(base, status="unknown", before=row if seen_before else None,
                                      after=None if seen_before else row, reason=reason))
                continue
            bi, ai = _index(chk, b_rows), _index(chk, a_rows)
            for key in list(dict.fromkeys(list(bi) + list(ai))):
                for b, a in _pair(bi.get(key, []), ai.get(key, [])):
                    extra = {}
                    if b is None:
                        st = "new"
                    elif a is None:
                        why = _why_not_fixed(chk, b, before, after, a_rows) if is_server else None
                        if why:
                            st, extra = "unknown", {"reason": why}
                        else:
                            st = "fixed"
                    elif a == b:
                        st = "unchanged"
                    else:
                        st = "changed"
                    items.append(dict(base, status=st, before=b, after=a, **extra))
    items.sort(key=lambda x: (STATUSES.index(x["status"]), SEV_ORDER[x["severity"]], x["check"], x["scope"]))
    counts = {s: sum(1 for x in items if x["status"] == s) for s in STATUSES}
    open_by_sev = {s: sum(1 for x in items if x["severity"] == s and x["status"] in ("new", "changed", "unchanged"))
                   for s in ("high", "medium", "low")}
    return {"before": {"started": before.get("started"), "dbs": before["dbs"]},
            "after": {"started": after.get("started"), "dbs": after["dbs"]},
            "counts": counts, "open_by_severity": open_by_sev, "items": items}


def _row_text(chk_cols, row):
    if row is None:
        return "-"
    if len(row) != len(chk_cols):
        return esc(", ".join(row))
    return esc(", ".join(f"{c}={v}" for c, v in zip(chk_cols, row)))


def render_markdown(diff, title="SQL Server Health Check - Re-check comparison"):
    c, o = diff["counts"], diff["open_by_severity"]
    L = [f"# {title}", ""]
    L.append(f"- Before run: {esc(diff['before']['started'])}, {len(diff['before']['dbs'])} user database(s).")
    L.append(f"- After run: {esc(diff['after']['started'])}, {len(diff['after']['dbs'])} user database(s).")
    gone = [d for d in diff["before"]["dbs"] if d not in diff["after"]["dbs"]]
    added = [d for d in diff["after"]["dbs"] if d not in diff["before"]["dbs"]]
    if gone:
        L.append("- Not checked in the after run: " + ", ".join(esc(d) for d in gone) + " (their items are unknown, not fixed).")
    if added:
        L.append("- Only in the after run: " + ", ".join(esc(d) for d in added) + ".")
    L.append("- Matching: by check, scope and the check's key columns. Each finding row is one item.")
    L += ["", "## Summary", "",
          f"**{c['fixed']} fixed, {c['new']} new, {c['changed']} changed, {c['unchanged']} unchanged, "
          f"{c['unknown']} unknown.**", "",
          f"Still open after: {o['high']} high, {o['medium']} medium, {o['low']} low.", ""]
    heads = {"fixed": "Fixed", "new": "New since the first run", "changed": "Still open, details changed",
             "unchanged": "Still open, unchanged", "unknown": "Could not compare (check error or not checked)"}
    for st in STATUSES:
        group = [x for x in diff["items"] if x["status"] == st]
        if not group:
            continue
        L += ["", f"## {heads[st]} ({len(group)})", ""]
        for x in group:
            where = esc(x["scope"])
            line = f"- **{x['severity'].upper()}** {x['check']} {x['title']} - {where}"
            if st == "changed":
                line += f": before {_row_text(x['cols'], x['before'])}; after {_row_text(x['cols'], x['after'])}"
            else:
                row = x["after"] if x["after"] is not None else x["before"]
                line += f": {_row_text(x['cols'], row)}"
            if st == "unknown":
                line += f" ({esc(x['reason'])})"
            L.append(line)
    L += ["", "---", "Generated by sql-healthcheck-kit compare. Uptime-based checks (S13, D05) reset at "
          "restart: a 'fixed' there may only mean the counters were cleared."]
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(prog="sqlhc.compare", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("before", help="results.json from the first run")
    p.add_argument("after", help="results.json from the re-check run")
    p.add_argument("--out", "-o", default="sqlhc-compare", help="output folder (default sqlhc-compare)")
    a = p.parse_args(argv)
    try:
        diff = compare(load(a.before, "before"), load(a.after, "after"))
    except (CompareError, OSError) as e:
        print(f"compare failed: {e}", file=sys.stderr)
        return 2
    os.makedirs(a.out, exist_ok=True)
    rp, jp = os.path.join(a.out, "compare.md"), os.path.join(a.out, "compare.json")
    try:
        with open(rp, "x") as f:
            f.write(render_markdown(diff))
        with open(jp, "x") as f:
            json.dump(diff, f, indent=1)
    except FileExistsError as e:
        print(f"refusing to overwrite {e.filename}", file=sys.stderr)
        return 2
    print(json.dumps({"report": rp, "json": jp, "counts": diff["counts"],
                      "open_by_severity": diff["open_by_severity"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
