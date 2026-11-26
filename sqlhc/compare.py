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
    # S10 has at most one row (principal_id = 1 is always sa, even if renamed): a
    # rename is a changed detail, not a fix plus a new finding. Same for S11.
    "S10": [], "S11": [], "S13": ["database", "table", "equality", "inequality", "include"],
    "D01": ["table"], "D02": ["table", "index_a", "index_b"], "D03": ["table", "narrower_index", "covered_by"],
    "D04": ["table", "constraint"], "D05": ["table", "index"], "S21": ["database", "file"],
    "S22": ["database", "file_id", "page_id"], "S23": ["database"],
    "S24": ["job"], "S25": ["job"], "D07": ["user"], "D08": [],
    # D09/D10 return at most one row per database: a new VLF count or wait reason
    # is a changed detail, not a fix plus a new finding.
    "D09": [], "D10": [],
    # D11: at most one row per database (sys.database_query_store_options), so a state
    # change (OFF -> READ_ONLY) is a changed detail, not a fix plus a new finding.
    "D11": [],
    "S26": ["database"], "S27": ["database"],
    # S29: one row per certificate name (unique in master); counts and dates are details.
    "S29": ["certificate"],
}
# Checks that return only the top N rows. An item missing from a full top-N list may
# just have been ranked out, so it is unknown, not fixed.
CAPPED = {"S13": 10, "S21": 15, "S22": 20, "S24": 20, "S25": 50, "D07": 50}
# System databases are not in the 'dbs' list (database_id <= 4), so a run holds no
# record of their state. master and tempdb cannot be set OFFLINE and the instance does
# not run without them, so they are always covered. model and msdb have no state
# evidence in a run: a vanished row for them is unknown, except in checks that list
# files whatever the database state (S06 reads sys.master_files).
SYSTEM_DBS = {"master", "model", "msdb", "tempdb"}
ALWAYS_ONLINE = {"master", "tempdb"}
STATE_FREE_CHECKS = {"S06"}
# Checks over a time window of history that can also be purged (S24: SQL Agent keeps
# 1,000 rows / 100 per job by default). A row that drops out may only have aged out of
# the window or been deleted, so it is unknown, never fixed.
WINDOWED = {"S24": "after: failure may only have left the 7-day window or been purged from Agent history"}
# S26/S27 judge the latest full in msdb history. A row that drops out may mean a better
# full was taken, or only that history was purged or the database was restored (new
# database_guid). The run cannot tell these apart, so the row is unknown, never fixed.
_BACKUP_HISTORY = "after: backup history may have been purged or the database restored; confirm a new full backup"
WINDOWED.update({"S26": _BACKUP_HISTORY, "S27": _BACKUP_HISTORY})
# S29 also reads msdb history (which certificate encrypted a backup, and when), and its
# expiry issue only counts backups from the last 30 days, so a row can drop out by ageing or
# purging rather than a key export or a new certificate.
WINDOWED["S29"] = ("after: backup history may have been purged or the last encrypted backup left the "
                   "30-day window; confirm the private key export or new certificate")
STATUSES = ("new", "fixed", "changed", "unchanged", "unknown")
# Checks whose row names an unordered pair: (IX_A, IX_B) and (IX_B, IX_A) are the
# same finding. D02 orders the pair by index_id, which a drop/recreate can flip.
UNORDERED_PAIRS = {"D02": ("index_a", "index_b")}


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
    dblist = res["server"].get("DBLIST")
    if "DBLIST" in res["server"] and not (isinstance(dblist, dict) and isinstance(dblist.get("error"), str)):
        raise CompareError(f"{label}: malformed DBLIST entry")
    if not isinstance(data.get("dbs"), list):
        raise CompareError(f"{label}: missing dbs list")
    skipped = data.get("skipped_dbs", [])
    if not isinstance(skipped, list) or not all(isinstance(d, str) for d in skipped):
        raise CompareError(f"{label}: malformed skipped_dbs list")
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
    return [_canon(chk, list(x)) for x in rows], None


def _canon(chk, row):
    """Put an unordered pair in one fixed order, so orientation is not identity."""
    pair = UNORDERED_PAIRS.get(chk["id"])
    if pair:
        i, j = (chk["cols"].index(n) for n in pair)
        if row[j] < row[i]:
            row[i], row[j] = row[j], row[i]
    return row


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


def _dblist_error(data):
    """The run's database-list error text, or None when the list was read."""
    r = data["results"]["server"].get("DBLIST")
    return r["error"] if r else None


def _why_not_fixed(chk, row, before, after, a_rows):
    """Reason a vanished instance-level row cannot count as fixed, or None."""
    db = _db_of(chk, row)
    if db is not None and db in SYSTEM_DBS:
        if db not in ALWAYS_ONLINE and chk["id"] not in STATE_FREE_CHECKS:
            return f"after: no evidence that system database {db} was online"
    elif db is not None:
        if _dblist_error(after) is not None:
            return "after: database list could not be read"
        if db not in after["dbs"]:
            # Offline, no access or skipped name: the after run never looked at it.
            return f"after: database {db} not checked in this run"
    if chk["id"] in WINDOWED:
        return WINDOWED[chk["id"]]
    cap = CAPPED.get(chk["id"])
    if cap is not None and len(a_rows) >= cap:
        return f"after: list is a full top {cap}; the item may only have been ranked out"
    return None


def _capped_why(chk, rows, side):
    """Per-database checks (scope = the database): only the top-N cap can hide a row."""
    cap = CAPPED.get(chk["id"])
    if cap is not None and len(rows) >= cap:
        return f"{side}: list is a full top {cap}; the item may only have been ranked out"
    return None


def _why_not_new(chk, row, before, after, b_rows):
    """Reason an instance-level row absent before cannot count as new, or None."""
    db = _db_of(chk, row)
    if db is not None and db in SYSTEM_DBS:
        # Same rule as for 'fixed': model/msdb may have been OFFLINE in the first run.
        if db not in ALWAYS_ONLINE and chk["id"] not in STATE_FREE_CHECKS:
            return f"before: no evidence that system database {db} was online"
    elif db is not None:
        if _dblist_error(before) is not None:
            return "before: database list could not be read"
        if db not in before["dbs"]:
            # Offline, no access or skipped name in the first run: it may have had
            # this finding already. Absence from the list is not proof of creation.
            return f"before: database {db} not checked in this run"
    cap = CAPPED.get(chk["id"])
    if cap is not None and len(b_rows) >= cap:
        return f"before: list is a full top {cap}; the item may only have been ranked out"
    return None


def open_after(after):
    """Finding rows per severity in the readable checks of the AFTER run alone.

    This does not depend on the before run or on any comparison status: a finding
    the after run shows is open, even when the before side was unreadable (its item
    is 'unknown'). Checks that errored or were not run in AFTER count nothing.
    """
    out = {"high": 0, "medium": 0, "low": 0}
    for chk, is_server in _checks():
        sev = chk.get("severity", "info")
        if sev not in out:
            continue
        for scope in [INSTANCE] if is_server else list(dict.fromkeys(after["dbs"])):
            rows, why = _result(after, chk, is_server, scope)
            if why is None and rows is not None:
                out[sev] += len(rows)
    return out


def compare(before, after):
    items = []
    b_dberr, a_dberr = _dblist_error(before), _dblist_error(after)
    if b_dberr is not None or a_dberr is not None:
        # The database inventory itself is a gap: show it, so that the per-database
        # items below are never read as a complete picture.
        reason = "; ".join(x for x in (b_dberr is not None and "before: database list could not be read: "
                                       + str(b_dberr)[:200],
                                       a_dberr is not None and "after: database list could not be read: "
                                       + str(a_dberr)[:200]) if x)
        items.append({"check": "DBLIST", "title": "User database list", "severity": "high",
                      "area": "Coverage", "scope": INSTANCE, "cols": [], "status": "unknown",
                      "before": None, "after": None, "reason": reason})
    for side, data in (("before", before), ("after", after)):
        # The collector skips databases with unusual or unparsable names: none of
        # their checks ran. Show each one, so the gap is never read as '0 unknown'.
        for name in data.get("skipped_dbs", []):
            items.append({"check": "SKIPPED", "title": "Database skipped by the collector", "severity": "high",
                          "area": "Coverage", "scope": name, "cols": [], "status": "unknown",
                          "before": None, "after": None,
                          "reason": f"{side}: database skipped by the collector (unusual or unparsable "
                                    "name); its checks did not run"})
    for chk, is_server in _checks():
        if chk.get("severity", "info") == "info":
            continue
        scopes = [INSTANCE] if is_server else list(dict.fromkeys(before["dbs"] + after["dbs"]))
        for scope in scopes:
            b_rows, b_why = _result(before, chk, is_server, scope)
            a_rows, a_why = _result(after, chk, is_server, scope)
            if b_why == a_why == NOT_IN_RUN:
                continue  # both runs came from a kit version without this check
            # A database missing from one run's list is unknown on that side (set by
            # _result). The list only holds ONLINE databases the login can open, so
            # absence before does not prove the database was created since: its
            # findings are never 'new'; absence after never makes them 'fixed'.
            if not is_server and scope not in before["dbs"] and b_dberr is not None:
                b_why = "database list could not be read"
            elif not is_server and scope not in after["dbs"] and a_dberr is not None:
                a_why = "database list could not be read"
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
                        why = (_why_not_new(chk, a, before, after, b_rows) if is_server
                               else _capped_why(chk, b_rows, "before"))
                        if why:
                            st, extra = "unknown", {"reason": why}
                        else:
                            st = "new"
                    elif a is None:
                        why = (_why_not_fixed(chk, b, before, after, a_rows) if is_server
                               else _capped_why(chk, a_rows, "after"))
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
    open_by_sev = open_after(after)
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
        L.append("- Not checked in the before run: " + ", ".join(esc(d) for d in added)
                 + " (offline, no access or created since; their items are unknown, not new).")
    L.append("- Matching: by check, scope and the check's key columns. Each finding row is one item.")
    L += ["", "## Summary", "",
          f"**{c['fixed']} fixed, {c['new']} new, {c['changed']} changed, {c['unchanged']} unchanged, "
          f"{c['unknown']} unknown.**", "",
          f"Still open after (finding rows seen in the after run): {o['high']} high, {o['medium']} medium, "
          f"{o['low']} low.", ""]
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
    L += ["", "---", "Generated by sql-healthcheck-kit compare. Uptime-based checks (S13, S21, D05) reset at "
          "restart: a 'fixed' there may only mean the counters were cleared. S24 (failed Agent jobs) "
          "never shows 'fixed': a failure that drops out may only have aged out of the 7-day window."]
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
    for path in (rp, jp):
        # Check both first, so a refusal never leaves a new report next to an old one.
        if os.path.lexists(path):
            print(f"refusing to overwrite {path}", file=sys.stderr)
            return 2
    made = []
    try:
        # UTF-8 always: server text (login, database names) may be any Unicode,
        # whatever the locale of the machine that runs the compare.
        with open(rp, "x", encoding="utf-8") as f:
            made.append(rp)
            f.write(render_markdown(diff))
        with open(jp, "x", encoding="utf-8") as f:
            made.append(jp)
            json.dump(diff, f, indent=1)
    except Exception as e:
        # Created between the check and here, or a write failed (disk full...):
        # remove only what this run made, so no half pair is left behind.
        for path in made:
            try:
                os.remove(path)
            except OSError:
                pass
        if isinstance(e, FileExistsError):
            print(f"refusing to overwrite {e.filename}", file=sys.stderr)
        else:
            print(f"compare failed writing report: {getattr(e, 'strerror', None) or e}", file=sys.stderr)
        return 2
    print(json.dumps({"report": rp, "json": jp, "counts": diff["counts"],
                      "open_by_severity": diff["open_by_severity"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
