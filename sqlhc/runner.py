"""Run the read-only checks with sqlcmd and write a Markdown report, an HTML report and JSON.

The password is never taken on the command line. For SQL logins, set it in the
environment variable SQLCMDPASSWORD (sqlcmd reads it there). For Windows
authentication use --windows-auth.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

from .checks import DB_CHECKS, DB_PRIV_PROBE, PRIV_PROBE, PROBE_SYSTEM_DBS, SERVER_CHECKS, TOO_POWERFUL
from .redact import redact

SEP = "\x1f"
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
# A keyword starts where no letter, '_', '@', '#' or '$' comes before it. A digit
# may come before it: T-SQL reads 'SELECT 1DROP TABLE t' as '1' then 'DROP'.
_KW_START = r"(?<![A-Za-z_@#$])"
FORBIDDEN = re.compile(
    _KW_START +
    r"(INSERT|UPDATE|DELETE|MERGE|ALTER|DROP|CREATE|TRUNCATE|EXEC|EXECUTE|DBCC|GRANT|REVOKE|DENY|"
    r"BACKUP|RESTORE|SHUTDOWN|KILL|RECONFIGURE|OPENROWSET|OPENQUERY|OPENDATASOURCE|OPENXML|BULK|INTO|"
    r"WAITFOR|USE|GO|CHECKPOINT|WRITETEXT|UPDATETEXT|READTEXT|RECEIVE|SEND|ENABLE|DISABLE|RAISERROR|THROW|"
    r"PRINT|BEGIN|COMMIT|ROLLBACK|SAVE|TRAN|TRANSACTION|DECLARE|SET|IF|WHILE|GOTO|RETURN|OPEN|FETCH|CLOSE|"
    r"DEALLOCATE|NEXT|SETUSER|REVERT|TABLOCKX|XLOCK|UPDLOCK|HOLDLOCK)\b"
    r"|" + _KW_START + r"(xp_|sp_)|;|--|/\*|\*/|\$\(|^\s*[:!]", re.I | re.M)
# Quoted runs, blanked before the deny-list: 'string' / N'string', [bracketed name], "quoted name".
# One left-to-right pass, so a quote inside [..] or ".." cannot start a fake string literal.
_QUOTED = re.compile(r"N?'(?:[^'\n]|'')*'|\[(?:[^\]\n]|\]\])*\]|\"(?:[^\"\n]|\"\")*\"")
DB_NAME_OK = re.compile(r"^[A-Za-z0-9_\-. $]{1,128}$")


class GuardError(Exception):
    pass


def guard(sql):
    """Refuse anything that is not one plain SELECT (or ;WITH ... SELECT).

    Defence in depth only: every shipped query is hard-coded, and the server-side
    least-privilege login is the real boundary. The guard is an allow-list shape
    check plus a deny-list: no comments, no ';' after the start, no sqlcmd
    commands (':' or '!' at a line start, $(var)), no GO, and no write, exec,
    transaction, lock or control-flow keyword anywhere outside string literals.
    """
    body = sql.lstrip()
    if body.startswith(";"):
        body = body[1:].lstrip()
    if not re.match(r"(SELECT|WITH)\b", body, re.I):
        raise GuardError(f"not a SELECT: {body[:40]!r}")
    blanked = _QUOTED.sub("''", body)
    if re.search(r"['\"\[\]]", blanked.replace("''", "")):
        raise GuardError("unbalanced or multi-line quote, bracket or string literal")
    # Literals (wait-type names etc.) and quoted names are blanked, then nothing forbidden
    # may remain. Comment markers are forbidden outright, so a comment cannot desync this.
    m = FORBIDDEN.search(blanked)
    if m:
        raise GuardError(f"forbidden token {m.group(0)!r}")


class Sqlcmd:
    def __init__(self, server, user=None, windows_auth=False, trust_cert=False, docker=None,
                 sqlcmd="sqlcmd", timeout=120, docker_cmd="docker"):
        if not windows_auth and not user:
            raise SystemExit("give --user (password in SQLCMDPASSWORD) or --windows-auth")
        if not windows_auth and not os.environ.get("SQLCMDPASSWORD"):
            raise SystemExit("SQLCMDPASSWORD is not set; the password is never read from arguments")
        self.timeout = timeout
        base = [sqlcmd, "-S", server]
        base += ["-E"] if windows_auth else ["-U", user]
        if trust_cert:
            base.append("-C")
        if docker:
            # 'docker exec -e NAME' copies the value from this process's environment: no value on argv.
            base = docker_cmd.split() + ["exec", "-i", "-e", "SQLCMDPASSWORD", docker] + base
        elif not shutil.which(sqlcmd):
            raise SystemExit(f"{sqlcmd} not found (install mssql-tools18 or pass --sqlcmd PATH)")
        self.base = base

    def query(self, sql, db="master"):
        guard(sql)
        if not DB_NAME_OK.match(db):
            return 1, "", f"database name refused: {db!r}"
        cmd = self.base + ["-d", db, "-b", "-X1", "-x", "-W", "-h", "-1", "-s", SEP, "-i", "/dev/stdin"]
        # NOCOUNT stays OFF: sqlcmd's own "(N rows affected)" line lets rows_of() spot
        # a name with a line break that tries to fake an extra row.
        r = subprocess.run(cmd, input=sql + "\nGO\n", capture_output=True,
                           text=True, timeout=self.timeout)
        return r.returncode, r.stdout, r.stderr


_ROWCOUNT = re.compile(r"^\((\d+) rows? affected\)$")


def rows_of(out, ncols, dropped=None):
    """Split sqlcmd output into rows.

    Lines with the wrong column count (for example a name that holds a newline) are not
    silently lost: they are counted in dropped[0]. sqlcmd prints "(N rows affected)" as
    its LAST line, after all server text, so a name cannot fake it. If the number of
    output lines differs from N, a value held a line break: then no row is trusted
    and every line counts as dropped."""
    # Informational server messages ("Warning: Null value is eliminated ...") are not rows.
    # A forged "Warning:" line is skipped too, so it can never become a trusted row.
    lines = [ln for ln in out.splitlines() if ln.strip() and not
             (ln.startswith("Warning: ") and SEP not in ln)]
    expected = None
    last = _ROWCOUNT.match(lines[-1].strip()) if lines else None
    if last:
        expected = int(last.group(1))
        lines = lines[:-1]
    if expected is not None and len(lines) != expected:
        if dropped is not None:
            dropped[0] += max(len(lines), 1)
        return []
    rows = []
    for line in lines:
        parts = [p.strip() for p in line.split(SEP)]
        if len(parts) == ncols:
            rows.append(parts)
        elif dropped is not None:
            dropped[0] += 1
    return rows


def run_check(conn, chk, db, full_text=False):
    rc, out, err = conn.query(chk["sql"], db)
    if rc:
        # Error text can echo server details; keep only the first line, capped.
        first = ((err or out).strip().splitlines() or ["error"])[0]
        return {"error": first[:200]}
    dropped = [0]
    rows = rows_of(out, len(chk["cols"]), dropped)
    col = chk.get("redact_col")
    if col is not None and not full_text:
        for r in rows:
            r[col] = redact(r[col])
    if dropped[0]:
        # Rows were seen but could not be parsed: report it, never hide it.
        return {"rows": rows, "error": f"{dropped[0]} output line(s) could not be parsed (odd characters in a name?)"}
    return {"rows": rows}


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~>-])")
# Bidi controls can make a name read differently from its real bytes ("Trojan Source").
_BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_WORD_JOINER = "\u2060"


def esc(v):
    """Make server-supplied text inert in Markdown and in HTML renderers.

    Names (databases, logins, indexes) and query text come from the target server,
    and anyone who can name an object controls them. Flatten control characters,
    show bidi controls as U+FFFD, HTML-escape &, <, >, backslash-escape Markdown
    punctuation, and break GitHub autolinks: the ':' of '://' and the dot of 'www.'
    become character references, and an invisible word joiner follows each e-mail
    style '@' (which also stops mailto: and xmpp: links). Times like 10:00 and SQL
    variables like @x stay as they are.
    """
    v = str(v)
    v = re.sub(r"[\x00-\x1f\x7f]", " ", v)
    v = _BIDI.sub("\ufffd", v)
    v = v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    v = _MD_SPECIAL.sub(r"\\\1", v)
    # After the Markdown pass, so the '#' of these references is not backslash-escaped.
    v = re.sub(r":(?=//)", "&#58;", v)
    # Only an '@' right after an e-mail local-part character: '@var' in query text stays clean.
    v = re.sub(r"(?<=[A-Za-z0-9._%+\-])@", "@" + _WORD_JOINER, v)
    return re.sub(r"(?i)(www)\.", r"\1&#46;", v)


def md_table(cols, rows, limit=15):
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows[:limit]:
        lines.append("| " + " | ".join(esc(v) for v in r) + " |")
    if len(rows) > limit:
        lines.append(f"| ... {len(rows) - limit} more |" + " |" * (len(cols) - 1))
    return "\n".join(lines)


def db_probe(conn, db):
    """Return the write-capable roles/permissions the login has in one database ([] = fine).
    Fails closed: an unreadable probe counts as powerful."""
    rc, out, err = conn.query(DB_PRIV_PROBE["sql"], db)
    rows = rows_of(out, len(DB_PRIV_PROBE["cols"])) if not rc else []
    if not rows or any(v not in ("0", "1") for v in rows[0]):
        return ["probe failed"]
    return [k for k, v in zip(DB_PRIV_PROBE["cols"], rows[0]) if v == "1"]


def collect(conn, full_text=False, allow_powerful=False):
    rc, out, err = conn.query(PRIV_PROBE["sql"])
    if rc:
        raise SystemExit("could not connect or run the privilege probe: " +
                         ((err or out).strip().splitlines() or ["?"])[0][:200])
    probe_rows = rows_of(out, len(PRIV_PROBE["cols"]))
    if not probe_rows or any(v not in ("0", "1") for v in probe_rows[0]):
        # Fail closed: an unreadable probe must never count as "not powerful".
        raise SystemExit("privilege probe returned no usable row; refusing to run")
    probe = dict(zip(PRIV_PROBE["cols"], probe_rows[0]))
    powerful = [k for k in TOO_POWERFUL if probe.get(k) == "1"]
    if powerful and not allow_powerful:
        raise SystemExit("refusing to run: login holds " + ", ".join(powerful) +
                         ". Use a least-privilege login (sql/grant-reader.sql) or pass --allow-powerful-login.")

    started = datetime.datetime.now()
    results = {"server": {}, "db": {}}
    for chk in SERVER_CHECKS:
        results["server"][chk["id"]] = run_check(conn, chk, "master", full_text)
    rc, out, err = conn.query(
        "SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0 AND HAS_DBACCESS(name) = 1")
    if rc:
        results["server"]["DBLIST"] = {"error": ((err or out).strip().splitlines() or ["error"])[0][:200]}
    dropped = [0]
    dbs = [r[0] for r in rows_of(out, 1, dropped)] if not rc else []
    skipped = [d for d in dbs if not DB_NAME_OK.match(d)]
    skipped += ["(unparsable name)"] * dropped[0]
    dbs = [d for d in dbs if DB_NAME_OK.match(d)]
    db_powerful = {}
    for db in list(PROBE_SYSTEM_DBS) + dbs:
        dp = db_probe(conn, db)
        if dp:
            db_powerful[db] = dp
    if db_powerful and not allow_powerful:
        raise SystemExit("refusing to run: login can change " + "; ".join(
            f"{d} ({', '.join(p)})" for d, p in db_powerful.items()) +
            ". Use a least-privilege login (sql/grant-reader.sql) or pass --allow-powerful-login.")
    for db in dbs:
        results["db"][db] = {chk["id"]: run_check(conn, chk, db, full_text) for chk in DB_CHECKS}
    secs = (datetime.datetime.now() - started).total_seconds()
    return {"started": started.isoformat(timespec="seconds"), "secs": round(secs, 1), "probe": probe,
            "powerful": powerful, "dbs": dbs, "skipped_dbs": skipped, "results": results,
            "full_query_text": full_text}


def findings_of(data):
    res, out = data["results"], []
    for chk in SERVER_CHECKS:
        r = res["server"][chk["id"]]
        if chk.get("severity", "info") != "info" and r.get("rows"):
            out.append((chk, "(instance)", r["rows"]))
    for db in data["dbs"]:
        for chk in DB_CHECKS:
            r = res["db"][db][chk["id"]]
            if chk.get("severity", "info") != "info" and r.get("rows"):
                out.append((chk, db, r["rows"]))
    out.sort(key=lambda f: (SEV_ORDER[f[0]["severity"]], f[0]["id"]))
    return out


def errors_of(data):
    res = data["results"]
    errs = [(cid, r["error"]) for cid, r in res["server"].items() if "error" in r]
    errs += [(f"{db}/{cid}", r["error"]) for db in data["dbs"] for cid, r in res["db"][db].items() if "error" in r]
    return errs


def render_markdown(data, title="SQL Server Health Check"):
    res = data["results"]
    findings = findings_of(data)
    errors = errors_of(data)
    inv = (res["server"]["S01"].get("rows") or [["?"] * 6])[0]
    counts = {s: sum(1 for f in findings if f[0]["severity"] == s) for s in ("high", "medium", "low")}
    autoclose = [r[0] for r in res["server"]["S04"].get("rows", []) if "AUTO_CLOSE ON" in r[1]]
    L = [f"# {title}", ""]
    L.append(f"- Run: {data['started']}, {data['secs']} s, {len(SERVER_CHECKS)} instance checks + "
             f"{len(DB_CHECKS)} per-database checks over {len(data['dbs'])} user database(s).")
    L.append("- Server: SQL Server " + esc(f"{inv[0]} {inv[1]}, {inv[2]}, {inv[3]} CPUs, {inv[4]} MB RAM, up {inv[5]} h."))
    L.append("- Access: catalog views and DMVs only, sent as SELECT statements. No user table rows read; "
             "no data or settings changed.")
    L.append("- Query text: " + ("FULL (opt-in)." if data["full_query_text"] else
                                 "literals redacted (strings, numbers, hex replaced with ?)."))
    if data["powerful"]:
        L.append(f"- WARNING: login holds {', '.join(data['powerful'])}. Read-only is enforced by this tool only.")
    try:
        if int(inv[5]) < 168:
            L.append(f"- NOTE: uptime is {esc(inv[5])} h (< 7 days). Wait, index-usage and query stats reset at "
                     "restart, so performance sections may be incomplete.")
    except ValueError:
        pass
    if autoclose:
        L.append(f"- NOTE: AUTO_CLOSE is ON for {', '.join(esc(a) for a in autoclose)}. DMV stats for those databases are "
                 "emptied each time they close, so performance sections are blind for them.")
    if data["skipped_dbs"]:
        L.append(f"- Skipped {len(data['skipped_dbs'])} database(s) with unusual names.")
    L += ["", "## Summary", "", f"**{counts['high']} high, {counts['medium']} medium, {counts['low']} low** findings.", ""]
    for chk, where, rows in findings:
        L.append(f"- **{chk['severity'].upper()}** {chk['id']} {chk['title']} - {esc(where)}: {len(rows)} item(s)")
    L += ["", "## Findings"]
    for chk, where, rows in findings:
        L += ["", f"### {chk['id']} [{chk['severity'].upper()}] {chk['title']} ({chk['area']}, {esc(where)})", "",
              md_table(chk["cols"], rows), "", f"**Fix:** {chk.get('fix', '')}"]
    L += ["", "## Context (no action implied)"]
    for cid in ("S12", "S14"):
        chk = next(c for c in SERVER_CHECKS if c["id"] == cid)
        L += ["", f"### {cid} {chk['title']}", "", md_table(chk["cols"], res["server"][cid].get("rows", []))]
    d06 = next(c for c in DB_CHECKS if c["id"] == "D06")
    for db in data["dbs"]:
        L += ["", f"### D06 File sizes - {esc(db)}", "", md_table(d06["cols"], res["db"][db]["D06"].get("rows", []))]
    if errors:
        L += ["", "## Check errors"]
        L += [f"- {esc(cid)}: {esc(e)}" for cid, e in errors]
    L += ["", "---", "Generated by sql-healthcheck-kit. Every fix is for your DBA to review and run in a change window."]
    return "\n".join(L) + "\n", counts, errors


def main(argv=None):
    p = argparse.ArgumentParser(prog="sqlhc", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--server", "-S", required=True, help="server name, host,port or host\\instance")
    p.add_argument("--user", "-U", help="SQL login (password from SQLCMDPASSWORD)")
    p.add_argument("--windows-auth", "-E", action="store_true", help="use Windows/Kerberos authentication")
    p.add_argument("--trust-cert", "-C", action="store_true", help="trust the server certificate (lab/self-signed)")
    p.add_argument("--out", "-o", default="sqlhc-out", help="output folder (default sqlhc-out)")
    p.add_argument("--full-query-text", action="store_true", help="do NOT redact literals in query text")
    p.add_argument("--allow-powerful-login", action="store_true",
                   help="run even if the login is sysadmin or can change settings (not recommended)")
    p.add_argument("--sqlcmd", default="sqlcmd", help="path to sqlcmd")
    p.add_argument("--docker", metavar="CONTAINER", help="run sqlcmd inside this container (lab use)")
    p.add_argument("--docker-cmd", default="docker",
                   help="docker command prefix, e.g. 'sudo -n --preserve-env=SQLCMDPASSWORD docker'")
    a = p.parse_args(argv)
    conn = Sqlcmd(a.server, a.user, a.windows_auth, a.trust_cert, a.docker, a.sqlcmd,
                  docker_cmd=a.docker_cmd)
    data = collect(conn, a.full_query_text, a.allow_powerful_login)
    from .html_report import render_html
    md, counts, errors = render_markdown(data)
    page, _, _ = render_html(data)
    os.makedirs(a.out, exist_ok=True)
    rp, hp, jp = (os.path.join(a.out, n) for n in ("report.md", "report.html", "results.json"))
    with open(rp, "w", encoding="utf-8") as f:
        f.write(md)
    with open(hp, "w", encoding="utf-8") as f:
        f.write(page)
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    print(json.dumps({"report": rp, "html": hp, "json": jp, "counts": counts, "errors": len(errors),
                      "databases": len(data["dbs"]), "secs": data["secs"]}))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
