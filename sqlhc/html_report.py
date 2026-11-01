"""Render the health-check results as ONE self-contained HTML file.

No scripts, no external CSS, fonts or images: everything is inline, and a
Content-Security-Policy meta tag blocks any load even if a name slipped through.
Server-supplied text (names, query text) is HTML-escaped, control characters are
flattened and bidi controls are shown as U+FFFD, the same as in the Markdown report.
"""
import html
import re

from .checks import DB_CHECKS, SERVER_CHECKS
from .runner import errors_of, findings_of

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")

CSS = """
:root{--hi:#b42318;--hi-bg:#fef3f2;--me:#b54708;--me-bg:#fffaeb;--lo:#175cd3;--lo-bg:#eff8ff;
--ink:#1d2939;--mute:#475467;--line:#e4e7ec;--card:#fff;--page:#f9fafb}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 -apple-system,"Segoe UI",Roboto,
Helvetica,Arial,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:32px 0 12px;border-bottom:1px solid var(--line);
padding-bottom:6px}h3{font-size:16px;margin:0 0 8px}
.meta{color:var(--mute);margin:0 0 4px;padding-left:18px}.meta li{margin:2px 0}
.note{background:var(--me-bg);border-left:4px solid var(--me);padding:8px 12px;margin:8px 0;border-radius:4px}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.tile{flex:1 1 140px;border-radius:8px;padding:12px 16px;background:var(--card);border:1px solid var(--line)}
.tile b{display:block;font-size:28px;line-height:1.1}
.tile.high b{color:var(--hi)}.tile.medium b{color:var(--me)}.tile.low b{color:var(--lo)}
.card{background:var(--card);border:1px solid var(--line);border-left-width:6px;border-radius:8px;
padding:14px 16px;margin:12px 0;overflow-x:auto}
.card.high{border-left-color:var(--hi)}.card.medium{border-left-color:var(--me)}.card.low{border-left-color:var(--lo)}
.card.info{border-left-color:var(--line)}
.sev{display:inline-block;font-size:12px;font-weight:700;letter-spacing:.04em;padding:1px 8px;border-radius:10px;
margin-right:6px;vertical-align:1px}
.sev.high{background:var(--hi-bg);color:var(--hi)}.sev.medium{background:var(--me-bg);color:var(--me)}
.sev.low{background:var(--lo-bg);color:var(--lo)}
.where{color:var(--mute);font-weight:400}
table{border-collapse:collapse;width:100%;margin:6px 0 8px;font-size:13px}
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
th{background:var(--page);font-weight:600}td{font-family:ui-monospace,Consolas,Menlo,monospace;word-break:break-word}
.fix{margin:6px 0 0}.fix b{color:var(--ink)}
.summary td,.summary th{font-family:inherit}
footer{color:var(--mute);margin-top:32px;font-size:13px}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def h(v):
    """Escape server-supplied text for HTML (text and attribute context)."""
    v = _CTRL.sub(" ", str(v))
    v = _BIDI.sub("\ufffd", v)
    return html.escape(v, quote=True)


def _table(cols, rows, limit=15):
    out = ["<table><thead><tr>" + "".join(f"<th>{h(c)}</th>" for c in cols) + "</tr></thead><tbody>"]
    for r in rows[:limit]:
        out.append("<tr>" + "".join(f"<td>{h(v)}</td>" for v in r) + "</tr>")
    if len(rows) > limit:
        out.append(f'<tr><td colspan="{len(cols)}">... {len(rows) - limit} more</td></tr>')
    out.append("</tbody></table>")
    return "".join(out)


def render_html(data, title="SQL Server Health Check"):
    """Return (html_text, counts, errors) for the collected data."""
    res = data["results"]
    findings = findings_of(data)
    errors = errors_of(data)
    inv = (res["server"]["S01"].get("rows") or [["?"] * 6])[0]
    counts = {s: sum(1 for f in findings if f[0]["severity"] == s) for s in ("high", "medium", "low")}
    autoclose = [r[0] for r in res["server"]["S04"].get("rows", []) if "AUTO_CLOSE ON" in r[1]]

    P = ["<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
         '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; '
         'form-action \'none\'">',
         '<meta name="viewport" content="width=device-width, initial-scale=1">',
         '<meta name="referrer" content="no-referrer">',
         f"<title>{h(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{h(title)}</h1>", '<ul class="meta">',
         f"<li>Run: {h(data['started'])}, {h(data['secs'])} s, {len(SERVER_CHECKS)} instance checks + "
         f"{len(DB_CHECKS)} per-database checks over {len(data['dbs'])} user database(s).</li>",
         f"<li>Server: SQL Server {h(inv[0])} {h(inv[1])}, {h(inv[2])}, {h(inv[3])} CPUs, {h(inv[4])} MB RAM, "
         f"up {h(inv[5])} h.</li>",
         "<li>Access: catalog views and DMVs only, sent as SELECT statements. No user table rows read; "
         "no data or settings changed.</li>",
         "<li>Query text: " + ("FULL (opt-in)." if data["full_query_text"] else
                               "literals redacted (strings, numbers, hex replaced with ?).") + "</li>",
         "</ul>"]
    if data["powerful"]:
        P.append(f'<p class="note">WARNING: login holds {h(", ".join(data["powerful"]))}. '
                 "Read-only is enforced by this tool only.</p>")
    try:
        if int(inv[5]) < 168:
            P.append(f'<p class="note">NOTE: uptime is {h(inv[5])} h (&lt; 7 days). Wait, index-usage and query '
                     "stats reset at restart, so performance sections may be incomplete.</p>")
    except ValueError:
        pass
    if autoclose:
        P.append(f'<p class="note">NOTE: AUTO_CLOSE is ON for {h(", ".join(autoclose))}. DMV stats for those '
                 "databases are emptied each time they close, so performance sections are blind for them.</p>")
    if data["skipped_dbs"]:
        P.append(f'<p class="note">Skipped {len(data["skipped_dbs"])} database(s) with unusual names.</p>')

    P.append("<h2>Summary</h2><div class=\"tiles\">")
    for s in ("high", "medium", "low"):
        P.append(f'<div class="tile {s}"><b>{counts[s]}</b>{s}</div>')
    P.append("</div>")
    if findings:
        P.append('<table class="summary"><thead><tr><th>Severity</th><th>ID</th><th>Check</th><th>Where</th>'
                 "<th>Items</th></tr></thead><tbody>")
        for chk, where, rows in findings:
            s = chk["severity"]
            P.append(f'<tr><td><span class="sev {s}">{s.upper()}</span></td><td>{h(chk["id"])}</td>'
                     f'<td>{h(chk["title"])}</td><td>{h(where)}</td><td>{len(rows)}</td></tr>')
        P.append("</tbody></table>")

    P.append("<h2>Findings</h2>")
    for chk, where, rows in findings:
        s = chk["severity"]
        P.append(f'<section class="card {s}"><h3><span class="sev {s}">{s.upper()}</span>{h(chk["id"])} '
                 f'{h(chk["title"])} <span class="where">({h(chk["area"])}, {h(where)})</span></h3>'
                 + _table(chk["cols"], rows) +
                 f'<p class="fix"><b>Fix:</b> {h(chk.get("fix", ""))}</p></section>')

    P.append("<h2>Context (no action implied)</h2>")
    for cid in ("S12", "S14"):
        chk = next(c for c in SERVER_CHECKS if c["id"] == cid)
        P.append(f'<section class="card info"><h3>{cid} {h(chk["title"])}</h3>'
                 + _table(chk["cols"], res["server"][cid].get("rows", [])) + "</section>")
    d06 = next(c for c in DB_CHECKS if c["id"] == "D06")
    for db in data["dbs"]:
        P.append(f'<section class="card info"><h3>D06 File sizes - {h(db)}</h3>'
                 + _table(d06["cols"], res["db"][db]["D06"].get("rows", [])) + "</section>")
    if errors:
        P.append("<h2>Check errors</h2><ul>" +
                 "".join(f"<li>{h(cid)}: {h(e)}</li>" for cid, e in errors) + "</ul>")
    P.append("<footer>Generated by sql-healthcheck-kit. Every fix is for your DBA to review and run in a "
             "change window.</footer></main></body></html>")
    return "\n".join(P) + "\n", counts, errors
