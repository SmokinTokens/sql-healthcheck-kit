"""Plain-English executive summary: category-prioritized findings, not measured risk.

Ranking is by area first, then severity, then check id:
Recoverability > Security > Configuration > Performance > Schema > Inventory.
Losing data you cannot get back outranks a breach risk, which outranks a
misconfiguration, which outranks a slow query. Inside one area, the check's own
severity breaks the tie. The texts are fixed strings written for a manager,
never built from server values, so nothing from the server reaches them.

Every check id in SERVER_CHECKS and DB_CHECKS must have an IMPACT entry
(tests/test_sqlhc.py enforces this). Info checks never become findings, but
they get a text too, so a later severity change cannot leave a gap.
"""

AREA_RANK = {
    "Recoverability": 0,
    "Integrity": 0,
    "Security": 1,
    "Configuration": 2,
    "Performance": 3,
    "Schema": 4,
    "Inventory": 5,
}

SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

IMPACT = {
    "S01": "This is the server's basic inventory and shows no risk by itself.",
    "S02": "For the listed databases, this server's backup history shows no full backup in the last 7 days, so a disk failure or mistake could lose data unless backups are kept another way; confirm coverage with a test restore.",
    "S03": "For the listed databases, this server's backup history shows no log backup in the last 24 hours, so a failure could lose recent work and the log file may keep growing; confirm actual backup coverage.",
    "S04": "These settings can let disk corruption go unnoticed, slow the server down without warning, or let database code gain more rights than intended.",
    "S05": "The databases run on an older query engine level, so they may miss newer query improvements, and a delayed upgrade can carry more risk of slow queries.",
    "S06": "Files set to grow by a percentage can take larger and larger growth steps as they get bigger, which may pause the application while each step is allocated.",
    "S07": "Default instance settings can let SQL Server starve the operating system of memory or waste CPU, which may show up as slowdowns at busy times.",
    "S08": "Each enabled sysadmin login can read, change or delete any data on the server, so one stolen password or mistake on any of them can affect the whole business.",
    "S09": "Logins with the password policy off can keep weak or never-changed passwords, which may make them easier targets for guessing attacks.",
    "S10": "The built-in administrator login (sa, even if renamed) is enabled, and it has full control, so a guessed or leaked password would hand over the whole server.",
    "S11": "Too few tempdb files can cause queueing inside SQL Server when many users sort or report at the same time.",
    "S12": "This shows where the server spends its waiting time, for context only.",
    "S13": "SQL Server estimates that some queries may run faster with an extra index, which may mean slower screens and reports for users; test before adding any.",
    "S14": "This lists the queries that use the most CPU, for context only.",
    "S22": "SQL Server has logged read errors on these database pages, which may mean storage damage and possible data loss; run DBCC CHECKDB and confirm you have good backups.",
    "S23": "DBCC CHECKDB is overdue or unverifiable: the last success is older than 7 days, absent, or unreadable; damage could go unnoticed, so verify UNKNOWN dates with a DBA and schedule regular integrity checks.",
    "S21": "These files have averaged slow disk reads or writes since startup, which may make the application feel slow when it must go to disk; measure again under normal load.",
    "S24": "These SQL Agent jobs recorded a failed run in the last 7 days; if any of them does backups, integrity checks or data loads, that work may not have happened, so read each job's history to see what failed.",
    "S25": "These enabled SQL Agent jobs have no enabled schedule, so they run only when something else starts them; if any is meant to run on a timetable, it may have silently stopped.",
    "D01": "Large tables without a clustered index may get slower to read and may waste disk space as rows change, unless they are staging tables by design.",
    "D02": "These indexes share the same key columns and may be duplicates, which may add avoidable work to every write and extra disk space until their full definitions are reviewed.",
    "D03": "These indexes may overlap, which may add write work and disk use that one index could cover; review their full definitions and usage before changing any.",
    "D04": "SQL Server cannot rely on these constraints, so some queries may run slower, and data that breaks the rules may already be stored.",
    "D05": "These indexes show recorded writes but no recorded reads in the stats available, so they may cost write time for no use; watch a full business cycle before removing any.",
    "D06": "This shows database file sizes, for context only.",
    "D07": "These database users point to logins that no longer exist on this server, so they are leftovers from a restore, move or dropped login that may hide old permissions.",
    "D08": "The guest user can connect here, so any login on this server without its own user can enter this database and use whatever rights guest and public hold.",
}


def risk_key(finding):
    """Sort key for a (check, where, rows) finding: area, then severity, then id, then place."""
    chk, where, _rows = finding
    return (AREA_RANK.get(chk.get("area"), len(AREA_RANK)), SEV_RANK.get(chk.get("severity", "info"), 3),
            chk["id"], where)


def top_findings(findings, n=3):
    """The n highest-risk findings. A check that fires in many databases counts once,
    at its first place, so one noisy check cannot fill the whole summary."""
    out, seen = [], set()
    for f in sorted(findings, key=risk_key):
        if f[0]["id"] in seen:
            continue
        seen.add(f[0]["id"])
        out.append(f)
        if len(out) == n:
            break
    return out
