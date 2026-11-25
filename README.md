# sql-healthcheck-kit

Read-only health checks for Microsoft SQL Server. One command produces a Markdown report,
a self-contained HTML report (one file, no scripts or external assets, severity colours) and
JSON of backup gaps, risky settings, security issues and schema problems, each with a
plain-language fix. Samples from the demo lab: [docs/sample.md](docs/sample.md) and
[docs/sample.html](docs/sample.html).

- **Read-only by design.** Every check is a single `SELECT` over catalog views, DMVs,
  `msdb.dbo.backupset`, `msdb.dbo.suspect_pages` and named columns of the msdb SQL Agent
  job tables. No `DBCC`, no `xp_`/`sp_` calls, no writes, and no user table rows.
- **Three layers of safety.**
  1. Server-enforced (the real boundary): run it as the least-privilege login from
     `sql/grant-reader.sql`. That login cannot read user table rows, change data or change
     settings. It CAN see metadata: other sessions' query text in the plan cache
     (`VIEW SERVER STATE`) and the source of views, procedures and functions
     (`VIEW ANY DEFINITION`). If your code keeps secrets in procedure source or query
     literals, treat the login and the raw `results.json` as sensitive.
  2. Tool-enforced: the tool probes its own login first and **refuses to run** if the login is
     sysadmin or holds a server permission that can change logins, settings, connections,
     linked servers, credentials, traces, event sessions, endpoints or databases, or if it is
     owner, writer, DDL or security admin, holds a database-wide write permission, or has a
     write, execute or alter grant on any non-system object or schema in `master`, `msdb`,
     `model` or any user database it would check. In `msdb` the SQL Agent, Database Mail and
     SSIS roles count as powerful too (override: `--allow-powerful-login`). A probe it cannot
     read counts as powerful.
  3. Code guard (defence in depth): every query must start with `SELECT`/`WITH` and pass a
     deny-list (no comments, no `;` after the start, no `GO`, no sqlcmd `:`/`!!` commands or
     `$(var)`, no write, exec, transaction, lock or control-flow keywords). sqlcmd also runs
     with `-X1 -x` (sqlcmd commands and variables off). The guard is a check on our own
     hard-coded queries, not a sandbox for untrusted SQL.
- **Report text is escaped.** Names and query text come from the server, so the report
  HTML-escapes them, escapes Markdown punctuation, breaks bare URL and e-mail autolinks
  (GitHub style) and shows bidi control characters as `�`: a database or index named like a
  link, an `<img>` tag or `http://...` shows as plain text. A name with a line break cannot
  add a fake row: the tool checks sqlcmd's row count and reports the check as unparsable.
- **Query text is redacted.** The "top queries" section replaces string, number and hex
  literals with `?`, so data inside queries does not end up in the report
  (opt out with `--full-query-text`).
- **No dependencies.** Python 3.8+ standard library plus Microsoft's `sqlcmd`. Runs on Linux
  and macOS (on Windows, use WSL: the tool feeds SQL through `/dev/stdin`).
- **Passwords never on the command line.** The password comes from the `SQLCMDPASSWORD`
  environment variable, or use Windows authentication (`-E`).

## Checks

| ID | Check | Severity |
|---|---|---|
| S02 | Databases without a full backup in 7 days | high |
| S03 | FULL recovery databases without a log backup in 24 h | high |
| S04 | AUTO_SHRINK, AUTO_CLOSE, PAGE_VERIFY not CHECKSUM, TRUSTWORTHY | high |
| S05 | Old compatibility level | medium |
| S07 | Instance settings left at defaults (max memory, cost threshold, ...) | medium |
| S08 | Non-system sysadmin members | medium |
| S09 | SQL logins with password policy off | medium |
| S13 | Top missing-index requests | medium |
| S21 | Slow file I/O: average read or write latency >= 20 ms since startup (files with >= 1000 I/Os) | medium |
| S22 | Suspect pages (823/824 errors, bad checksum, torn page) in `msdb.dbo.suspect_pages` | high |
| S23 | `DBCC CHECKDB` overdue or unverifiable (7 days) | medium |
| S24 | SQL Agent jobs with a failed run in the last 7 days (top 20) | medium |
| D01 | Large heaps | medium |
| D02 | Duplicate indexes | medium |
| D08 | `guest` user can connect (CONNECT granted) in a user database | medium |
| S06 | Percent-based file growth | low |
| S10 | `sa` login enabled | low |
| S11 | tempdb data files vs CPUs | low |
| S25 | Enabled SQL Agent jobs with no enabled schedule (top 50) | low |
| D03 | Left-prefix overlapping indexes | low |
| D04 | Untrusted foreign keys / check constraints | low |
| D05 | Write-only indexes | low |
| D07 | Orphaned database users: login-based users with no matching login (top 50) | low |
| S01, S12, S14, D06 | Inventory, top waits, top queries by CPU (redacted), file sizes | context |

The report also warns when uptime is under 7 days (DMV stats reset at restart) and when
AUTO_CLOSE is on (it empties DMV stats for that database).

S21 reads `sys.dm_io_virtual_file_stats` joined to `sys.master_files` (`VIEW SERVER STATE`)
and shows logical file names only, never physical paths. Its numbers are averages since each
file came online, so they hide short spikes; Microsoft puts the point where users start to
notice at about 10-15 ms per transfer
([Troubleshoot slow SQL Server performance caused by I/O issues](https://learn.microsoft.com/troubleshoot/sql/database-engine/performance/troubleshoot-sql-io-performance)).
The lab container's fast disk produces no S21 rows,
so this is what a finding looks like (illustrative values, not lab output):

| database | file | type | reads | avg_read_ms | writes | avg_write_ms |
|---|---|---|---|---|---|---|
| Sales | Sales_log | LOG | 12 | 0.4 | 48210 | 27.3 |

S22 and S23 look for corruption without running `DBCC`. S22 reads
[`msdb.dbo.suspect_pages`](https://learn.microsoft.com/sql/relational-databases/system-tables/suspect-pages-transact-sql):
one row per page that failed with a minor 823 or an 824 error. S22 shows the 20 most
recent open rows (event types 1-3), ordered by last update, and skips pages already
restored, repaired or deallocated. A listed page
can still be fine, and the table keeps at most 1,000 rows, so treat a row as a reason to run
`DBCC CHECKDB` now, not as proof of damage. S23 reads
[`DATABASEPROPERTYEX(name, 'LastGoodCheckDbTime')`](https://learn.microsoft.com/sql/t-sql/functions/databasepropertyex-transact-sql)
for each online database except tempdb and snapshots. `NEVER` means the server returned
1900-01-01 (no successful CHECKDB on record). `UNKNOWN` means it returned NULL, so the date
could not be read; one cause is a server older than SQL Server 2016 SP2 / 2017 CU9, which
lack the property. In an availability group the date is the
last good CHECKDB on the primary replica.

S24 and S25 read `msdb.dbo.sysjobs`, `sysjobhistory`, `sysjobschedules` and `sysschedules`
([sysjobhistory](https://learn.microsoft.com/sql/relational-databases/system-tables/dbo-sysjobhistory-transact-sql):
`step_id` 0 is the job outcome, `run_status` 0 is Failed). The reader login gets
column-level `SELECT` on those tables only, not `SQLAgentReaderRole`: members of that role
are also members of `SQLAgentUserRole` and can create and run their own jobs
([SQL Server Agent fixed database roles](https://learn.microsoft.com/ssms/agent/sql-server-agent-fixed-database-roles)).
The report never reads the history `message` column (job step output can hold paths or data)
or the job owner. Times are the server's local time. S24 covers 7 server-local calendar
days back from the current time of day, not exactly 168 hours across daylight-saving
changes. `last_failed_run_start` is the start time of the latest failed run, not its
completion time. SQL Server Agent keeps 1,000 history rows
in total and 100 per job by default
([Job automation with SQL Agent jobs](https://learn.microsoft.com/azure/azure-sql/managed-instance/job-automation-managed-instance#job-history)),
so on a busy server an empty S24 can mean the failures were already purged. S25 does not
detect a schedule that is enabled but already ended. Express edition has no Agent: both
checks then return nothing.

D07 and D08 run in each user database and read catalog views only (`VIEW ANY DEFINITION`).
D07 uses Microsoft's own orphan test: a user with `authentication_type_desc = 'INSTANCE'`
whose SID has no row in `sys.server_principals`
([Troubleshoot orphaned users](https://learn.microsoft.com/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server)).
Contained users and users without a login are not orphans and are skipped. Built-in users
(`dbo`, `guest`, `INFORMATION_SCHEMA`, `sys`; principal ids 1-4) are skipped as well: a stale
`dbo` SID after a restore is a database-owner question, so compare `sys.databases.owner_sid`
before changing anything. Windows users
are skipped too, as in Microsoft's query: they can still connect through a Windows group
login. Fix with `ALTER USER ... WITH LOGIN`, not the deprecated `sp_change_users_login`.
Before dropping an unused user, check what depends on it and list the grants in any schema it
owns. Changing a schema owner drops permissions on objects in that schema that have no explicit
owner ([ALTER AUTHORIZATION](https://learn.microsoft.com/sql/t-sql/statements/alter-authorization-transact-sql#special-cases-and-conditions)),
so do it in a tested change window and reapply the grants still needed. Never drop its schemas
or objects as part of this cleanup.
D08 lists a database-level `CONNECT` grant to `guest` (principal id 2). Microsoft's
best-practice rule is to revoke it in user databases unless it is needed
([Guest permissions on user databases](https://learn.microsoft.com/sql/relational-databases/policy-based-management/guest-permissions-on-user-databases)).
`master`, `msdb` and `tempdb` need guest, so the kit does not check system databases here.

## Quick start

1. Install the ODBC [sqlcmd](https://learn.microsoft.com/sql/tools/sqlcmd/sqlcmd-utility) from
   `mssql-tools18`. That is the version the tool is tested with. The newer Go `sqlcmd`
   is not tested yet.
2. Your DBA creates the reader login (sysadmin needed once). The password comes from the
   environment, not the command line:

   ```sh
   read -rs HC_PW && export HC_PW      # type it; it stays out of shell history
   sqlcmd -S myserver -E -i sql/grant-reader.sql
   ```

   The password must not contain a single quote (`'`): sqlcmd pastes `$(HC_PW)` into the
   script as text. The script only creates a new login: if a login or msdb user named
   `hc_reader` already exists, it stops and changes nothing (an old `hc_reader` may hold
   other rights). Run `sql/remove-reader.sql` first if that login is yours.

3. Run the check:

   ```sh
   export SQLCMDPASSWORD="$HC_PW"
   python3 -m sqlhc --server myserver --user hc_reader --out report-myserver
   # Windows auth: python3 -m sqlhc --server myserver -E
   # Self-signed certificate (lab): add --trust-cert
   ```

4. Read `report-myserver/report.md` or open `report-myserver/report.html` in a browser
   (same content; the HTML file has no scripts and loads nothing from the network).
   Remove the login when done:
   `sqlcmd -S myserver -E -i sql/remove-reader.sql`.

Exit code: 0 = ran clean, 1 = one or more checks errored (listed in the report).

## Try it on a demo database

`lab/run-lab.sh` starts a throwaway SQL Server 2022 container, seeds `DemoShop` with 15
planted defects (including a fake suspect-page row in msdb; no page is really damaged),
creates the reader login, proves that login is denied writes and row reads, proves the tool
refuses `sa`, runs the check, then proves the reader login could read both corruption
sources (S22, S23) with `lab/assert-integrity.py` and found the planted orphaned user and
guest `CONNECT` grant (D07, D08) with `lab/assert-security.py`. Passwords are random and are never put on
a command line; the container keeps `MSSQL_SA_PASSWORD` in its config (`docker inspect`)
until you remove it. Starting the container sets `ACCEPT_EULA=Y`: by running the script you
accept the Microsoft SQL Server Developer Edition licence.

```sh
bash lab/run-lab.sh sqlhc-lab lab-out     # needs docker
docker rm -f sqlhc-lab                     # clean up
```

If docker needs sudo, keep the password variables across it:
`DOCKER="sudo --preserve-env=MSSQL_SA_PASSWORD,SQLCMDPASSWORD,HC_PW docker" bash lab/run-lab.sh`.

Result on SQL Server 2022 (16.0) before S22/S23 existed: 3 high, 7 medium, 5 low findings.
The S22/S23 lab run on 2026-11-24 confirmed that `hc_reader` could read both sources
and find the planted defects: a suspect page and DemoShop, model and msdb without a
CHECKDB. The lab run summary recorded `lab_exit=0`, no containers
left, and passing read-only negative controls. This confirms S22/S23; it is not a
lab verification of the later S24/S25 checks or a fresh finding-count baseline.
All planted defects are found except AUTO_CLOSE: the lab workload turns AUTO_CLOSE off on purpose, so the DMV-based
sections have data to show. See [docs/sample.md](docs/sample.md) and
[docs/sample.html](docs/sample.html) (demo data only; CPU, RAM and run time are
placeholders). Rebuild both from `docs/sample-results.json` with `python3 docs/make-samples.py`.

**Never run `lab/seed-demo.sql` on a real server.** It plants defects on purpose.

## Compare two runs (re-check)

After fixes, run the check again into a new folder, then compare the two JSON files:

    python3 -m sqlhc.compare first/results.json recheck/results.json --out compare-out

This writes `compare.md` and `compare.json`. Each finding row is one item, matched by
check, scope and the check's key columns (login, table + index, ...). Items are **fixed**,
**new**, **changed** (same item, other values moved), **unchanged** or **unknown**. A check
that errored, malformed rows, or a database missing from one run (or an unreadable database
list) are unknown: an error is never shown as a fix. S13 and S21 return only a top 10 / top 15;
an item that drops out of a full list is unknown, because it may only have been ranked out.
Checks that use counters since startup (S13, D05, S21) reset at restart, so a "fixed" there can
mean only that the counters were cleared. S24 never shows **fixed**: a failed job that drops out
is **unknown**, because it may only have left the 7-day window or been purged from Agent
history. Check the job's next runs instead. The tool reads two files; it never connects to a server.

## What it does not check (yet)

VLF counts, last good CHECKDB on servers older than SQL Server 2016 SP2 (S23 shows
`UNKNOWN` there; the old way needs `DBCC DBINFO`), SQL Agent failure messages (left out
on purpose), I/O latency over a short window (S21 shows averages
since startup only; a two-snapshot delta needs `WAITFOR`, which the guard refuses).
Pull requests welcome, as long as every new check stays a single read-only `SELECT`.

## How this compares to the First Responder Kit

If you already run Brent Ozar's
[SQL Server First Responder Kit](https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit)
(`sp_Blitz`, `sp_BlitzCache`, `sp_BlitzIndex`, ...), keep running it. It is MIT licensed,
mature and actively maintained, and it is far deeper than this kit: `sp_Blitz` alone has
check IDs up to 277 (CHECKDB age, corruption, TDE certificate backups, Agent jobs, VLFs and
much more), and the other procedures cover plan-cache tuning, index tuning, deadlocks and
live waits. Its `sp_BlitzCache` and `sp_BlitzIndex` (single-table mode) can also build AI
prompts (`@AI = 2`) or call an AI provider (`@AI = 1` on SQL Server 2025 / Azure SQL DB).
This kit does not replace it.

What is different here:

| | This kit | First Responder Kit |
|---|---|---|
| Install on the server | Nothing. Queries are sent from the client | Stored procedures, usually in `master` |
| Checks | 27 single `SELECT` checks | Hundreds of checks across several procedures |
| Login | Least-privilege reader; refuses to run as sysadmin or any write-capable login | Not restricted; some checks need high rights (e.g. trace-flag checks via `DBCC TRACESTATUS`) |
| Output | One Markdown report, one self-contained HTML report, and JSON | Result sets in SSMS, optional output tables |
| Query text | Literals redacted by default | Full query text and plans |

Use this kit when you may not install code on a server (a client's box, a locked-down
production server, an audit) and want a short, read-only report you can hand to a
non-DBA. Use the First Responder Kit for deeper tuning and troubleshooting.

## Tests

```sh
python3 -m unittest discover -s tests
```

Offline tests cover the guard (every shipped check passes; writes, `INTO`, `EXEC`,
`OPENROWSET`, `WAITFOR`, stacked statements, `GO` batches, sqlcmd commands, comment tricks,
digit-glued keywords like `1DROP` and quotes hidden in `[..]` or `".."` are refused), the
fail-closed privilege probes (system databases included), the redactor, row-count checks
and report escaping.

## Credits

This kit stands on the work of the SQL Server community. The optional DBA toolkit
(`toolkit/`) installs these tools through [dbatools](https://github.com/dataplat/dbatools).
They are fetched from upstream at install time, unmodified, and are not stored in this
repository:

| Tool | Author | Licence |
|---|---|---|
| [SQL Server First Responder Kit](https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit) | Brent Ozar Unlimited and contributors | MIT ([text](third_party_licenses/SQL-Server-First-Responder-Kit-MIT.txt)) |
| [SQL Server Maintenance Solution](https://github.com/olahallengren/sql-server-maintenance-solution) | Ola Hallengren | MIT ([text](third_party_licenses/sql-server-maintenance-solution-MIT.txt)) |
| [sp_WhoIsActive](https://github.com/amachanic/sp_whoisactive) | Adam Machanic | GPL-3.0 ([text](third_party_licenses/sp_WhoIsActive-GPL-3.0.txt)) |

sp_WhoIsActive stays under GPL-3.0; it is not relicensed under this repository's MIT
licence. See [NOTICE](NOTICE) for the full attribution. These names are used only to
identify and credit the tools: their authors do not sponsor or endorse this project, and
it is not affiliated with them.

## License

MIT for this repository's own code. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Findings are advice; test every fix in a change window first.
