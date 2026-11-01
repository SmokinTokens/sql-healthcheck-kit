# sql-healthcheck-kit

Read-only health checks for Microsoft SQL Server. One command produces a Markdown report,
a self-contained HTML report (one file, no scripts or external assets, severity colours) and
JSON of backup gaps, risky settings, security issues and schema problems, each with a
plain-language fix. Samples from the demo lab: [docs/sample.md](docs/sample.md) and
[docs/sample.html](docs/sample.html).

- **Read-only by design.** Every check is a single `SELECT` over catalog views, DMVs and
  `msdb.dbo.backupset`. No `DBCC`, no `xp_`/`sp_` calls, no writes, and no user table rows.
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
| D01 | Large heaps | medium |
| D02 | Duplicate indexes | medium |
| S06 | Percent-based file growth | low |
| S10 | `sa` login enabled | low |
| S11 | tempdb data files vs CPUs | low |
| D03 | Left-prefix overlapping indexes | low |
| D04 | Untrusted foreign keys / check constraints | low |
| D05 | Write-only indexes | low |
| S01, S12, S14, D06 | Inventory, top waits, top queries by CPU (redacted), file sizes | context |

The report also warns when uptime is under 7 days (DMV stats reset at restart) and when
AUTO_CLOSE is on (it empties DMV stats for that database).

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
   script as text.

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

`lab/run-lab.sh` starts a throwaway SQL Server 2022 container, seeds `DemoShop` with 11
planted defects, creates the reader login, proves that login is denied writes and row reads,
proves the tool refuses `sa`, then runs the check. Passwords are random and are never put on
a command line; the container keeps `MSSQL_SA_PASSWORD` in its config (`docker inspect`)
until you remove it. Starting the container sets `ACCEPT_EULA=Y`: by running the script you
accept the Microsoft SQL Server Developer Edition licence.

```sh
bash lab/run-lab.sh sqlhc-lab lab-out     # needs docker
docker rm -f sqlhc-lab                     # clean up
```

If docker needs sudo, keep the password variables across it:
`DOCKER="sudo --preserve-env=MSSQL_SA_PASSWORD,SQLCMDPASSWORD,HC_PW docker" bash lab/run-lab.sh`.

Result on SQL Server 2022 (16.0): 3 high, 7 medium, 5 low findings. All planted defects are
found except AUTO_CLOSE: the lab workload turns AUTO_CLOSE off on purpose, so the DMV-based
sections have data to show. See [docs/sample.md](docs/sample.md) and
[docs/sample.html](docs/sample.html) (demo data only; CPU, RAM and run time are
placeholders). Rebuild both from `docs/sample-results.json` with `python3 docs/make-samples.py`.

**Never run `lab/seed-demo.sql` on a real server.** It plants defects on purpose.

## What it does not check (yet)

VLF counts, last good CHECKDB (needs `DBCC DBINFO`, not read-only), SQL Agent job failures
(needs `msdb.dbo.sysjobhistory`), I/O latency (`sys.dm_io_virtual_file_stats`).
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
| Checks | 20 single `SELECT` checks | Hundreds of checks across several procedures |
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
