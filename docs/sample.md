# SQL Server Health Check (sample, demo data)

- Run: 2026-01-15T09:00:00, 2.3 s, 22 instance checks + 11 per-database checks over 1 user database(s).
- Server: SQL Server 16.0.4305.5 RTM, Developer Edition \(64\-bit\), 4 CPUs, 16384 MB RAM, up 0 h.
- Access: catalog views and DMVs only, sent as SELECT statements. No user table rows read; no data or settings changed.
- Query text: literals redacted (strings, numbers, hex replaced with ?).
- NOTE: uptime is 0 h (< 7 days). Wait, index-usage and query stats reset at restart, so performance sections may be incomplete.

## Executive summary

Top 3 category-prioritized findings (data loss before security, then configuration, then speed):

1. **Databases without a recent full backup (7 days)** (Recoverability, high, \(instance\)): For the listed databases, this server's backup history shows no full backup in the last 7 days, so a disk failure or mistake could lose data unless backups are kept another way; confirm coverage with a test restore.
2. **FULL recovery databases without log backups (24 h)** (Recoverability, high, \(instance\)): For the listed databases, this server's backup history shows no log backup in the last 24 hours, so a failure could lose recent work and the log file may keep growing; confirm actual backup coverage.
3. **Suspect pages (823/824 errors) in msdb.dbo.suspect_pages** (Integrity, high, \(instance\)): A recorded suspect_pages entry flags possible page damage, but is not proof of a read-error event or current corruption; have a DBA run DBCC CHECKDB, check SQL Server and storage logs, and confirm good backups.

## Summary

**4 high, 11 medium, 7 low** findings.

- **HIGH** S02 Databases without a recent full backup (7 days) - \(instance\): 1 item(s)
- **HIGH** S03 FULL recovery databases without log backups (24 h) - \(instance\): 1 item(s)
- **HIGH** S04 Risky database options - \(instance\): 1 item(s)
- **HIGH** S22 Suspect pages (823/824 errors) in msdb.dbo.suspect_pages - \(instance\): 1 item(s)
- **MEDIUM** D01 Large heaps (tables without a clustered index) - DemoShop: 1 item(s)
- **MEDIUM** D02 Duplicate indexes (same key columns) - DemoShop: 1 item(s)
- **MEDIUM** D08 guest user can connect (CONNECT granted) - DemoShop: 1 item(s)
- **MEDIUM** D10 Log space held (log_reuse_wait_desc not NOTHING/CHECKPOINT) - DemoShop: 1 item(s)
- **MEDIUM** S05 Old compatibility level - \(instance\): 1 item(s)
- **MEDIUM** S07 Instance settings left at defaults - \(instance\): 5 item(s)
- **MEDIUM** S08 Sysadmin members (non-system) - \(instance\): 4 item(s)
- **MEDIUM** S09 SQL logins with password policy off - \(instance\): 1 item(s)
- **MEDIUM** S13 Top missing-index requests - \(instance\): 1 item(s)
- **MEDIUM** S23 DBCC CHECKDB overdue or unverifiable (7 days) - \(instance\): 3 item(s)
- **MEDIUM** S26 Last full backup without CHECKSUM, damaged, or copy-only only - \(instance\): 2 item(s)
- **LOW** D03 Left-prefix overlapping indexes - DemoShop: 2 item(s)
- **LOW** D04 Untrusted foreign keys / check constraints - DemoShop: 1 item(s)
- **LOW** D05 Write-only indexes (writes, no reads since startup) - DemoShop: 2 item(s)
- **LOW** D07 Orphaned database users (no matching login) - DemoShop: 1 item(s)
- **LOW** S06 Percent-based file growth - \(instance\): 5 item(s)
- **LOW** S10 'sa' login enabled - \(instance\): 1 item(s)
- **LOW** S27 Last full backup: native backup encryption not recorded - \(instance\): 3 item(s)

## Findings

### S02 [HIGH] Databases without a recent full backup (7 days) (Recoverability, \(instance\))

| database | recovery_model | last_full |
|---|---|---|
| model | FULL | NEVER |

**Fix:** Schedule full backups (weekly or nightly) and test a restore. System databases (master, msdb, model) need backups too.

### S03 [HIGH] FULL recovery databases without log backups (24 h) (Recoverability, \(instance\))

| database | last_log_backup |
|---|---|
| DemoShop | NEVER |

**Fix:** The log may grow, but missing msdb history alone does not prove blocked log reuse. Check D10 (log_reuse_wait_desc, recorded at the last checkpoint) and confirm the real backup strategy and restore needs with the owner, including external backups or purged history. With owner approval, schedule log backups to meet the recovery-point objective and test restores. Preserve the log-backup chain; do not change recovery model as a shortcut. Any recovery-model change needs separate owner approval, a plan for the log-backup chain and point-in-time restore, and checks for availability groups, log shipping, replication and mirroring.

### S04 [HIGH] Risky database options (Configuration, \(instance\))

| database | options |
|---|---|
| DemoShop | AUTO\_SHRINK ON; PAGE\_VERIFY NONE; |

**Fix:** Set AUTO_SHRINK OFF, AUTO_CLOSE OFF and PAGE_VERIFY CHECKSUM. Set TRUSTWORTHY OFF unless an application feature needs it (for example cross-database Service Broker). Use a change window.

### S22 [HIGH] Suspect pages (823/824 errors) in msdb.dbo.suspect_pages (Integrity, \(instance\))

| database | file_id | page_id | error | count | last_seen |
|---|---|---|---|---|---|
| DemoShop | 1 | 312 | bad checksum | 3 | 2026\-01\-15 08:58:00 |

**Fix:** A recorded suspect_pages entry is not proof of a read-error event or current corruption: rows can be added or changed manually and can remain after a fix. Treat it as possible corruption: have a DBA run DBCC CHECKDB WITH NO_INFOMSGS, ALL_ERRORMSGS in a quiet window, check SQL Server and storage logs, and confirm clean, tested backups. Plan a page or full restore only if investigation confirms it is needed. A page can be listed and still be fine. msdb keeps up to 1,000 entries; preserve the evidence before any owner-approved cleanup.

### D01 [MEDIUM] Large heaps (tables without a clustered index) (Schema, DemoShop)

| table | rows |
|---|---|
| dbo.OrderLines | 400000 |

**Fix:** Review with the table owner first: some heaps are intentional (staging, bulk-load or insert-only tables). If a clustered index is wanted, pick a narrow, ever-increasing key, test it against the real workload, check disk and log space, and create it in an approved maintenance window: it rewrites the table and rebuilds every nonclustered index, and an offline build blocks access to the table.

### D02 [MEDIUM] Duplicate indexes (same key columns) (Schema, DemoShop)

| table | index_a | index_b | key_column_ids |
|---|---|---|---|
| dbo.Orders | IX\_Orders\_Cust | IX\_Orders\_Cust\_Dup | 2 |

**Fix:** Potential duplicates: the keys match, but INCLUDE columns, filters and uniqueness are not compared. Never drop unique indexes or indexes backing PRIMARY KEY or UNIQUE constraints as part of this cleanup. Compare the full definitions and usage, check index hints that name either index, and obtain owner approval before removing any other index. Each extra index adds overhead to inserts, deletes and key updates.

### D08 [MEDIUM] guest user can connect (CONNECT granted) (Security, DemoShop)

| user | state |
|---|---|
| guest | GRANT |

**Fix:** Run REVOKE CONNECT FROM guest in this database (Microsoft's best-practice rule for user databases), after you confirm no application relies on guest access. Logins that need the database then get their own database user and roles.

### D10 [MEDIUM] Log space held (log_reuse_wait_desc not NOTHING/CHECKPOINT) (Recoverability, DemoShop)

| log_reuse_wait | recovery_model |
|---|---|
| LOG\_BACKUP | FULL |

**Fix:** Act on the reason shown. LOG_BACKUP: schedule regular log backups (see S03). Switching to SIMPLE recovery is a DBA decision for the whole recovery plan: it breaks the log-backup chain and is not allowed with log shipping, availability groups or mirroring. ACTIVE_TRANSACTION: find the long open transaction (sys.dm_tran_database_transactions) and have its owner commit or end it. REPLICATION or AVAILABILITY_REPLICA: check that the log reader or secondary is running and caught up. Short REPLICATION or AVAILABILITY_REPLICA waits, LOG_SCAN and DATABASE_SNAPSHOT_CREATION can be normal. This is the reason recorded at the last checkpoint, not a measure of log pressure: run the check again to see if the reason stays.

### S05 [MEDIUM] Old compatibility level (Configuration, \(instance\))

| database | compat_level | server_level |
|---|---|---|
| DemoShop | 130 | 160 |

**Fix:** Plan a tested upgrade of the compatibility level (turn on Query Store first to catch plan regressions).

### S07 [MEDIUM] Instance settings left at defaults (Configuration, \(instance\))

| setting | value |
|---|---|
| cost threshold for parallelism | 5 |
| max degree of parallelism | 0 |
| max server memory \(MB\) | 2147483647 |
| backup compression default | 0 |
| optimize for ad hoc workloads | 0 |

**Fix:** Cap max server memory (leave OS headroom). Raise cost threshold for parallelism in small steps and watch a full business cycle. Set MAXDOP per the Microsoft NUMA guidance (8 on one NUMA node with more than 8 logical CPUs). Consider optimize for ad hoc workloads, and backup compression if CPU allows.

### S08 [MEDIUM] Sysadmin members (non-system) (Security, \(instance\))

| login | type | state |
|---|---|---|
| sa | SQL\_LOGIN | enabled |
| BUILTIN\\Administrators | WINDOWS\_GROUP | enabled |
| NT AUTHORITY\\NETWORK SERVICE | WINDOWS\_LOGIN | enabled |
| legacy\_app | SQL\_LOGIN | enabled |

**Fix:** Keep sysadmin to named admins only. Application logins get database roles, not sysadmin.

### S09 [MEDIUM] SQL logins with password policy off (Security, \(instance\))

| login | policy | expiry | state |
|---|---|---|---|
| legacy\_app | off | off | enabled |

**Fix:** Turn CHECK_POLICY ON and rotate the password. This also turns on expiry and lockout, which can break an application login; set CHECK_EXPIRATION to match your password-rotation process.

### S13 [MEDIUM] Top missing-index requests (Performance, \(instance\))

| database | table | equality | inequality | include | score |
|---|---|---|---|---|---|
| DemoShop | \[DemoShop\].\[dbo\].\[Orders\] | \[Status\] | \[OrderDate\] | \[Total\] | 3655.7 |

**Fix:** Review each request against existing indexes; add only the top few after testing. Do not add all of them.

### S23 [MEDIUM] DBCC CHECKDB overdue or unverifiable (7 days) (Integrity, \(instance\))

| database | last_good_checkdb |
|---|---|
| model | NEVER |
| msdb | NEVER |
| DemoShop | NEVER |

**Fix:** Schedule DBCC CHECKDB at least weekly for every database, system databases included (for example Ola Hallengren's DatabaseIntegrityCheck), and alert on failure. Run it off-peak: it uses tempdb and I/O. UNKNOWN means the date could not be read (the property returned NULL); a server older than SQL Server 2016 SP2 / 2017 CU9 is one cause. Check the date there with a DBA login.

### S26 [MEDIUM] Last full backup without CHECKSUM, damaged, or copy-only only (Recoverability, \(instance\))

| database | last_full | issues |
|---|---|---|
| DemoShop | 2026\-01\-15 08:58:12 | no CHECKSUM;  |
| msdb | 2026\-01\-15 08:58:14 | copy\-only fulls only;  |

**Fix:** Take full backups WITH CHECKSUM (or turn on the 'backup checksum default' server option) so the backup verifies page checksums and records a backup checksum. With the default STOP_ON_ERROR a bad page stops the backup; CONTINUE_AFTER_ERROR lets it finish and marks it damaged. Checksums do not prove a backup restores: test a restore. A DAMAGED backup was taken despite errors: run DBCC CHECKDB, then plan a clean full with the backup owner (see below). 'Copy-only fulls only' means no regular full is on record here: first check the real backup strategy with its owner (another tool may take the regular fulls). A new regular full resets the differential base for later differential backups, so do not add one without that check. 'No full since recreated or restored' means every full on record belongs to an older copy of the database: check with the backup owner, then plan a new full (see below). 'History unknown' means no full matches the current copy and some fulls on record have no database_guid, so this server cannot tell which copy they belong to: confirm a current full exists another way. Before taking ANY new regular full, check the backup strategy with its owner: it becomes the base for later differential backups, so it must be kept in the same retained restore chain (or use COPY_ONLY).

### D03 [LOW] Left-prefix overlapping indexes (Schema, DemoShop)

| table | narrower_index | covered_by |
|---|---|---|
| dbo.Orders | IX\_Orders\_Cust | IX\_Orders\_Cust\_Date |
| dbo.Orders | IX\_Orders\_Cust\_Dup | IX\_Orders\_Cust\_Date |

**Fix:** Potential overlap: the wider index can often serve seeks that use the narrower one, but INCLUDE columns and filters are not compared. Never drop unique indexes or indexes backing PRIMARY KEY or UNIQUE constraints as part of this cleanup. Compare the full definitions and usage, check index hints that name either index, and obtain owner approval before removing any other index.

### D04 [LOW] Untrusted foreign keys / check constraints (Schema, DemoShop)

| table | constraint | kind |
|---|---|---|
| dbo.Orders | FK\_Orders\_Customers | FK |

**Fix:** Re-validate WITH CHECK CHECK CONSTRAINT in a change window so the optimizer can trust it.

### D05 [LOW] Write-only indexes (writes, no reads since startup) (Schema, DemoShop)

| table | index | writes | reads |
|---|---|---|---|
| dbo.Orders | IX\_Orders\_Cust | 1 | 0 |
| dbo.Orders | IX\_Orders\_Cust\_Date | 1 | 0 |

**Fix:** Zero recorded reads do not prove an index is unnecessary. Never drop unique indexes or indexes backing PRIMARY KEY or UNIQUE constraints as part of this cleanup. Observe usage over a full business cycle of uptime (month-end included), accounting for usage-counter resets. Compare the full definitions, including INCLUDE columns and filters, check index hints that name the index, and obtain owner approval before removing any other index.

### D07 [LOW] Orphaned database users (no matching login) (Security, DemoShop)

| user | type |
|---|---|
| lab\_orphan | SQL\_USER |

**Fix:** For each user, map it to the right login with ALTER USER <user> WITH LOGIN = <login>. If nobody needs it and it owns no schema, drop the user. If it owns a schema, leave it in place: do not change the owner or drop anything as part of this cleanup. Changing a schema owner drops every permission on the schema itself and on objects in it that have no explicit owner (grants, denies and grant options), so treat it as a separate, tested change that records those permissions first, restores them after, and checks application access. Do not use the deprecated sp_change_users_login. Built-in users (dbo, guest, INFORMATION_SCHEMA, sys) are not listed. Windows users are not listed (they can still get in through a Windows group login).

### S06 [LOW] Percent-based file growth (Configuration, \(instance\))

| database | file | type | growth | size_mb |
|---|---|---|---|---|
| master | master | ROWS | 10% | 4 |
| master | mastlog | LOG | 10% | 0 |
| msdb | MSDBData | ROWS | 10% | 15 |
| msdb | MSDBLog | LOG | 10% | 1 |
| DemoShop | DemoShop | ROWS | 10% | 37 |

**Fix:** Use fixed growth (for example 256 MB data, 128 MB log).

### S10 [LOW] 'sa' login enabled (Security, \(instance\))

| login |
|---|
| sa |

**Fix:** Disable sa once named admin logins exist. A disabled login can still be impersonated, so also review IMPERSONATE grants.

### S27 [LOW] Last full backup: native backup encryption not recorded (Security, \(instance\))

| database | last_full |
|---|---|
| DemoShop | 2026\-01\-15 08:58:12 |
| master | 2026\-01\-15 08:58:13 |
| msdb | 2026\-01\-15 08:58:14 |

**Fix:** msdb records no native backup encryption for this backup. It may still be protected another way: TDE that was on when it was taken (backup history cannot show this), encrypted storage, or a backup tool that encrypts. Verify how the backup files are protected before changing anything. If they are not protected, anyone who gets a copy of a file can restore it and read the data: encrypt backups (BACKUP ... WITH ENCRYPTION, using a certificate or asymmetric key) or use TDE, and back up that certificate and its private key to a separate safe place: without it the backup cannot be restored.

## Context (no action implied)

### S12 Top waits since startup

| wait_type | seconds | pct |
|---|---|---|
| LCK\_M\_U | 5.2 | 30.5 |
| CHKPT | 3.4 | 20.0 |
| WRITELOG | 1.6 | 9.7 |
| PAGEIOLATCH\_UP | 1.1 | 6.4 |
| SLEEP\_PHYSMASTERDBREADY | 1.0 | 5.7 |
| CXCONSUMER | .8 | 4.9 |
| LCK\_M\_S | .7 | 4.1 |
| CXSYNC\_PORT | .5 | 3.1 |

### S14 Top queries by total CPU

| database | execs | cpu_ms | logical_reads | statement_110ch |
|---|---|---|---|---|
| DemoShop | 40 | 669 | 78960 | SELECT @x = SUM\(Qty \* Price\) FROM dbo.OrderLines WHERE Sku = CONCAT\('?', @i\) |
| DemoShop | 40 | 308 | 33800 | SELECT @x = SUM\(Total\) FROM dbo.Orders WHERE Status = \(@i % ?\) AND OrderDate &gt; DATEADD\(day, \-?, sysdatetime\(\)\) |
| DemoShop | 40 | 44 | 4600 | SELECT @x = COUNT\(\*\) FROM dbo.Customers WHERE Email LIKE CONCAT\('?', @i, '?'\) |
| DemoShop | 1 | 2 | 2653 | UPDATE TOP \(?\) dbo.Orders SET CustomerID = CustomerID \+ ? WHERE OrderID % ? = ? |
| ? | 1 | 0 | 197 | select @configcount = count\(\*\) from sys.configurations where lower\(name collate Latin1\_General\_CI\_AS\) like |

### D06 File sizes - DemoShop

| file | type | size_mb | max_mb |
|---|---|---|---|
| DemoShop | ROWS | 41 | unlimited |
| DemoShop\_log | LOG | 264 | 2097152 |

---
Generated by sql-healthcheck-kit. Every fix is for your DBA to review and run in a change window.
