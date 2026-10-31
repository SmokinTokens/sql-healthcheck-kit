# SQL Server Health Check

- Run: 2026-10-28T02:52:39, 2.3 s, 14 instance checks + 6 per-database checks over 1 user database(s).
- Server: SQL Server 16.0.4305.5 RTM, Developer Edition \(64\-bit\), <cpus> CPUs, <ram> MB RAM (lab host, removed from this sample), up 0 h.
- Access: catalog views and DMVs only, sent as SELECT statements. No user table rows read; no data or settings changed.
- Query text: literals redacted (strings, numbers, hex replaced with ?).
- NOTE: uptime is 0 h (< 7 days). Wait, index-usage and query stats reset at restart, so performance sections may be incomplete.

## Summary

**3 high, 7 medium, 5 low** findings.

- **HIGH** S02 Databases without a recent full backup (7 days) - \(instance\): 3 item(s)
- **HIGH** S03 FULL recovery databases without log backups (24 h) - \(instance\): 1 item(s)
- **HIGH** S04 Risky database options - \(instance\): 1 item(s)
- **MEDIUM** D01 Large heaps (tables without a clustered index) - DemoShop: 1 item(s)
- **MEDIUM** D02 Duplicate indexes (same key columns) - DemoShop: 1 item(s)
- **MEDIUM** S05 Old compatibility level - \(instance\): 1 item(s)
- **MEDIUM** S07 Instance settings left at defaults - \(instance\): 5 item(s)
- **MEDIUM** S08 Sysadmin members (non-system) - \(instance\): 4 item(s)
- **MEDIUM** S09 SQL logins with password policy off - \(instance\): 1 item(s)
- **MEDIUM** S13 Top missing-index requests - \(instance\): 1 item(s)
- **LOW** D03 Left-prefix overlapping indexes - DemoShop: 2 item(s)
- **LOW** D04 Untrusted foreign keys / check constraints - DemoShop: 1 item(s)
- **LOW** D05 Write-only indexes (writes, no reads since startup) - DemoShop: 2 item(s)
- **LOW** S06 Percent-based file growth - \(instance\): 5 item(s)
- **LOW** S10 'sa' login enabled - \(instance\): 1 item(s)

## Findings

### S02 [HIGH] Databases without a recent full backup (7 days) (Recoverability, \(instance\))

| database | recovery_model | last_full |
|---|---|---|
| model | FULL | NEVER |
| master | SIMPLE | NEVER |
| msdb | SIMPLE | NEVER |

**Fix:** Schedule full backups (weekly or nightly) and test a restore. System databases (master, msdb, model) need backups too.

### S03 [HIGH] FULL recovery databases without log backups (24 h) (Recoverability, \(instance\))

| database | last_log_backup |
|---|---|
| DemoShop | NEVER |

**Fix:** Add log backups every 15-60 min, or switch to SIMPLE if point-in-time restore is not needed. The log grows without limit until then.

### S04 [HIGH] Risky database options (Configuration, \(instance\))

| database | options |
|---|---|
| DemoShop | AUTO\_SHRINK ON; PAGE\_VERIFY NONE; |

**Fix:** Set AUTO_SHRINK OFF, AUTO_CLOSE OFF, PAGE_VERIFY CHECKSUM, TRUSTWORTHY OFF (in a change window).

### D01 [MEDIUM] Large heaps (tables without a clustered index) (Schema, DemoShop)

| table | rows |
|---|---|
| dbo.OrderLines | 400000 |

**Fix:** Add a narrow, ever-increasing clustered key, unless the heap is a staging table by design.

### D02 [MEDIUM] Duplicate indexes (same key columns) (Schema, DemoShop)

| table | index_a | index_b | key_column_ids |
|---|---|---|---|
| dbo.Orders | IX\_Orders\_Cust | IX\_Orders\_Cust\_Dup | 2 |

**Fix:** Drop the extra copy after checking hints and constraints. Each copy slows every write.

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

**Fix:** Cap max server memory (leave OS headroom), raise cost threshold (~50), turn on optimize for ad hoc workloads and backup compression.

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

**Fix:** Turn CHECK_POLICY ON and rotate the password.

### S13 [MEDIUM] Top missing-index requests (Performance, \(instance\))

| database | table | equality | inequality | include | score |
|---|---|---|---|---|---|
| DemoShop | \[DemoShop\].\[dbo\].\[Orders\] | \[Status\] | \[OrderDate\] | \[Total\] | 3655.7 |

**Fix:** Review each request against existing indexes; add only the top few after testing. Do not add all of them.

### D03 [LOW] Left-prefix overlapping indexes (Schema, DemoShop)

| table | narrower_index | covered_by |
|---|---|---|
| dbo.Orders | IX\_Orders\_Cust | IX\_Orders\_Cust\_Date |
| dbo.Orders | IX\_Orders\_Cust\_Dup | IX\_Orders\_Cust\_Date |

**Fix:** The narrower index is usually redundant; confirm usage before dropping.

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

**Fix:** Candidates to drop only after a full business cycle of uptime (month-end included).

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

**Fix:** Disable or rename sa once named admin logins exist.

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
