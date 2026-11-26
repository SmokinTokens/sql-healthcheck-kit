"""Read-only SQL Server health-check queries.

Every query is a SELECT over catalog views, DMVs, msdb.dbo.backupset,
msdb.dbo.suspect_pages or the msdb SQL Agent job tables (granted columns only).
No DBCC, no xp_/sp_ calls, no writes, no reads of user table rows.
Designed for a least-privilege login (see sql/grant-reader.sql):
VIEW SERVER STATE + VIEW ANY DEFINITION + CONNECT ANY DATABASE
+ SELECT on msdb.dbo.backupset + column-level SELECT on msdb sysjobs,
sysjobhistory, sysjobschedules and sysschedules (no SQLAgentReaderRole).
msdb.dbo.suspect_pages is readable by anyone with access to msdb (Microsoft Learn),
so it needs no extra grant.

SERVER_CHECKS run once in master; DB_CHECKS run in each user database.
PRIV_PROBE (server) and DB_PRIV_PROBE (each database) run first; see runner.collect.
severity 'info' checks are context only and never become findings.
"""

SERVER_CHECKS = [
    {
        "id": "S01", "title": "Server version and uptime", "area": "Inventory",
        "sql": """SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(30)),
 CAST(SERVERPROPERTY('ProductLevel') AS varchar(30)),
 CAST(SERVERPROPERTY('Edition') AS varchar(60)),
 (SELECT cpu_count FROM sys.dm_os_sys_info),
 (SELECT physical_memory_kb/1024 FROM sys.dm_os_sys_info),
 (SELECT DATEDIFF(hour, sqlserver_start_time, SYSDATETIME()) FROM sys.dm_os_sys_info)""",
        "cols": ["version", "level", "edition", "cpus", "ram_mb", "uptime_h"], "severity": "info",
    },
    {
        "id": "S02", "title": "Databases without a recent full backup (7 days)", "area": "Recoverability",
        "sql": """SELECT d.name, d.recovery_model_desc,
 ISNULL(CONVERT(varchar(19), MAX(b.backup_finish_date), 120), 'NEVER')
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset b ON b.database_name = d.name AND b.type = 'D'
WHERE d.name <> 'tempdb' AND d.state = 0
GROUP BY d.name, d.recovery_model_desc
HAVING MAX(b.backup_finish_date) IS NULL OR MAX(b.backup_finish_date) < DATEADD(day, -7, GETDATE())""",
        "cols": ["database", "recovery_model", "last_full"], "severity": "high",
        "fix": "Schedule full backups (weekly or nightly) and test a restore. System databases (master, msdb, model) need backups too.",
    },
    {
        "id": "S03", "title": "FULL recovery databases without log backups (24 h)", "area": "Recoverability",
        "sql": """SELECT d.name, ISNULL(CONVERT(varchar(19), MAX(b.backup_finish_date), 120), 'NEVER')
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset b ON b.database_name = d.name AND b.type = 'L'
WHERE d.recovery_model = 1 AND d.name NOT IN ('model') AND d.state = 0
GROUP BY d.name
HAVING MAX(b.backup_finish_date) IS NULL OR MAX(b.backup_finish_date) < DATEADD(hour, -24, GETDATE())""",
        "cols": ["database", "last_log_backup"], "severity": "high",
        "fix": "The log may grow, but missing msdb history alone does not prove blocked log reuse. "
               "Check D10 (log_reuse_wait_desc, recorded at the last checkpoint) and confirm the real "
               "backup strategy and restore needs with the owner, including external backups or purged history. "
               "With owner approval, schedule log backups to meet the recovery-point objective and test restores. "
               "Preserve the log-backup chain; do not change recovery model as a shortcut. Any recovery-model "
               "change needs separate owner approval, a plan for the log-backup chain and point-in-time restore, "
               "and checks for availability groups, log shipping, replication and mirroring.",
    },
    {
        # Quality of the most recent full backup (type 'D', copy-only included) per online
        # database, from msdb.dbo.backupset bit columns: has_backup_checksums, is_damaged,
        # is_copy_only. BACKUP defaults to NO_CHECKSUM, except for compressed backups or when
        # the 'backup checksum default' server option is on.
        # A copy-only full cannot be a differential base, so "copy-only fulls only" means no
        # regular full is on record. Databases with no full of any copy at all are S02's job.
        # History rows are matched by name AND the current database_guid (sys.database_recovery_status),
        # so a dropped-and-recreated database never inherits an older namesake's backups. Only retained
        # fulls matching the current name and database_guid count; a restore that changes the GUID
        # excludes earlier history. S02 matches by name only, so when the only fulls on record belong
        # to an older copy (other non-NULL GUID), S26 reports 'no full since recreated or restored'
        # instead. A NULL backupset.database_guid is unknown provenance, not proof of an older copy:
        # when no current-copy full exists and any NULL-GUID full is on record (alone or mixed with
        # older-copy fulls), S26 reports 'history unknown' with last_full 'UNKNOWN'.
        # backup_set_id breaks ties between equal finish times (datetime is not unique).
        # sys.database_recovery_status rows need VIEW ANY DATABASE (granted to public by default);
        # if it is revoked the checks return no rows, so the lab proof gate fails rather than passes.
        # https://learn.microsoft.com/sql/relational-databases/system-tables/backupset-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/system-catalog-views/sys-database-recovery-status-transact-sql
        # https://learn.microsoft.com/sql/t-sql/statements/backup-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/backup-restore/copy-only-backups-sql-server
        "id": "S26", "title": "Last full backup without CHECKSUM, damaged, or copy-only only", "area": "Recoverability",
        "sql": """SELECT d.name, ISNULL(CONVERT(varchar(19), f.backup_finish_date, 120),
   CASE WHEN n.backup_set_id IS NULL THEN 'NONE FOR THIS COPY' ELSE 'UNKNOWN' END),
 CASE WHEN f.backup_set_id IS NULL AND n.backup_set_id IS NOT NULL
   THEN 'some fulls on record have no database_guid (history unknown); '
 WHEN f.backup_set_id IS NULL THEN 'no full since recreated or restored; '
 ELSE CONCAT(CASE WHEN f.is_damaged = 1 THEN 'DAMAGED (taken despite errors); ' ELSE '' END,
        CASE WHEN ISNULL(f.has_backup_checksums, 0) = 0 THEN 'no CHECKSUM; ' ELSE '' END,
        CASE WHEN r.backup_set_id IS NULL THEN 'copy-only fulls only; ' ELSE '' END) END
FROM sys.databases d
JOIN sys.database_recovery_status rs ON rs.database_id = d.database_id AND rs.database_guid IS NOT NULL
OUTER APPLY (SELECT TOP (1) b.backup_set_id, b.backup_finish_date, b.has_backup_checksums, b.is_damaged
 FROM msdb.dbo.backupset b
 WHERE b.database_name = d.name AND b.database_guid = rs.database_guid AND b.type = 'D'
 ORDER BY b.backup_finish_date DESC, b.backup_set_id DESC) f
OUTER APPLY (SELECT TOP (1) b2.backup_set_id FROM msdb.dbo.backupset b2
 WHERE b2.database_name = d.name AND b2.database_guid = rs.database_guid AND b2.type = 'D'
   AND b2.is_copy_only = 0) r
OUTER APPLY (SELECT TOP (1) b3.backup_set_id FROM msdb.dbo.backupset b3
 WHERE b3.database_name = d.name AND b3.type = 'D'
   AND b3.database_guid IS NOT NULL AND b3.database_guid <> rs.database_guid) o
OUTER APPLY (SELECT TOP (1) b4.backup_set_id FROM msdb.dbo.backupset b4
 WHERE b4.database_name = d.name AND b4.type = 'D' AND b4.database_guid IS NULL) n
WHERE d.name <> 'tempdb' AND d.state = 0
  AND ((f.backup_set_id IS NOT NULL
        AND (ISNULL(f.has_backup_checksums, 0) = 0 OR f.is_damaged = 1 OR r.backup_set_id IS NULL))
       OR (f.backup_set_id IS NULL AND (o.backup_set_id IS NOT NULL OR n.backup_set_id IS NOT NULL)))""",
        "cols": ["database", "last_full", "issues"], "severity": "medium",
        "fix": "Take full backups WITH CHECKSUM (or turn on the 'backup checksum default' server option) so "
               "the backup verifies page checksums and records a backup checksum. With the default "
               "STOP_ON_ERROR a bad page stops the backup; CONTINUE_AFTER_ERROR lets it finish and marks it "
               "damaged. Checksums do not prove a backup restores: test a restore. A DAMAGED backup was "
               "taken despite errors: run DBCC CHECKDB, then plan a clean full with the backup owner (see below). 'Copy-only fulls only' means "
               "no regular full is on record here: first check the real backup strategy with its owner "
               "(another tool may take the regular fulls). A new regular full resets the differential base "
               "for later differential backups, so do not add one without that check. 'No full since "
               "recreated or restored' means every full on record belongs to an older copy of the "
               "database: check with the backup owner, then plan a new full (see below). 'History unknown' means no full matches the current "
               "copy and some fulls on record have no database_guid, so this server cannot tell which copy "
               "they belong to: confirm a current full exists another way. Before taking ANY new regular full, "
               "check the backup strategy with its owner: it becomes the base for later differential "
               "backups, so it must be kept in the same retained restore chain (or use COPY_ONLY).",
    },
    {
        # The most recent full backup has no native backup encryption recorded in msdb:
        # encryptor_type is NULL and key_algorithm is NULL or NO_Encryption. Only these
        # backup-bound columns are used. The database's CURRENT TDE state (sys.databases.
        # is_encrypted) says nothing about a backup taken earlier, and backupset records no TDE
        # state, so TDE protection of a historical backup cannot be proved here and is not used.
        # Express and Web editions cannot encrypt backups, so they are left out to avoid a
        # finding with no fix. Same current-incarnation match and tie-break as S26.
        # https://learn.microsoft.com/sql/relational-databases/system-tables/backupset-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/backup-restore/backup-encryption
        "id": "S27", "title": "Last full backup: native backup encryption not recorded", "area": "Security",
        "sql": """SELECT d.name, CONVERT(varchar(19), f.backup_finish_date, 120)
FROM sys.databases d
JOIN sys.database_recovery_status rs ON rs.database_id = d.database_id AND rs.database_guid IS NOT NULL
CROSS APPLY (SELECT TOP (1) b.backup_finish_date, b.encryptor_type, b.key_algorithm
 FROM msdb.dbo.backupset b
 WHERE b.database_name = d.name AND b.database_guid = rs.database_guid AND b.type = 'D'
 ORDER BY b.backup_finish_date DESC, b.backup_set_id DESC) f
WHERE d.name <> 'tempdb' AND d.state = 0 AND f.encryptor_type IS NULL
  AND UPPER(ISNULL(f.key_algorithm, N'NO_ENCRYPTION')) = N'NO_ENCRYPTION'
  AND CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) NOT LIKE N'Express%'
  AND CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) NOT LIKE N'Web%'""",
        "cols": ["database", "last_full"], "severity": "low",
        "fix": "msdb records no native backup encryption for this backup. It may still be protected another "
               "way: TDE that was on when it was taken (backup history cannot show this), encrypted storage, "
               "or a backup tool that encrypts. Verify how the backup files are protected before changing "
               "anything. If they are not protected, anyone who gets a copy of a file can restore it and read "
               "the data: encrypt backups (BACKUP ... WITH ENCRYPTION, using a certificate or asymmetric key) "
               "or use TDE, and back up that certificate and its private key to a separate safe place: "
               "without it the backup cannot be restored.",
    },
    {
        # Certificates in master that a restore depends on: the TDE protector of a database
        # (sys.dm_database_encryption_keys.encryptor_thumbprint) or the encryptor of a native
        # encrypted backup still in msdb history (backupset.encryptor_thumbprint). Two issues:
        # 1. pvt_key_last_backup_date is NULL: no private-key export (BACKUP CERTIFICATE ... WITH
        #    PRIVATE KEY) is recorded on this server. It is NOT proof that no copy exists: a
        #    certificate created from backup files, or copied another way, can also read NULL.
        # 2. expiry_date has passed or is within 30 days, ONLY for a certificate that encrypted a
        #    backup in the last 30 days: new encrypted backups fail with an expired certificate
        #    (Msg 3096), restores still work. TDE does not enforce expiry, so a TDE-only
        #    certificate is never listed for its date.
        # expiry_date is in UTC (CREATE CERTIFICATE EXPIRY_DATE), so it is compared with
        # GETUTCDATE(); backup_finish_date is server-local, so it is compared with GETDATE().
        # tempdb (database_id 2) is left out of the TDE count: it is encrypted automatically
        # whenever any user database uses TDE, so it is not a separate dependency.
        # Unused certificates (no TDE database, no encrypted backup on record) are left out,
        # including the built-in ##MS_...## ones. The reader needs VIEW ANY DEFINITION
        # (sys.certificates), VIEW SERVER STATE (the DMV) and SELECT on msdb.dbo.backupset.
        # Never advise dropping or replacing a listed certificate: old backups need it to restore.
        # https://learn.microsoft.com/sql/relational-databases/system-catalog-views/sys-certificates-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-database-encryption-keys-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/security/encryption/transparent-data-encryption
        # https://learn.microsoft.com/sql/relational-databases/backup-restore/backup-encryption
        # https://learn.microsoft.com/sql/t-sql/statements/backup-certificate-transact-sql
        "id": "S29", "title": "Certificates protecting TDE or backups: key export not recorded, or expiring",
        "area": "Recoverability",
        "sql": """SELECT c.name, CAST(t.n AS varchar(10)), ISNULL(CONVERT(varchar(19), u.last_used, 120), 'NONE'),
 ISNULL(CONVERT(varchar(19), c.pvt_key_last_backup_date, 120), 'NOT RECORDED'),
 CONVERT(varchar(19), c.expiry_date, 120),
 CONCAT(CASE WHEN c.pvt_key_last_backup_date IS NULL THEN 'private key export not recorded; ' ELSE '' END,
        CASE WHEN u.last_used >= DATEADD(day, -30, GETDATE()) AND c.expiry_date < GETUTCDATE()
               THEN 'EXPIRED: new encrypted backups with it fail; '
             WHEN u.last_used >= DATEADD(day, -30, GETDATE()) AND c.expiry_date < DATEADD(day, 30, GETUTCDATE())
               THEN 'expires within 30 days: new encrypted backups with it will fail; '
             ELSE '' END)
FROM master.sys.certificates c
CROSS APPLY (SELECT COUNT(*) AS n FROM sys.dm_database_encryption_keys k
 WHERE k.encryptor_thumbprint = c.thumbprint AND k.database_id <> 2) t
CROSS APPLY (SELECT MAX(b.backup_finish_date) AS last_used FROM msdb.dbo.backupset b
 WHERE b.encryptor_thumbprint = c.thumbprint) u
WHERE (t.n > 0 OR u.last_used IS NOT NULL)
  AND (c.pvt_key_last_backup_date IS NULL
       OR (u.last_used >= DATEADD(day, -30, GETDATE()) AND c.expiry_date < DATEADD(day, 30, GETUTCDATE())))""",
        "cols": ["certificate", "tde_databases", "last_encrypted_backup", "key_exported", "expiry_utc", "issues"],
        "severity": "medium",
        "fix": "Do not drop, replace or renew a listed certificate in place: TDE databases and old encrypted "
               "backups need this exact certificate (matched by thumbprint) to restore. 'Private key export not "
               "recorded' means this server has no record of BACKUP CERTIFICATE ... WITH PRIVATE KEY for it; a copy "
               "may still exist (a certificate created from backup files also shows no export), so first ask the "
               "owner whether the certificate file and private-key file are kept safe. If not, back them up now "
               "(BACKUP CERTIFICATE ... TO FILE ... WITH PRIVATE KEY (FILE ..., ENCRYPTION BY PASSWORD ...)), store "
               "access-controlled copies of both files off this server (another machine or secure storage, not "
               "just another folder here) and away from the database backups, keep the password somewhere else "
               "again, and test a restore "
               "on another server. Without them a TDE database or encrypted backup cannot be restored anywhere else. "
               "'Expires' or 'EXPIRED' applies to backup encryption only (TDE ignores the date): create a new "
               "certificate, back it up the same way, switch the backup jobs to it, and keep the old certificate "
               "for as long as any backup taken with it is kept.",
    },
    {
        "id": "S04", "title": "Risky database options", "area": "Configuration",
        "sql": """SELECT name,
 CONCAT(CASE WHEN is_auto_shrink_on = 1 THEN 'AUTO_SHRINK ON; ' ELSE '' END,
        CASE WHEN is_auto_close_on = 1 THEN 'AUTO_CLOSE ON; ' ELSE '' END,
        CASE WHEN page_verify_option <> 2 THEN CONCAT('PAGE_VERIFY ', page_verify_option_desc, '; ') ELSE '' END,
        CASE WHEN is_trustworthy_on = 1 AND name <> 'msdb' THEN 'TRUSTWORTHY ON; ' ELSE '' END)
FROM sys.databases
WHERE database_id > 4 AND (is_auto_shrink_on = 1 OR is_auto_close_on = 1 OR page_verify_option <> 2
   OR (is_trustworthy_on = 1 AND name <> 'msdb'))""",
        "cols": ["database", "options"], "severity": "high",
        "fix": "Set AUTO_SHRINK OFF, AUTO_CLOSE OFF and PAGE_VERIFY CHECKSUM. Set TRUSTWORTHY OFF unless an application feature needs it (for example cross-database Service Broker). Use a change window.",
    },
    {
        "id": "S05", "title": "Old compatibility level", "area": "Configuration",
        "sql": """SELECT name, compatibility_level,
 CAST(LEFT(CAST(SERVERPROPERTY('ProductMajorVersion') AS varchar(4)), 4) AS int) * 10
FROM sys.databases
WHERE database_id > 4
  AND compatibility_level < CAST(SERVERPROPERTY('ProductMajorVersion') AS int) * 10""",
        "cols": ["database", "compat_level", "server_level"], "severity": "medium",
        "fix": "Plan a tested upgrade of the compatibility level (turn on Query Store first to catch plan regressions).",
    },
    {
        "id": "S06", "title": "Percent-based file growth", "area": "Configuration",
        "sql": """SELECT DB_NAME(database_id), name, type_desc, CONCAT(growth, '%'), size/128
FROM sys.master_files WHERE is_percent_growth = 1 AND database_id <> 2""",
        "cols": ["database", "file", "type", "growth", "size_mb"], "severity": "low",
        "fix": "Use fixed growth (for example 256 MB data, 128 MB log).",
    },
    {
        "id": "S07", "title": "Instance settings left at defaults", "area": "Configuration",
        "sql": """SELECT name, CAST(value_in_use AS varchar(20))
FROM sys.configurations
WHERE (name = 'max server memory (MB)' AND CAST(value_in_use AS bigint) = 2147483647)
   OR (name = 'cost threshold for parallelism' AND CAST(value_in_use AS int) = 5)
   OR (name = 'optimize for ad hoc workloads' AND CAST(value_in_use AS int) = 0)
   OR (name = 'max degree of parallelism' AND CAST(value_in_use AS int) = 0
       AND (SELECT cpu_count FROM sys.dm_os_sys_info) > 8)
   OR (name = 'backup compression default' AND CAST(value_in_use AS int) = 0)""",
        "cols": ["setting", "value"], "severity": "medium",
        "fix": "Cap max server memory (leave OS headroom). Raise cost threshold for parallelism in small steps and watch a full business cycle. Set MAXDOP per the Microsoft NUMA guidance (8 on one NUMA node with more than 8 logical CPUs). Consider optimize for ad hoc workloads, and backup compression if CPU allows.",
    },
    {
        "id": "S08", "title": "Sysadmin members (non-system)", "area": "Security",
        "sql": """SELECT m.name, m.type_desc, CASE m.is_disabled WHEN 1 THEN 'disabled' ELSE 'enabled' END
FROM sys.server_role_members rm
JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id AND r.name = 'sysadmin'
JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id
WHERE m.name COLLATE Latin1_General_CI_AS NOT LIKE 'NT SERVICE\\%' AND m.name NOT LIKE '##%'""",
        "cols": ["login", "type", "state"], "severity": "medium",
        "fix": "Keep sysadmin to named admins only. Application logins get database roles, not sysadmin.",
    },
    {
        "id": "S09", "title": "SQL logins with password policy off", "area": "Security",
        "sql": """SELECT name, CASE is_policy_checked WHEN 1 THEN 'on' ELSE 'off' END,
 CASE is_expiration_checked WHEN 1 THEN 'on' ELSE 'off' END, CASE is_disabled WHEN 1 THEN 'disabled' ELSE 'enabled' END
FROM sys.sql_logins WHERE is_policy_checked = 0 AND name NOT LIKE '##%'""",
        "cols": ["login", "policy", "expiry", "state"], "severity": "medium",
        "fix": "Turn CHECK_POLICY ON and rotate the password. This also turns on expiry and lockout, which can break an application login; set CHECK_EXPIRATION to match your password-rotation process.",
    },
    {
        "id": "S10", "title": "'sa' login enabled", "area": "Security",
        "sql": """SELECT name FROM sys.sql_logins WHERE principal_id = 1 AND is_disabled = 0""",
        "cols": ["login"], "severity": "low",
        "fix": "Disable sa once named admin logins exist. A disabled login can still be impersonated, so also review IMPERSONATE grants.",
    },
    {
        "id": "S11", "title": "tempdb data files vs CPUs", "area": "Configuration",
        "sql": """SELECT COUNT(*), (SELECT cpu_count FROM sys.dm_os_sys_info)
FROM sys.master_files WHERE database_id = 2 AND type = 0
HAVING COUNT(*) < CASE WHEN (SELECT cpu_count FROM sys.dm_os_sys_info) > 8 THEN 8
                       ELSE (SELECT cpu_count FROM sys.dm_os_sys_info) END""",
        "cols": ["tempdb_data_files", "cpus"], "severity": "low",
        "fix": "Use one tempdb data file per logical CPU up to 8, all the same size. Add files in groups of 4 only if allocation contention remains.",
    },
    {
        "id": "S12", "title": "Top waits since startup", "area": "Performance",
        "sql": """SELECT TOP (8) wait_type, CAST(wait_time_ms/1000.0 AS decimal(12,1)),
 CAST(100.0 * wait_time_ms / NULLIF(SUM(wait_time_ms) OVER (), 0) AS decimal(5,1))
FROM sys.dm_os_wait_stats
WHERE wait_time_ms > 0 AND wait_type NOT IN (
 'SLEEP_TASK','BROKER_TASK_STOP','BROKER_TO_FLUSH','SQLTRACE_BUFFER_FLUSH','CLR_AUTO_EVENT','CLR_MANUAL_EVENT',
 'LAZYWRITER_SLEEP','SOS_WORK_DISPATCHER','XE_TIMER_EVENT','XE_DISPATCHER_WAIT','REQUEST_FOR_DEADLOCK_SEARCH',
 'LOGMGR_QUEUE','CHECKPOINT_QUEUE','FT_IFTS_SCHEDULER_IDLE_WAIT','BROKER_EVENTHANDLER','DIRTY_PAGE_POLL',
 'HADR_FILESTREAM_IOMGR_IOCOMPLETION','SP_SERVER_DIAGNOSTICS_SLEEP','QDS_PERSIST_TASK_MAIN_LOOP_SLEEP',
 'QDS_ASYNC_QUEUE','QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP','WAITFOR','BROKER_RECEIVE_WAITFOR',
 'ONDEMAND_TASK_QUEUE','SLEEP_SYSTEMTASK','SLEEP_DBSTARTUP','SLEEP_DCOMSTARTUP','SLEEP_MASTERDBREADY',
 'SLEEP_MASTERMDREADY','SLEEP_MASTERUPGRADED','SLEEP_MSDBSTARTUP','SLEEP_TEMPDBSTARTUP','PWAIT_EXTENSIBILITY_CLEANUP_TASK',
 'PREEMPTIVE_OS_FLUSHFILEBUFFERS','PARALLEL_REDO_DRAIN_WORKER','PARALLEL_REDO_LOG_CACHE','PARALLEL_REDO_TRAN_LIST',
 'PARALLEL_REDO_WORKER_SYNC','PARALLEL_REDO_WORKER_WAIT_WORK','PVS_PREALLOCATE','SOS_WORKER_MIGRATION','VDI_CLIENT_OTHER',
 'XE_LIVE_TARGET_TVF','PREEMPTIVE_XE_GETTARGETSTATE','PREEMPTIVE_OS_LIBRARYOPS','STARTUP_DEPENDENCY_MANAGER',
 'DISPATCHER_QUEUE_SEMAPHORE','SQLTRACE_INCREMENTAL_FLUSH_SLEEP','AZURE_IMDS_VERSIONS','PWAIT_ALL_COMPONENTS_INITIALIZED',
 'HADR_WORK_QUEUE','HADR_TIMER_TASK','HADR_CLUSAPI_CALL','FT_IFTSHC_MUTEX','SNI_HTTP_ACCEPT','WAIT_XTP_OFFLINE_CKPT_NEW_LOG')
ORDER BY wait_time_ms DESC""",
        "cols": ["wait_type", "seconds", "pct"], "severity": "info",
    },
    {
        "id": "S13", "title": "Top missing-index requests", "area": "Performance",
        "sql": """SELECT TOP (10) DB_NAME(d.database_id), d.statement,
 ISNULL(d.equality_columns, ''), ISNULL(d.inequality_columns, ''), ISNULL(d.included_columns, ''),
 CAST(s.avg_total_user_cost * s.avg_user_impact * (s.user_seeks + s.user_scans) AS decimal(14,1))
FROM sys.dm_db_missing_index_details d
JOIN sys.dm_db_missing_index_groups g ON g.index_handle = d.index_handle
JOIN sys.dm_db_missing_index_group_stats s ON s.group_handle = g.index_group_handle
WHERE d.database_id > 4
ORDER BY 6 DESC""",
        "cols": ["database", "table", "equality", "inequality", "include", "score"], "severity": "medium",
        "fix": "Review each request against existing indexes; add only the top few after testing. Do not add all of them.",
    },
    {
        "id": "S14", "title": "Top queries by total CPU", "area": "Performance",
        "sql": """SELECT TOP (5) ISNULL(DB_NAME(CAST(pa.value AS int)), '?'), qs.execution_count,
 qs.total_worker_time/1000, qs.total_logical_reads,
 REPLACE(REPLACE(LEFT(SUBSTRING(st.text, qs.statement_start_offset/2 + 1,
   (CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text) ELSE qs.statement_end_offset END
    - qs.statement_start_offset)/2 + 1), 110), CHAR(13), ' '), CHAR(10), ' ')
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
OUTER APPLY sys.dm_exec_plan_attributes(qs.plan_handle) pa
WHERE pa.attribute = 'dbid' AND CAST(pa.value AS int) > 4
ORDER BY qs.total_worker_time DESC""",
        "cols": ["database", "execs", "cpu_ms", "logical_reads", "statement_110ch"], "severity": "info",
        # Query text can hold data in literals. The runner redacts this column unless --full-query-text.
        "redact_col": 4,
    },
    {
        # Averages since each file came online (usually instance start). Microsoft puts the
        # point where users start to feel I/O latency at about 10-15 ms per transfer; 20 ms
        # plus a 1000-I/O floor keeps idle files and short blips out of the findings.
        # Logical file names only: physical paths would leak the drive layout into reports.
        "id": "S21", "title": "Slow file I/O (avg latency >= 20 ms since startup)", "area": "Performance",
        "sql": """SELECT TOP (15) ISNULL(DB_NAME(vfs.database_id), CAST(vfs.database_id AS varchar(10))),
 mf.name, mf.type_desc,
 vfs.num_of_reads, ISNULL(CAST(1.0 * vfs.io_stall_read_ms / NULLIF(vfs.num_of_reads, 0) AS decimal(12,1)), 0),
 vfs.num_of_writes, ISNULL(CAST(1.0 * vfs.io_stall_write_ms / NULLIF(vfs.num_of_writes, 0) AS decimal(12,1)), 0)
FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
JOIN sys.master_files mf ON mf.database_id = vfs.database_id AND mf.file_id = vfs.file_id
WHERE (vfs.num_of_reads >= 1000 AND vfs.io_stall_read_ms >= 20 * vfs.num_of_reads)
   OR (vfs.num_of_writes >= 1000 AND vfs.io_stall_write_ms >= 20 * vfs.num_of_writes)
ORDER BY vfs.io_stall_read_ms + vfs.io_stall_write_ms DESC""",
        "cols": ["database", "file", "type", "reads", "avg_read_ms", "writes", "avg_write_ms"],
        "severity": "medium",
        "fix": "These are averages since startup and hide spikes: take two snapshots of "
               "sys.dm_io_virtual_file_stats a few minutes apart under normal load and compare. "
               "If still slow, check the storage path (disk queue, SAN/VM host, antivirus scanning "
               "data files) and the queries driving the I/O (S12 PAGEIOLATCH/WRITELOG waits, S14).",
    },
    {
        # msdb.dbo.suspect_pages: one row per page that failed with a minor 823 or an 824
        # error (max 1,000 rows). event_type 1/2/3 = 823-824 error / bad checksum / torn page;
        # 4/5/7 = restored / repaired / deallocated, so those are left out.
        # https://learn.microsoft.com/sql/relational-databases/system-tables/suspect-pages-transact-sql
        "id": "S22", "title": "Suspect pages (823/824 errors) in msdb.dbo.suspect_pages", "area": "Integrity",
        "sql": """SELECT TOP (20) ISNULL(DB_NAME(sp.database_id), CAST(sp.database_id AS varchar(10))),
 sp.file_id, sp.page_id,
 CASE sp.event_type WHEN 1 THEN '823/824 error' WHEN 2 THEN 'bad checksum' ELSE 'torn page' END,
 sp.error_count, CONVERT(varchar(19), sp.last_update_date, 120)
FROM msdb.dbo.suspect_pages sp
WHERE sp.event_type IN (1, 2, 3)
ORDER BY sp.last_update_date DESC""",
        "cols": ["database", "file_id", "page_id", "error", "count", "last_seen"], "severity": "high",
        "fix": "A recorded suspect_pages entry is not proof of a read-error event or current corruption: "
               "rows can be added or changed manually and can remain after a fix. Treat it as possible "
               "corruption: have a DBA run DBCC CHECKDB WITH NO_INFOMSGS, ALL_ERRORMSGS in a quiet window, "
               "check SQL Server and storage logs, and confirm clean, tested backups. Plan a page or full "
               "restore only if investigation confirms it is needed. A page can be listed and still be fine. "
               "msdb keeps up to 1,000 entries; preserve the evidence before any owner-approved cleanup.",
    },
    {
        # DATABASEPROPERTYEX(name, 'LastGoodCheckDbTime'): last successful DBCC CHECKDB;
        # 1900-01-01 = never; NULL = invalid input (the property needs SQL Server 2016 SP2,
        # 2017 CU9, 2019 or later). On an AG database it reports the primary's CHECKDB.
        # https://learn.microsoft.com/sql/t-sql/functions/databasepropertyex-transact-sql
        "id": "S23", "title": "DBCC CHECKDB overdue or unverifiable (7 days)", "area": "Integrity",
        "sql": """SELECT d.name,
 CASE WHEN x.t IS NULL THEN 'UNKNOWN' WHEN x.t < '19000102' THEN 'NEVER'
      ELSE CONVERT(varchar(19), x.t, 120) END
FROM sys.databases d
CROSS APPLY (SELECT CAST(DATABASEPROPERTYEX(d.name, 'LastGoodCheckDbTime') AS datetime) AS t) x
WHERE d.name <> 'tempdb' AND d.state = 0 AND d.source_database_id IS NULL
  AND (x.t IS NULL OR x.t < DATEADD(day, -7, GETDATE()))""",
        "cols": ["database", "last_good_checkdb"], "severity": "medium",
        "fix": "Schedule DBCC CHECKDB at least weekly for every database, system databases included "
               "(for example Ola Hallengren's DatabaseIntegrityCheck), and alert on failure. Run it "
               "off-peak: it uses tempdb and I/O. UNKNOWN means the date could not be read "
               "(the property returned NULL); a server older than SQL Server 2016 SP2 / 2017 CU9 "
               "is one cause. Check the date there with a DBA login.",
    },
    {
        # SQL Agent job outcome rows (step_id 0) with run_status 0 = Failed, started in the
        # last 7 server-local calendar days at the current time of day, not exactly 168 hours
        # across daylight-saving changes (run_date yyyyMMdd, run_time HHmmss = run start).
        # The run_date-only term is a coarse prefilter; packed date+time preserves seconds. Reads only the
        # columns granted in sql/grant-reader.sql: never sysjobhistory.message (step output
        # can hold paths or data) or sysjobs.owner_sid. COUNT(col), not COUNT(*): the reader
        # holds column-level SELECT only. Agent keeps 1,000 history rows in total and 100 per
        # job by default, so older failures may already be purged.
        "id": "S24", "title": "SQL Agent jobs that failed in the last 7 days", "area": "Recoverability",
        "sql": """;WITH f AS (
 SELECT h.job_id, COUNT(h.instance_id) AS fails,
  MAX(CAST(h.run_date AS bigint) * 1000000 + h.run_time) AS last_run
 FROM msdb.dbo.sysjobhistory h
 WHERE h.step_id = 0 AND h.run_status = 0
   AND h.run_date >= CAST(CONVERT(char(8), DATEADD(day, -7, GETDATE()), 112) AS int)
   AND CAST(h.run_date AS bigint) * 1000000 + h.run_time >=
    CAST(CONVERT(char(8), DATEADD(day, -7, GETDATE()), 112) AS bigint) * 1000000
    + DATEPART(hour, DATEADD(day, -7, GETDATE())) * 10000
    + DATEPART(minute, DATEADD(day, -7, GETDATE())) * 100 + DATEPART(second, DATEADD(day, -7, GETDATE()))
 GROUP BY h.job_id)
SELECT TOP (20) j.name, CASE j.enabled WHEN 1 THEN 'enabled' ELSE 'disabled' END, f.fails,
 CONVERT(varchar(19), DATEADD(second, CAST(f.last_run % 100 + (f.last_run / 100 % 100) * 60
   + (f.last_run / 10000 % 100) * 3600 AS int),
   CONVERT(datetime, CONVERT(char(8), f.last_run / 1000000), 112)), 120)
FROM f JOIN msdb.dbo.sysjobs j ON j.job_id = f.job_id
ORDER BY f.last_run DESC""",
        "cols": ["job", "job_state", "failed_runs_7d", "last_failed_run_start"], "severity": "medium",
        "fix": "Open each job's history (SSMS: SQL Server Agent > Jobs > right-click > View History) and "
               "read the failing step's message; this report leaves messages out on purpose because they "
               "can hold paths or data. Fix the cause, then add a failure notification (operator plus "
               "Database Mail) so the next failure is not silent. Agent keeps 1,000 history rows (100 per "
               "job) by default, so an empty result can also mean the history was already purged.",
    },
    {
        # Enabled jobs with no enabled schedule never run on their own. Some are on purpose
        # (started by an alert, another job or an application), so this is low severity.
        "id": "S25", "title": "Enabled SQL Agent jobs with no enabled schedule", "area": "Configuration",
        "sql": """SELECT TOP (50) j.name
FROM msdb.dbo.sysjobs j
WHERE j.enabled = 1 AND NOT EXISTS (
 SELECT js.schedule_id FROM msdb.dbo.sysjobschedules js
 JOIN msdb.dbo.sysschedules s ON s.schedule_id = js.schedule_id
 WHERE js.job_id = j.job_id AND s.enabled = 1)
ORDER BY j.name""",
        "cols": ["job"], "severity": "low",
        "fix": "Check that each job is meant to start only on demand (from an alert, another job or an "
               "application). If it should run on a timetable, attach or enable a schedule; if it is no "
               "longer used, disable it. A schedule that is enabled but already ended (one-time or past "
               "its end date) is not detected here.",
    },
]

DB_CHECKS = [
    {
        "id": "D01", "title": "Large heaps (tables without a clustered index)", "area": "Schema",
        "sql": """SELECT SCHEMA_NAME(t.schema_id) + '.' + t.name, SUM(p.rows)
FROM sys.tables t JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id = 0
WHERE t.is_ms_shipped = 0
GROUP BY t.schema_id, t.name HAVING SUM(p.rows) >= 10000""",
        "cols": ["table", "rows"], "severity": "medium",
        "fix": "Review with the table owner first: some heaps are intentional (staging, bulk-load or "
               "insert-only tables). If a clustered index is wanted, pick a narrow, ever-increasing key, test "
               "it against the real workload, check disk and log space, and create it in an approved "
               "maintenance window: it rewrites the table and rebuilds every nonclustered index, and an "
               "offline build blocks access to the table.",
    },
    {
        "id": "D02", "title": "Duplicate indexes (same key columns)", "area": "Schema",
        "sql": """;WITH k AS (
 SELECT i.object_id, i.index_id, i.name,
  STUFF((SELECT ',' + CAST(ic.column_id AS varchar(10)) + CASE ic.is_descending_key WHEN 1 THEN 'd' ELSE '' END
         FROM sys.index_columns ic WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0
         ORDER BY ic.key_ordinal FOR XML PATH('')), 1, 1, '') AS keycols
 FROM sys.indexes i JOIN sys.tables t ON t.object_id = i.object_id
 WHERE t.is_ms_shipped = 0 AND i.index_id > 0 AND i.is_hypothetical = 0)
SELECT OBJECT_SCHEMA_NAME(a.object_id) + '.' + OBJECT_NAME(a.object_id), a.name, b.name, a.keycols
FROM k a JOIN k b ON a.object_id = b.object_id AND a.keycols = b.keycols AND a.index_id < b.index_id""",
        "cols": ["table", "index_a", "index_b", "key_column_ids"], "severity": "medium",
        "fix": "Potential duplicates: the keys match, but INCLUDE columns, filters and uniqueness are not compared. Never drop unique indexes or indexes backing PRIMARY KEY or UNIQUE constraints as part of this cleanup. Compare the full definitions and usage, check index hints that name either index, and obtain owner approval before removing any other index. Each extra index adds overhead to inserts, deletes and key updates.",
    },
    {
        "id": "D03", "title": "Left-prefix overlapping indexes", "area": "Schema",
        "sql": """;WITH k AS (
 SELECT i.object_id, i.index_id, i.name, i.is_unique,
  STUFF((SELECT ',' + CAST(ic.column_id AS varchar(10))
         FROM sys.index_columns ic WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0
         ORDER BY ic.key_ordinal FOR XML PATH('')), 1, 1, '') AS keycols
 FROM sys.indexes i JOIN sys.tables t ON t.object_id = i.object_id
 WHERE t.is_ms_shipped = 0 AND i.index_id > 1 AND i.is_hypothetical = 0)
SELECT OBJECT_SCHEMA_NAME(a.object_id) + '.' + OBJECT_NAME(a.object_id), a.name, b.name
FROM k a JOIN k b ON a.object_id = b.object_id AND a.index_id <> b.index_id
 AND b.keycols LIKE a.keycols + ',%' AND a.is_unique = 0""",
        "cols": ["table", "narrower_index", "covered_by"], "severity": "low",
        "fix": "Potential overlap: the wider index can often serve seeks that use the narrower one, but INCLUDE columns and filters are not compared. Never drop unique indexes or indexes backing PRIMARY KEY or UNIQUE constraints as part of this cleanup. Compare the full definitions and usage, check index hints that name either index, and obtain owner approval before removing any other index.",
    },
    {
        "id": "D04", "title": "Untrusted foreign keys / check constraints", "area": "Schema",
        "sql": """SELECT OBJECT_SCHEMA_NAME(parent_object_id) + '.' + OBJECT_NAME(parent_object_id), name, 'FK'
FROM sys.foreign_keys WHERE is_not_trusted = 1 AND is_disabled = 0
UNION ALL
SELECT OBJECT_SCHEMA_NAME(parent_object_id) + '.' + OBJECT_NAME(parent_object_id), name, 'CHECK'
FROM sys.check_constraints WHERE is_not_trusted = 1 AND is_disabled = 0""",
        "cols": ["table", "constraint", "kind"], "severity": "low",
        "fix": "Re-validate WITH CHECK CHECK CONSTRAINT in a change window so the optimizer can trust it.",
    },
    {
        "id": "D05", "title": "Write-only indexes (writes, no reads since startup)", "area": "Schema",
        "sql": """SELECT OBJECT_SCHEMA_NAME(i.object_id) + '.' + OBJECT_NAME(i.object_id), i.name,
 s.user_updates, s.user_seeks + s.user_scans + s.user_lookups
FROM sys.indexes i
JOIN sys.dm_db_index_usage_stats s ON s.object_id = i.object_id AND s.index_id = i.index_id AND s.database_id = DB_ID()
WHERE i.index_id > 1 AND i.is_primary_key = 0 AND i.is_unique_constraint = 0
  AND OBJECTPROPERTY(i.object_id, 'IsMsShipped') = 0
  AND s.user_seeks + s.user_scans + s.user_lookups = 0 AND s.user_updates > 0""",
        "cols": ["table", "index", "writes", "reads"], "severity": "low",
        "fix": "Zero recorded reads do not prove an index is unnecessary. Never drop unique indexes or indexes backing PRIMARY KEY or UNIQUE constraints as part of this cleanup. Observe usage over a full business cycle of uptime (month-end included), accounting for usage-counter resets. Compare the full definitions, including INCLUDE columns and filters, check index hints that name the index, and obtain owner approval before removing any other index.",
    },
    {
        "id": "D06", "title": "Database file sizes", "area": "Inventory",
        "sql": """SELECT name, type_desc, size/128, CASE max_size WHEN -1 THEN 'unlimited' ELSE CAST(max_size/128 AS varchar(20)) END
FROM sys.database_files""",
        "cols": ["file", "type", "size_mb", "max_mb"], "severity": "info",
    },
    {
        # Orphaned users: a login-based user whose SID has no login in sys.server_principals.
        # Same test as Microsoft Learn "Troubleshoot orphaned users" (authentication_type_desc
        # = 'INSTANCE'); contained users (DATABASE) and users WITHOUT LOGIN (NONE) are skipped.
        # Readable with VIEW ANY DEFINITION; runs in user databases only.
        "id": "D07", "title": "Orphaned database users (no matching login)", "area": "Security",
        "sql": """SELECT TOP (50) dp.name, dp.type_desc
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid
WHERE sp.sid IS NULL AND dp.authentication_type_desc = 'INSTANCE'
  AND dp.principal_id > 4
ORDER BY dp.name""",
        "cols": ["user", "type"], "severity": "low",
        "fix": "For each user, map it to the right login with ALTER USER <user> WITH LOGIN = <login>. "
               "If nobody needs it and it owns no schema, drop the user. If it owns a schema, leave it in "
               "place: do not change the owner or drop anything as part of this cleanup. Changing a schema "
               "owner drops every permission on the schema itself and on objects in it that have no explicit "
               "owner (grants, denies and grant options), so treat it as a separate, tested change that "
               "records those permissions first, restores them after, and checks application access. "
               "Do not use the deprecated sp_change_users_login. Built-in users (dbo, guest, "
               "INFORMATION_SCHEMA, sys) are not listed. Windows users are not listed (they can still get in "
               "through a Windows group login).",
    },
    {
        # guest with CONNECT lets every login without its own user enter the database as guest.
        # User databases only (the runner skips master, tempdb, msdb and model). Granted or
        # granted WITH GRANT OPTION ('G', 'W') counts; an explicit DENY does not. guest is
        # always principal_id 2, so a case-sensitive database collation cannot hide it.
        "id": "D08", "title": "guest user can connect (CONNECT granted)", "area": "Security",
        "sql": """SELECT dp.name, p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals dp ON dp.principal_id = p.grantee_principal_id
WHERE p.class = 0 AND p.type = 'CO' AND p.state IN ('G', 'W') AND p.grantee_principal_id = 2""",
        "cols": ["user", "state"], "severity": "medium",
        "fix": "Run REVOKE CONNECT FROM guest in this database (Microsoft's best-practice rule for user "
               "databases), after you confirm no application relies on guest access. Logins that need "
               "the database then get their own database user and roles.",
    },
    {
        # sys.dm_db_log_info: one row per virtual log file (VLF) of the current database
        # (SQL Server 2016 SP2 and later). Needs VIEW SERVER STATE, or VIEW DATABASE
        # PERFORMANCE STATE on SQL Server 2022+. Many VLFs, from many small log growths,
        # slow startup, restore and backup. Microsoft logs error 9017 at 10,000 VLFs
        # (2012+); this kit flags earlier, above 1,000, a common DBA rule of thumb.
        # https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-db-log-info-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/errors-events/mssqlserver-9017-database-engine-error
        "id": "D09", "title": "Too many virtual log files (VLFs > 1000)", "area": "Configuration",
        "sql": """SELECT COUNT(li.vlf_sequence_number), CAST(SUM(li.vlf_size_mb) AS decimal(12,1))
FROM sys.dm_db_log_info(DB_ID()) li
HAVING COUNT(li.vlf_sequence_number) > 1000""",
        "cols": ["vlf_count", "log_mb"], "severity": "low",
        "fix": "Plan this with the database owner as an approved maintenance change. Check first for "
               "availability groups, log shipping, replication or mirroring, and keep the log-backup chain: "
               "in FULL recovery take a normal log backup (never switch to SIMPLE just to shrink, which "
               "breaks the chain); in SIMPLE run a CHECKPOINT. Then, in a quiet window, shrink the log file "
               "and grow it back to the size it really needs in one or a few large steps "
               "(ALTER DATABASE ... MODIFY FILE (NAME = ..., SIZE = ...)). Set a fixed growth in MB, not "
               "a tiny or percent growth, so it does not come back. Check the VLF count again after.",
    },
    {
        # sys.databases.log_reuse_wait_desc: why log space cannot be reused right now.
        # NOTHING and CHECKPOINT are routine; any other value (LOG_BACKUP, ACTIVE_TRANSACTION,
        # REPLICATION, AVAILABILITY_REPLICA, ...) can make the log grow until it is full
        # (error 9002). It is a point-in-time value: a short ACTIVE_TRANSACTION can be normal.
        # https://learn.microsoft.com/sql/relational-databases/logs/the-transaction-log-sql-server
        "id": "D10", "title": "Log space held (log_reuse_wait_desc not NOTHING/CHECKPOINT)",
        "area": "Recoverability",
        "sql": """SELECT d.log_reuse_wait_desc, d.recovery_model_desc
FROM sys.databases d
WHERE d.database_id = DB_ID() AND d.log_reuse_wait_desc NOT IN ('NOTHING', 'CHECKPOINT')""",
        "cols": ["log_reuse_wait", "recovery_model"], "severity": "medium",
        "fix": "Act on the reason shown. LOG_BACKUP: schedule regular log backups (see S03). Switching to "
               "SIMPLE recovery is a DBA decision for the whole recovery plan: it breaks the log-backup "
               "chain and is not allowed with log shipping, availability groups or mirroring. ACTIVE_TRANSACTION: find the long open transaction "
               "(sys.dm_tran_database_transactions) and have its owner commit or end it. REPLICATION or "
               "AVAILABILITY_REPLICA: check that the log reader or secondary is running and caught up. "
               "Short REPLICATION or AVAILABILITY_REPLICA waits, LOG_SCAN and DATABASE_SNAPSHOT_CREATION can be "
               "normal. This is the reason recorded at the last checkpoint, not a measure of log pressure: "
               "run the check again to see if the reason stays.",
    },
    {
        # sys.database_query_store_options: one row for the current database (SQL Server
        # 2016+). Needs VIEW DATABASE STATE (2016-2019) or VIEW DATABASE PERFORMANCE STATE
        # (2022+); VIEW SERVER STATE covers both. Flags Query Store OFF (0), READ_ONLY (1)
        # or ERROR (3), and any desired_state that differs from actual_state (Query Store
        # can switch to READ_ONLY on its own, e.g. at its size limit). READ_WRITE (2) and a
        # requested READ_CAPTURE_SECONDARY (4, Query Store for secondary replicas) pass.
        # https://learn.microsoft.com/sql/relational-databases/system-catalog-views/sys-database-query-store-options-transact-sql
        # https://learn.microsoft.com/sql/relational-databases/performance/best-practice-with-the-query-store#Verify
        "id": "D11", "title": "Query Store OFF, READ_ONLY, ERROR or actual mode differs from requested",
        "area": "Configuration",
        "sql": """SELECT q.desired_state_desc, q.actual_state_desc, q.readonly_reason,
 CONCAT(
  CASE WHEN q.readonly_reason & 1 <> 0 THEN 'database read-only; ' ELSE '' END,
  CASE WHEN q.readonly_reason & 2 <> 0 THEN 'single-user; ' ELSE '' END,
  CASE WHEN q.readonly_reason & 4 <> 0 THEN 'emergency mode; ' ELSE '' END,
  CASE WHEN q.readonly_reason & 8 <> 0 THEN 'secondary replica; ' ELSE '' END,
  CASE WHEN q.readonly_reason & 65536 <> 0 THEN 'size limit reached; ' ELSE '' END,
  CASE WHEN q.readonly_reason & 131072 <> 0 THEN 'statement-count memory limit; ' ELSE '' END,
  CASE WHEN q.readonly_reason & 262144 <> 0 THEN 'pending-persistence memory limit (temporary); ' ELSE '' END,
  CASE WHEN q.readonly_reason & 524288 <> 0 THEN 'database disk-size limit; ' ELSE '' END,
  CASE WHEN q.readonly_reason & ~983055 <> 0
       THEN CONCAT('unknown bits ', q.readonly_reason & ~983055, '; ') ELSE '' END) AS readonly_detail,
 q.current_storage_size_mb, q.max_storage_size_mb
FROM sys.database_query_store_options q
WHERE q.actual_state IN (0, 1, 3) OR q.desired_state <> q.actual_state""",
        "cols": ["desired_state", "actual_state", "readonly_reason", "readonly_detail", "storage_mb", "max_storage_mb"],
        "severity": "low",
        "fix": ("Agree any change with the database owner first. OFF: Query Store is off by default before "
                "SQL Server 2022, and restored or upgraded databases keep their old setting; to start capture "
                "run `ALTER DATABASE [name] SET QUERY_STORE = ON (OPERATION_MODE = READ_WRITE)` and watch the "
                "overhead. READ_ONLY when READ_WRITE was requested: the readonly_detail column decodes every "
                "bit of readonly_reason. Database read-only, single-user, emergency and secondary replica can "
                "be expected: do not change them just to restart capture. Size limit reached: check free disk "
                "first, then the owner may raise MAX_STORAGE_SIZE_MB and keep SIZE_BASED_CLEANUP_MODE = AUTO. "
                "Statement-count or pending-persistence memory limit: often temporary; check again later "
                "before changing anything. Database disk-size limit: the database itself is full, a capacity "
                "question for the owner. Unknown bits: look them up in Microsoft's "
                "sys.database_query_store_options page before acting. Set OPERATION_MODE = READ_WRITE again "
                "only when no remaining reason is an expected state of the database. READ_ONLY on request: "
                "someone chose it, so ask before changing it. ERROR: set OPERATION_MODE = READ_WRITE and "
                "check again; on SQL Server 2017+ Microsoft names sp_query_store_consistency_check. Do not "
                "run SET QUERY_STORE CLEAR or CLEAR ALL as routine cleanup: it deletes the captured history "
                "that forced plans and Query Store hints rely on, so treat it as a separate owner decision."),
    },
]

# Privilege probe: read-only functions only. The runner refuses to run when the
# login holds any of these, because then "read-only" would rest on our code alone.
PRIV_PROBE = {
    "id": "P01", "title": "Login privilege probe",
    "sql": """SELECT IS_SRVROLEMEMBER('sysadmin'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER SETTINGS'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY DATABASE'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'CREATE ANY DATABASE'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'SELECT ALL USER SECURABLES'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'IMPERSONATE ANY LOGIN'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY CONNECTION'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER SERVER STATE'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LINKED SERVER'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY CREDENTIAL'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY SERVER ROLE'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ADMINISTER BULK OPERATIONS'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'SHUTDOWN'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER TRACE'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY EVENT SESSION'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY ENDPOINT'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER RESOURCES'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY AVAILABILITY GROUP'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY SERVER AUDIT'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY EVENT NOTIFICATION'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'EXTERNAL ACCESS ASSEMBLY'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'UNSAFE ASSEMBLY'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'AUTHENTICATE SERVER'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER STATE'),
 HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION')""",
    "cols": ["sysadmin", "control_server", "alter_any_login", "alter_settings", "alter_any_database",
             "create_any_database", "select_all_user_securables", "impersonate_any_login", "alter_any_connection",
             "alter_server_state", "alter_any_linked_server", "alter_any_credential", "alter_any_server_role",
             "administer_bulk_operations", "shutdown", "alter_trace", "alter_any_event_session",
             "alter_any_endpoint", "alter_resources", "alter_any_availability_group", "alter_any_server_audit",
             "alter_any_event_notification", "external_access_assembly", "unsafe_assembly", "authenticate_server",
             "view_server_state", "view_any_definition"],
}
TOO_POWERFUL = ("sysadmin", "control_server", "alter_any_login", "alter_settings", "alter_any_database",
                "create_any_database", "select_all_user_securables", "impersonate_any_login", "alter_any_connection",
                "alter_server_state", "alter_any_linked_server", "alter_any_credential", "alter_any_server_role",
                "administer_bulk_operations", "shutdown", "alter_trace", "alter_any_event_session",
                "alter_any_endpoint", "alter_resources", "alter_any_availability_group", "alter_any_server_audit",
                "alter_any_event_notification", "external_access_assembly", "unsafe_assembly", "authenticate_server")

# Per-database probe, run in master, msdb and each user database before any check
# there. Any 1 = the login can change that database (owner, writer, DDL or security
# role, an msdb Agent/Mail/SSIS role, a database-wide write permission, or a write,
# execute or alter grant on any non-system object), so the runner refuses unless
# overridden. Roles that do not exist in a database count as 0.
DB_PRIV_PROBE = {
    "id": "P02", "title": "Database privilege probe",
    "sql": """SELECT ISNULL(IS_ROLEMEMBER('db_owner'), 0), ISNULL(IS_ROLEMEMBER('db_datawriter'), 0),
 ISNULL(IS_ROLEMEMBER('db_ddladmin'), 0), ISNULL(IS_ROLEMEMBER('db_securityadmin'), 0),
 ISNULL(IS_ROLEMEMBER('db_accessadmin'), 0),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'INSERT'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'UPDATE'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'DELETE'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'TAKE OWNERSHIP'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'EXECUTE'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER ANY USER'),
 HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER ANY ROLE'),
 ISNULL(IS_ROLEMEMBER('SQLAgentOperatorRole'), 0) | ISNULL(IS_ROLEMEMBER('SQLAgentUserRole'), 0)
  | ISNULL(IS_ROLEMEMBER('DatabaseMailUserRole'), 0) | ISNULL(IS_ROLEMEMBER('db_ssisadmin'), 0)
  | ISNULL(IS_ROLEMEMBER('db_ssisoperator'), 0),
 CASE WHEN EXISTS (
  SELECT 1 FROM sys.database_permissions p
  LEFT JOIN sys.all_objects o ON p.class = 1 AND o.object_id = p.major_id
  WHERE p.state IN ('G', 'W') AND p.class IN (1, 3, 4, 5, 6, 10, 24, 25)
    AND p.type IN ('IN', 'UP', 'DL', 'EX', 'AL', 'CL', 'TO', 'IM')
    AND NOT (p.class = 1 AND ISNULL(o.is_ms_shipped, 0) = 1)
    AND NOT (p.class = 1 AND ISNULL(OBJECT_SCHEMA_NAME(p.major_id), '') IN ('sys', 'INFORMATION_SCHEMA'))
    AND NOT (p.class = 3 AND p.major_id IN (SCHEMA_ID('sys'), SCHEMA_ID('INFORMATION_SCHEMA')))
    AND (p.grantee_principal_id = DATABASE_PRINCIPAL_ID()
         OR ISNULL(IS_ROLEMEMBER(USER_NAME(p.grantee_principal_id)), 0) = 1)
 ) THEN 1 ELSE 0 END""",
    "cols": ["db_owner", "db_datawriter", "db_ddladmin", "db_securityadmin", "db_accessadmin", "control",
             "alter", "insert", "update", "delete", "take_ownership", "execute", "alter_any_user",
             "alter_any_role", "msdb_agent_mail_ssis_role", "object_or_schema_write_grant"],
}
# System databases probed with DB_PRIV_PROBE before anything runs (tempdb: everyone can write there).
PROBE_SYSTEM_DBS = ("master", "msdb", "model")
