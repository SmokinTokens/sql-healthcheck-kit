"""Read-only SQL Server health-check queries.

Every query is a SELECT over catalog views, DMVs or msdb.dbo.backupset.
No DBCC, no xp_/sp_ calls, no writes, no reads of user table rows.
Designed for a least-privilege login (see sql/grant-reader.sql):
VIEW SERVER STATE + VIEW ANY DEFINITION + CONNECT ANY DATABASE
+ SELECT on msdb.dbo.backupset.

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
        "fix": "Add log backups every 15-60 min, or switch to SIMPLE if point-in-time restore is not needed. The log grows without limit until then.",
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
        "fix": "Set AUTO_SHRINK OFF, AUTO_CLOSE OFF, PAGE_VERIFY CHECKSUM, TRUSTWORTHY OFF (in a change window).",
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
        "fix": "Cap max server memory (leave OS headroom), raise cost threshold (~50), turn on optimize for ad hoc workloads and backup compression.",
    },
    {
        "id": "S08", "title": "Sysadmin members (non-system)", "area": "Security",
        "sql": """SELECT m.name, m.type_desc, CASE m.is_disabled WHEN 1 THEN 'disabled' ELSE 'enabled' END
FROM sys.server_role_members rm
JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id AND r.name = 'sysadmin'
JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id
WHERE m.name NOT LIKE 'NT SERVICE\\%' AND m.name NOT LIKE '##%'""",
        "cols": ["login", "type", "state"], "severity": "medium",
        "fix": "Keep sysadmin to named admins only. Application logins get database roles, not sysadmin.",
    },
    {
        "id": "S09", "title": "SQL logins with password policy off", "area": "Security",
        "sql": """SELECT name, CASE is_policy_checked WHEN 1 THEN 'on' ELSE 'off' END,
 CASE is_expiration_checked WHEN 1 THEN 'on' ELSE 'off' END, CASE is_disabled WHEN 1 THEN 'disabled' ELSE 'enabled' END
FROM sys.sql_logins WHERE is_policy_checked = 0 AND name NOT LIKE '##%'""",
        "cols": ["login", "policy", "expiry", "state"], "severity": "medium",
        "fix": "Turn CHECK_POLICY ON and rotate the password.",
    },
    {
        "id": "S10", "title": "'sa' login enabled", "area": "Security",
        "sql": """SELECT name FROM sys.sql_logins WHERE principal_id = 1 AND is_disabled = 0""",
        "cols": ["login"], "severity": "low",
        "fix": "Disable or rename sa once named admin logins exist.",
    },
    {
        "id": "S11", "title": "tempdb data files vs CPUs", "area": "Configuration",
        "sql": """SELECT COUNT(*), (SELECT cpu_count FROM sys.dm_os_sys_info)
FROM sys.master_files WHERE database_id = 2 AND type = 0
HAVING COUNT(*) < CASE WHEN (SELECT cpu_count FROM sys.dm_os_sys_info) > 8 THEN 8
                       ELSE (SELECT cpu_count FROM sys.dm_os_sys_info) END""",
        "cols": ["tempdb_data_files", "cpus"], "severity": "low",
        "fix": "Use one tempdb data file per core up to 8, all the same size.",
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
]

DB_CHECKS = [
    {
        "id": "D01", "title": "Large heaps (tables without a clustered index)", "area": "Schema",
        "sql": """SELECT SCHEMA_NAME(t.schema_id) + '.' + t.name, SUM(p.rows)
FROM sys.tables t JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id = 0
WHERE t.is_ms_shipped = 0
GROUP BY t.schema_id, t.name HAVING SUM(p.rows) >= 10000""",
        "cols": ["table", "rows"], "severity": "medium",
        "fix": "Add a narrow, ever-increasing clustered key, unless the heap is a staging table by design.",
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
        "fix": "Drop the extra copy after checking hints and constraints. Each copy slows every write.",
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
        "fix": "The narrower index is usually redundant; confirm usage before dropping.",
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
        "fix": "Candidates to drop only after a full business cycle of uptime (month-end included).",
    },
    {
        "id": "D06", "title": "Database file sizes", "area": "Inventory",
        "sql": """SELECT name, type_desc, size/128, CASE max_size WHEN -1 THEN 'unlimited' ELSE CAST(max_size/128 AS varchar(20)) END
FROM sys.database_files""",
        "cols": ["file", "type", "size_mb", "max_mb"], "severity": "info",
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
