-- sql-healthcheck-kit: least-privilege login for the health check.
-- Your DBA runs this (as sysadmin) before the check, and remove-reader.sql after.
--
-- The login can read metadata and DMVs. It cannot read user table rows, change
-- data or change settings. It can see other sessions' query text and the source of
-- views/procedures (VIEW SERVER STATE, VIEW ANY DEFINITION). The tool refuses to
-- run if the login is more powerful.
--
-- This script only creates a NEW login. If a login or msdb user named hc_reader
-- already exists, it stops before it creates or grants anything: an old hc_reader
-- may hold other rights (roles, table grants) that this script cannot see or undo.
-- Run remove-reader.sql first if that hc_reader is yours, or pick another name.
-- The whole script is one batch, so the stop works without sqlcmd -b.
--
-- Password: sqlcmd reads scripting variables from the environment, so set
-- HC_PW in the environment instead of on the command line:
--   read -rs HC_PW && export HC_PW          (PowerShell: $env:HC_PW = Read-Host)
--   sqlcmd -S <server> -E -i grant-reader.sql
-- The password must NOT contain a single quote ('): sqlcmd pastes $(HC_PW) below
-- as plain text, so a quote would break (or change) the CREATE LOGIN statement.
-- Prefer a Windows login? Replace the CREATE LOGIN below with
--   CREATE LOGIN [DOMAIN\svc_hc] FROM WINDOWS;  and change hc_reader to that name.
SET NOCOUNT ON;
IF SUSER_ID('hc_reader') IS NOT NULL
  THROW 50001, 'hc_reader login already exists: nothing was changed. Run remove-reader.sql first, or use another name.', 1;
IF EXISTS (SELECT 1 FROM msdb.sys.database_principals WHERE name = N'hc_reader')
  THROW 50002, 'msdb already has a user named hc_reader: nothing was changed. Run remove-reader.sql first, or use another name.', 1;
CREATE LOGIN hc_reader WITH PASSWORD = N'$(HC_PW)', CHECK_POLICY = ON, DEFAULT_DATABASE = master;
GRANT VIEW SERVER STATE TO hc_reader;       -- DMVs: waits, query stats, missing indexes
GRANT VIEW ANY DEFINITION TO hc_reader;     -- catalog metadata (indexes, constraints, logins list)
GRANT CONNECT ANY DATABASE TO hc_reader;    -- connect to each database for its catalog views
-- EXEC (...) not sp_executesql: on a Latin1_General_100_BIN2 server, SQL Server 2022 on
-- Linux fails every sp_executesql call with Msg 17750 (seen in lab, CU28).
-- msdb: backup history, plus SQL Agent job names, history outcome and schedules (S24, S25).
-- Column-level SELECT only: never sysjobhistory.message (step output) or sysjobs.owner_sid.
-- Not SQLAgentReaderRole: its members are also SQLAgentUserRole and can create and run jobs.
EXEC (N'USE msdb; CREATE USER hc_reader FOR LOGIN hc_reader; GRANT SELECT ON dbo.backupset TO hc_reader;
GRANT SELECT (job_id, name, enabled) ON dbo.sysjobs TO hc_reader;
GRANT SELECT (instance_id, job_id, step_id, run_status, run_date, run_time) ON dbo.sysjobhistory TO hc_reader;
GRANT SELECT (job_id, schedule_id) ON dbo.sysjobschedules TO hc_reader;
GRANT SELECT (schedule_id, enabled) ON dbo.sysschedules TO hc_reader;');
GO
