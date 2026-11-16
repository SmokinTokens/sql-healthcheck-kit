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
EXEC msdb.sys.sp_executesql
  N'CREATE USER hc_reader FOR LOGIN hc_reader; GRANT SELECT ON dbo.backupset TO hc_reader;'; -- backup history only
GO
