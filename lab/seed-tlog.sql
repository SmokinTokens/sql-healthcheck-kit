-- LAB ONLY. Never run this on a real server.
-- Builds LogSprawl, a throwaway database for the transaction-log checks:
--   D09: tiny 64 KB log autogrowth, then small manual growth steps until the real
--        sys.dm_db_log_info count is over 1,000 VLFs (fails loudly if never reached).
--   D10: FULL recovery, one full backup and no log backup, so log_reuse_wait_desc
--        reads LOG_BACKUP.
-- Run it as sa on a disposable container (lab/run-lab.sh does this).
SET NOCOUNT ON;
IF DB_ID('LogSprawl') IS NULL CREATE DATABASE LogSprawl;
GO
ALTER DATABASE LogSprawl SET RECOVERY FULL;
ALTER DATABASE LogSprawl MODIFY FILE (NAME = LogSprawl_log, FILEGROWTH = 64KB); -- defect: tiny log growth
GO
-- A full backup starts the log chain; after it, only a log backup frees log space.
BACKUP DATABASE LogSprawl TO DISK = '/var/opt/mssql/data/LogSprawl_full.bak' WITH INIT, COMPRESSION;
GO
USE LogSprawl;
GO
IF OBJECT_ID('dbo.Filler') IS NULL CREATE TABLE dbo.Filler (Id int IDENTITY PRIMARY KEY, Pad char(5000) NOT NULL);
GO
-- Real logged work after the full backup, so log_reuse_wait_desc reads LOG_BACKUP (D10).
DECLARE @i int = 0;
WHILE @i < 5
BEGIN
  ;WITH n AS (SELECT TOP (1000) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) i FROM sys.all_objects)
  INSERT dbo.Filler (Pad) SELECT REPLICATE('x', 5000) FROM n;
  SET @i += 1;
END
GO
-- D09: grow the log in many small manual steps until the REAL count from
-- sys.dm_db_log_info passes 1,000. An estimate is not enough: lab run 2026-11-25
-- (20,000 inserts with 64 KB autogrowth) stayed at or below 1,000 VLFs. Each 1 MB step
-- adds at least one VLF, so the loop ends after at most about 1,000 steps (about 1 GB
-- of log). The cap makes a seed that never reaches the threshold fail loudly (-b).
DECLARE @vlfs int = (SELECT COUNT(*) FROM sys.dm_db_log_info(DB_ID()));
DECLARE @steps int = 0, @kb bigint, @sql nvarchar(400);
WHILE @vlfs <= 1000 AND @steps < 2500
BEGIN
  SELECT @kb = CAST(size AS bigint) * 8 + 1024 FROM sys.database_files WHERE name = N'LogSprawl_log';
  -- Plain EXEC (...), as in grant-reader.sql (parameterized calls hit Msg 17750 on BIN2 servers).
  SET @sql = N'ALTER DATABASE LogSprawl MODIFY FILE (NAME = LogSprawl_log, SIZE = '
           + CAST(@kb AS nvarchar(20)) + N'KB);';
  EXEC (@sql);
  SET @steps += 1;
  SET @vlfs = (SELECT COUNT(*) FROM sys.dm_db_log_info(DB_ID()));
END
IF @vlfs <= 1000
  THROW 50010, 'seed-tlog: LogSprawl did not reach more than 1000 VLFs; the D09 lab proof cannot run.', 1;
PRINT CONCAT('seed-tlog: LogSprawl VLF count ', @vlfs, ' after ', @steps, ' manual log growth steps');
GO
