-- LAB ONLY. Never run this on a real server.
-- Builds LogSprawl, a throwaway database for the transaction-log checks:
--   D09: the log grows in tiny 64 KB steps, so it ends up with well over 1,000 VLFs.
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
-- char(5000) fits one row per 8 KB page, so 20,000 rows log at least 20,000 x 5,000 bytes
-- (about 95 MiB) and in practice one page image each (about 160 MiB). Beyond the default
-- 8 MiB start that is at least about 1,400 growths of 64 KiB, each adding one VLF on
-- SQL Server 2022 (one VLF per growth up to 64 MB), so well over the 1,000 threshold.
-- The lab gate (assert-tlog.py) checks the real count, not this estimate.
DECLARE @i int = 0;
WHILE @i < 20
BEGIN
  ;WITH n AS (SELECT TOP (1000) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) i FROM sys.all_objects)
  INSERT dbo.Filler (Pad) SELECT REPLICATE('x', 5000) FROM n;
  SET @i += 1;
END
GO
