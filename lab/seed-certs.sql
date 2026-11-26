-- LAB ONLY. Never run this on a real server.
-- Plants certificates in master for S29 (encryption-key backup check):
--   LabTdeCert     protects the TDE database CertTde; its private key is never exported
--                  -> S29 lists it: 'private key export not recorded'.
--   LabBackupCert  encrypts a backup of CertBak; private key exported; expires in 10 days
--                  -> S29 lists it: 'expires within 30 days'.
--   LabSafeCert    encrypts a later backup of CertBak; exported; expires in 1 year
--                  -> negative control, not listed.
--   LabUnusedCert  never exported, protects nothing -> negative control, not listed.
-- The master key and .pvk files use the run's random HC_PW (sqlcmd variable from the
-- environment, as in sql/grant-reader.sql); it never appears on a command line.
-- Run it as sa on a disposable container (lab/run-lab.sh does this).
SET NOCOUNT ON;
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = N'##MS_DatabaseMasterKey##')
  CREATE MASTER KEY ENCRYPTION BY PASSWORD = N'$(HC_PW)';
GO
CREATE CERTIFICATE LabTdeCert WITH SUBJECT = N'sqlhc lab TDE certificate';
CREATE CERTIFICATE LabUnusedCert WITH SUBJECT = N'sqlhc lab unused certificate';
GO
-- Expiry dates (UTC, as EXPIRY_DATE is) are computed now, so the fixture stays valid whenever the lab runs.
DECLARE @soon nvarchar(8) = CONVERT(nvarchar(8), DATEADD(day, 10, GETUTCDATE()), 112);
DECLARE @later nvarchar(8) = CONVERT(nvarchar(8), DATEADD(day, 365, GETUTCDATE()), 112);
EXEC (N'CREATE CERTIFICATE LabBackupCert WITH SUBJECT = N''sqlhc lab backup certificate'', EXPIRY_DATE = '''
      + @soon + N''';');
EXEC (N'CREATE CERTIFICATE LabSafeCert WITH SUBJECT = N''sqlhc lab safe certificate'', EXPIRY_DATE = '''
      + @later + N''';');
GO
BACKUP CERTIFICATE LabBackupCert TO FILE = '/var/opt/mssql/data/LabBackupCert.cer'
  WITH PRIVATE KEY (FILE = '/var/opt/mssql/data/LabBackupCert.pvk', ENCRYPTION BY PASSWORD = N'$(HC_PW)');
BACKUP CERTIFICATE LabSafeCert TO FILE = '/var/opt/mssql/data/LabSafeCert.cer'
  WITH PRIVATE KEY (FILE = '/var/opt/mssql/data/LabSafeCert.pvk', ENCRYPTION BY PASSWORD = N'$(HC_PW)');
GO
IF DB_ID('CertTde') IS NULL CREATE DATABASE CertTde;
IF DB_ID('CertBak') IS NULL CREATE DATABASE CertBak;
GO
ALTER DATABASE CertTde SET RECOVERY SIMPLE;
ALTER DATABASE CertBak SET RECOVERY SIMPLE;
GO
USE CertTde;
GO
-- Raises warning 33091 (certificate not backed up): that is the planted defect.
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE LabTdeCert;
GO
USE master;
GO
ALTER DATABASE CertTde SET ENCRYPTION ON;
GO
-- Regular fulls WITH CHECKSUM and native encryption, so S26/S27 do not list CertBak.
-- The LabSafeCert full is taken last, so it is CertBak's latest full.
BACKUP DATABASE CertBak TO DISK = '/var/opt/mssql/data/CertBak_soon.bak'
  WITH INIT, CHECKSUM, ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = LabBackupCert);
GO
BACKUP DATABASE CertBak TO DISK = '/var/opt/mssql/data/CertBak_safe.bak'
  WITH INIT, CHECKSUM, ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = LabSafeCert);
GO
-- Fail loudly if the fixture is not what lab/assert-certs.py expects.
IF (SELECT pvt_key_last_backup_date FROM sys.certificates WHERE name = N'LabBackupCert') IS NULL
  THROW 50020, 'seed-certs: LabBackupCert private key export was not recorded.', 1;
IF (SELECT COUNT(*) FROM sys.dm_database_encryption_keys k JOIN sys.certificates c
      ON c.thumbprint = k.encryptor_thumbprint
    WHERE c.name = N'LabTdeCert' AND k.database_id = DB_ID('CertTde')) <> 1
  THROW 50021, 'seed-certs: CertTde is not protected by LabTdeCert.', 1;
IF (SELECT COUNT(DISTINCT b.encryptor_thumbprint) FROM msdb.dbo.backupset b
    WHERE b.database_name = N'CertBak' AND b.type = 'D' AND b.encryptor_thumbprint IS NOT NULL) <> 2
  THROW 50022, 'seed-certs: msdb does not record two encrypted CertBak fulls.', 1;
PRINT 'seed-certs: LabTdeCert (TDE, not exported), LabBackupCert (expires in 10 days), controls planted';
GO
