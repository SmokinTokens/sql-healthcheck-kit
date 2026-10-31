-- sql-healthcheck-kit: remove the health-check login after the check.
SET NOCOUNT ON;
USE msdb;
IF USER_ID('hc_reader') IS NOT NULL DROP USER hc_reader;
GO
USE master;
IF SUSER_ID('hc_reader') IS NOT NULL DROP LOGIN hc_reader;
GO
