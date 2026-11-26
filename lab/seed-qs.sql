-- LAB ONLY. Never run this on a real server.
-- D11 (Query Store) fixture. Run as sa after seed-demo.sql.
-- defect: QsReadOnly has Query Store ON but in READ_ONLY mode, so it captures nothing new.
-- control: DemoShop gets Query Store explicitly READ_WRITE, so D11 must NOT list it
-- (set here rather than trusting the SQL Server 2022 default for new databases).
SET NOCOUNT ON;
IF DB_ID('QsReadOnly') IS NULL CREATE DATABASE QsReadOnly;
GO
ALTER DATABASE QsReadOnly SET QUERY_STORE = ON (OPERATION_MODE = READ_ONLY);
ALTER DATABASE DemoShop SET QUERY_STORE = ON (OPERATION_MODE = READ_WRITE);
GO
