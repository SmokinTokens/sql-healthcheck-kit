-- LAB ONLY. Never run this on a real server.
-- Builds a throwaway demo database (DemoShop) with 11 planted defects, so you
-- can see what the health check finds. Run it as sa on a disposable container.
-- No password is stored here: the demo app login gets a random password that
-- is generated inside SQL Server and never printed.
SET NOCOUNT ON;
IF DB_ID('DemoShop') IS NULL CREATE DATABASE DemoShop;
GO
ALTER DATABASE DemoShop SET RECOVERY FULL;               -- defect: full recovery, no log backups
ALTER DATABASE DemoShop SET AUTO_SHRINK ON;              -- defect
ALTER DATABASE DemoShop SET AUTO_CLOSE ON;               -- defect
ALTER DATABASE DemoShop SET PAGE_VERIFY NONE;            -- defect
ALTER DATABASE DemoShop SET COMPATIBILITY_LEVEL = 130;   -- defect: old compatibility level
ALTER DATABASE DemoShop MODIFY FILE (NAME = DemoShop, FILEGROWTH = 10%); -- defect: percent growth
GO
BACKUP DATABASE DemoShop TO DISK = '/var/opt/mssql/data/DemoShop_full.bak' WITH INIT, COMPRESSION;
GO
USE DemoShop;
GO
IF OBJECT_ID('dbo.OrderLines') IS NOT NULL DROP TABLE dbo.OrderLines;
IF OBJECT_ID('dbo.Orders') IS NOT NULL DROP TABLE dbo.Orders;
IF OBJECT_ID('dbo.Customers') IS NOT NULL DROP TABLE dbo.Customers;
IF OBJECT_ID('dbo.AuditLog') IS NOT NULL DROP TABLE dbo.AuditLog;
CREATE TABLE dbo.Customers (CustomerID int IDENTITY PRIMARY KEY, Email varchar(200), Region char(2), CreatedAt datetime2 DEFAULT sysdatetime());
CREATE TABLE dbo.Orders (OrderID int IDENTITY PRIMARY KEY, CustomerID int NOT NULL, OrderDate datetime2, Status tinyint, Total money);
CREATE TABLE dbo.OrderLines (OrderID int, LineNum int, Sku varchar(30), Qty int, Price money); -- defect: large heap
CREATE TABLE dbo.AuditLog (EventAt datetime2, Msg nvarchar(400));
CREATE INDEX IX_Orders_Cust ON dbo.Orders(CustomerID);
CREATE INDEX IX_Orders_Cust_Dup ON dbo.Orders(CustomerID);                 -- defect: exact duplicate
CREATE INDEX IX_Orders_Cust_Date ON dbo.Orders(CustomerID, OrderDate);     -- overlaps IX_Orders_Cust
GO
;WITH n AS (SELECT TOP (20000) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT dbo.Customers(Email, Region) SELECT CONCAT('c', i, '@example.test'), CHAR(65 + i % 20) + CHAR(65 + i % 7) FROM n;
;WITH n AS (SELECT TOP (200000) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT dbo.Orders(CustomerID, OrderDate, Status, Total) SELECT 1 + i % 20000, DATEADD(minute, -i, sysdatetime()), i % 5, (i % 900) + 0.99 FROM n;
;WITH n AS (SELECT TOP (400000) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT dbo.OrderLines SELECT 1 + i % 200000, i % 3, CONCAT('SKU', i % 5000), 1 + i % 4, (i % 90) + 0.5 FROM n;
GO
-- defect: untrusted foreign key (created WITH NOCHECK)
ALTER TABLE dbo.Orders WITH NOCHECK ADD CONSTRAINT FK_Orders_Customers FOREIGN KEY (CustomerID) REFERENCES dbo.Customers(CustomerID);
GO
-- defects: SQL login with password policy off, and an app login in sysadmin.
-- Random throwaway password, generated here and never shown.
IF SUSER_ID('legacy_app') IS NULL
BEGIN
  DECLARE @pw nvarchar(80) = CONVERT(nvarchar(36), NEWID()) + N'-' + CONVERT(nvarchar(36), NEWID());
  DECLARE @s nvarchar(400) = N'CREATE LOGIN legacy_app WITH PASSWORD = ' + QUOTENAME(@pw, '''') + N', CHECK_POLICY = OFF;';
  EXEC sys.sp_executesql @s;
END
ALTER SERVER ROLE sysadmin ADD MEMBER legacy_app;
GO
