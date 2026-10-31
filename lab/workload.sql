-- LAB ONLY. Turns AUTO_CLOSE off (so DMV stats survive) and replays a small
-- workload, so the missing-index, top-query and write-only-index sections
-- have something to show.
SET NOCOUNT ON;
ALTER DATABASE DemoShop SET AUTO_CLOSE OFF;
GO
USE DemoShop;
GO
DECLARE @i int = 0, @x money;
WHILE @i < 40
BEGIN
  SELECT @x = SUM(Total) FROM dbo.Orders WHERE Status = (@i % 5) AND OrderDate > DATEADD(day, -2, sysdatetime());
  SELECT @x = SUM(Qty * Price) FROM dbo.OrderLines WHERE Sku = CONCAT('SKU', @i);
  SELECT @x = COUNT(*) FROM dbo.Customers WHERE Email LIKE CONCAT('c', @i, '@%');
  SET @i += 1;
END
-- writes that touch IX_Orders_Cust_Dup while nothing reads it -> write-only index
UPDATE TOP (500) dbo.Orders SET CustomerID = CustomerID + 0 WHERE OrderID % 7 = 0;
GO
