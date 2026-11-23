# Connection problems: ports, named instances and encryption (DRAFT addendum)

Read this if step 2 or step 3 of `run-the-collector.md` cannot connect.
The checks below were run in a lab, not on a buyer's server. See the end of this page for how.

## 1. Which `-S` value to use

| Your server | Use | Result in the lab |
|---|---|---|
| Default instance on port 1433 | `-S sql01` | works |
| Any instance on another port, for example 14333 | `-S sql01,14333` | works |
| Same, forced TCP | `-S tcp:sql01,14333` | works |
| Named instance, port known | `-S 'sql01\PROD,14333'` | works (the port wins; the name is not checked) |
| Named instance, port not known | `-S 'sql01\PROD'` | works only if SQL Server Browser (UDP 1434) answers. SQL Server on Linux has no Browser, so this fails there |
| `host:port` with a colon | do not use | fails: sqlcmd reads it as a host name |

Use the same value in `--server` for the collector. Keep single quotes around a value
with a backslash.

Do not know the port? Ask the person who runs the server, or run this as an admin
on a connection that works:

```sql
SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID;
```

## 2. Encryption and certificates

sqlcmd 18 (ODBC Driver 18) encrypts by default (`Encrypt=Mandatory`) and checks the
server certificate. The collector does the same. Choose one:

1. **Best:** the server has a certificate from a CA your machine trusts, and you
   connect with the name that is in the certificate. No extra flag. Lab: works.
2. **Accept the server's certificate without a check:** add `-C` to `sqlcmd` and
   `--trust-cert` to the collector (same as `TrustServerCertificate=yes`). The
   connection is still encrypted, but the client does not prove who the server is.
   Use it only on your own network.

`-No` (Optional) does not help when the server forces encryption: the lab still
gave the certificate error.

**Strict encryption (`-Ns`, TDS 8.0):** the collector does not support it. It has no
`-N` option and always uses sqlcmd's default (Mandatory). If your server forces
Strict, the collector cannot connect: tell us before you buy. In the lab,
SQL Server 2022 on Linux refused every Strict connection, also with `-C` and with
`-J`/`-F`; this matches a public report (microsoft/mssql-docker issue #878).
SQL Server 2022 on Windows, and 2025, support Strict (Microsoft Learn, "Connect to
SQL Server with strict encryption"). The collector was not tested against them.

## 3. Error texts and what they mean

The collector prints only the FIRST line of the sqlcmd error, after
`could not connect or run the privilege probe:`. Run the same `-S` value with plain
`sqlcmd -Q "SELECT 1"` to see all lines.

| You see (Linux client, ODBC Driver 18.7) | Cause | Fix |
|---|---|---|
| `SSL Provider: [error:0A000086:SSL routines::certificate verify failed:unable to get local issuer certificate]` | The certificate is self-signed or from a CA your machine does not trust | Option 1 or 2 in section 2 |
| `SSL Provider: [error:0A000086:SSL routines::certificate verify failed:subject name does not match host name]` | The CA is trusted, but the name in `-S` is not in the certificate | Connect with the name in the certificate (often the full DNS name), or option 2 |
| `Login timeout expired.` then `TCP Provider: Error code 0x2749.` and `A network-related or instance-specific error ...` | Nothing answers on that port (wrong port, or the default 1433 when the server uses another one), or a firewall | Add the right `,port` |
| `Login timeout expired.` then `SQL Server Network Interfaces: Error Locating Server/Instance Specified [xFFFFFFFF].` | Named instance without a port, and SQL Server Browser did not answer | Use `'host\INSTANCE,port'` |
| `Login timeout expired.` then `TCP Provider: Error code 0x2AF9.` | A colon in `host:port`: the host name is not found | Use a comma: `host,port` |
| `TCP Provider: Error code 0x2746.` then `Client unable to establish connection.` | Strict (`-Ns`) refused by the server | Use the default (Mandatory) if the server allows it; otherwise see section 2 |

The step 2 note in the main guide quotes `certificate chain was issued by an
authority that is not trusted`. That is the text Windows clients commonly show
(not tested here). On Linux the lab showed the `SSL Provider` lines above instead.

When the collector itself fails, you see one line only, for example:

```
could not connect or run the privilege probe: Sqlcmd: Error: Microsoft ODBC Driver 18 for SQL Server : Login timeout expired.
```

That line alone does not say whether the port, the instance name or a firewall is
wrong. Use the sqlcmd test above.

## How this was tested

Throwaway SQL Server 2022 container (16.0.4325.4 CU28) with `tcpport = 14333`,
`forceencryption = 1`, `tlsprotocols = 1.2` and a lab certificate (CN and SAN
`sqllab.test`) signed by a throwaway lab CA. Client: sqlcmd 18.7.0001.1 inside the
container, login `hc_reader` from `sql/grant-reader.sql`. 19 sqlcmd cases and 6
collector cases; every case that worked read `encrypt_option = TRUE` and
`local_tcp_port = 14333` back from `sys.dm_exec_connections`. The collector ran in
the lab with the lab-only `--docker` option. Not tested: a Windows client, a
remote host, SQL Server Browser, SQL Server 2025, Azure SQL.
A second lab run with `tlsprotocols = 1.2,1.3` did not accept any connection
(Mandatory gave `Unable to complete login process due to delay in login response`;
Strict gave 0x2746). The cause was not proven; issue #878 cites the Microsoft Learn
TLS 1.3 page as listing Windows only for TLS 1.3 support.
