# How to run the read-only health check (guide for your DBA)

This guide is for the person who runs the check on your SQL Server. It takes about
15 minutes. You run everything yourself. We never connect to your server. You send us
one file at the end, and you decide what goes in it.

What the check does: it reads settings, metadata and backup history. It does not read
the rows in your tables. It does not change data or settings. The login you create in
step 2 cannot do those things: SQL Server itself refuses them.

## What you need

- A Linux or macOS machine (or Windows with WSL) that can reach the SQL Server.
- Python 3.8 or newer: `python3 --version`.
- Microsoft's ODBC `sqlcmd` from `mssql-tools18`: `sqlcmd -?` should print
  "SQL Server Command Line Tool". (The newer Go `sqlcmd` is not tested yet.)
- A sysadmin login for steps 2 and 6 only. The check itself does not use it.
- This kit, unpacked. Run all commands from the kit folder.

## Step 1. Pick a time

Any time works, because the check is a set of short `SELECT`s (a few seconds in our lab).
Two things make the report better:

- Run it when the server has been up for at least 7 days. Performance numbers reset at
  each restart.
- Run it after a normal work day, not right after maintenance.

## Step 2. Create the reader login (sysadmin, once)

Pick a password with 12 or more characters and no single quote (`'`). Type it at the
prompt, so it stays out of your shell history:

```sh
read -rs HC_PW && export HC_PW
sqlcmd -S myserver -E -i sql/grant-reader.sql
```

Replace `myserver` with your server (`host`, `host,port` or `host\instance`). Put a
named instance in single quotes, for example `-S 'sql01\prod'`: without them the shell
drops the backslash. Do the same in every command below. `-E` uses
your Windows/Kerberos login. With a SQL sysadmin login instead, use `-U youradmin` and
type its password when sqlcmd asks.

Certificate error ("certificate chain was issued by an authority that is not
trusted")? sqlcmd 18 encrypts the connection and checks the server's certificate by
default. The right fix is a trusted certificate on the server. If your team accepts
the server's self-signed certificate for this check, add `-C` to every `sqlcmd`
command in this guide and `--trust-cert` in step 3. Both skip the check of the
server's identity, so use them only on your own network.

When it works, the only line it prints is `Changed database context to 'msdb'.`
Any line that starts with `Msg` is an error: stop and send us that line (not the password).
If a login named `hc_reader` already exists from an earlier check, run step 6 first.

To confirm, run:

```sh
sqlcmd -S myserver -E -Q "SELECT pe.permission_name FROM sys.server_permissions pe JOIN sys.server_principals p ON p.principal_id = pe.grantee_principal_id WHERE p.name = 'hc_reader'"
```

You should see exactly these four: `CONNECT ANY DATABASE`, `CONNECT SQL`,
`VIEW ANY DEFINITION`, `VIEW SERVER STATE`. The script also lets the login read one
table in `msdb`: `dbo.backupset` (backup history).

## Step 3. Run the check as the reader login

```sh
export SQLCMDPASSWORD="$HC_PW"
python3 -m sqlhc --server myserver --user hc_reader --out report-myserver
```

Add `--trust-cert` only if you chose `-C` in step 2 (self-signed certificate).

It prints one line like this:
`{"report": ".../report.md", ..., "counts": {"high": 3, "medium": 7, "low": 5}, "errors": 0, ...}`

- `errors: 0` and exit code 0: done.
- That line is printed, but `errors` is more than 0 (exit code 1): some checks failed.
  The report lists them under "Check errors". Read those lines in step 4 (they are raw
  server messages), then send the report; we will tell you if anything needs a rerun.
- No such line, only an error message: the run did not finish. Do not send that
  folder, even if some files are in it. Common causes are a wrong server name, a wrong
  password, a certificate error (see `--trust-cert`) or a full disk. Fix the cause and
  run again with a new folder name, for example `--out report-myserver-2`.
- "refusing to run": the login has more rights than it needs (for example it is in
  sysadmin). No report was written. Use the `hc_reader` login from step 2. Do not use
  `--allow-powerful-login`.

The folder `report-myserver/` now holds three files:

| File | What it is |
|---|---|
| `report.md` | The report as text |
| `report.html` | The same report for a browser. It has no scripts and loads nothing from the network |
| `results.json` | The raw results behind the report |

## Step 4. Read the report, and remove what you do not want to share

Open `report.html` in a browser and read it. It holds:

- Server version, edition, CPU count, memory and uptime.
- Names of your databases, tables, indexes and logical files; file sizes; row counts
  for some large tables (heaps).
- Names of logins that are in sysadmin, have password policy off, or (for `sa`) are enabled.
- Wait statistics.
- The text of the top queries by CPU, first 110 characters each. Values in the queries
  (strings, numbers) are replaced with `?`.
- Under "Check errors" (if any): the raw error message from the server, up to 200
  characters each.

The checks do not collect table rows, passwords, file paths on disk, or the server
name you typed. But an error message from the server can contain a name or a path:
read the "Check errors" section before you send anything.

`results.json` holds everything in the report, plus the result of the login's
permission check. The report tables show at most 15 rows each; `results.json` keeps
ALL rows (for example every sysadmin login, not only the first 15). Open it in a text
editor and read it too before you send it. It has no rows from your own tables.

If a name is sensitive (for example a database named after a client), you can edit it.
Replace it with a code, such as `DB1`, in all three files. Use the same code everywhere,
so that the findings still match up. If you prefer not to share `results.json`,
send only `report.md` and `report.html`. We can still write the fix scripts from them.

## Step 5. Send the file

Zip the folder:

```sh
python3 -m zipfile -c healthcheck-myserver.zip report-myserver/
```

If you chose NOT to share `results.json`, zip only the two reports instead:

```sh
python3 -m zipfile -c healthcheck-myserver.zip report-myserver/report.md report-myserver/report.html
```

Check what is in the zip before you send it:
`python3 -m zipfile -l healthcheck-myserver.zip`. Send the zip through the channel
we agreed in writing, for example your company's file-share link. Do not post it in
a public place.

## Step 6. Remove the reader login (sysadmin)

First clear the reader password from your shell. Otherwise sqlcmd would try it for
your admin login too:

```sh
unset HC_PW SQLCMDPASSWORD
sqlcmd -S myserver -E -i sql/remove-reader.sql
```

With a SQL sysadmin login, use `-U youradmin` instead of `-E`, as in step 2.

To confirm it is gone (this should print 0):

```sh
sqlcmd -S myserver -E -Q "SELECT COUNT(*) FROM sys.server_principals WHERE name = 'hc_reader'"
```

## What happens next

We send you the findings in plain language, and a fix script for each one. Your DBA
reviews them and runs them in your own change window. We do not change anything on
your server.
