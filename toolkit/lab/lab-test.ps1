# LAB ONLY. Runs inside a pwsh container next to a throwaway SQL Server container.
# Env: LAB_SQL (host), MSSQL_SA_PASSWORD. Exit 0 only if every proof passes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not (Get-Module -ListAvailable dbatools)) {
  Set-PSRepository PSGallery -InstallationPolicy Trusted
  Install-Module dbatools -Scope CurrentUser -Force
}
Import-Module dbatools
"dbatools $((Get-Module dbatools).Version)"
Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit = Split-Path -Parent $here
$pw = ConvertTo-SecureString $env:MSSQL_SA_PASSWORD -AsPlainText -Force
$cred = [pscredential]::new('sa', $pw)
$inst = $env:LAB_SQL
$s = Connect-DbaInstance -SqlInstance $inst -SqlCredential $cred
$fail = 0
function Check([string] $name, [bool] $ok) { if ($ok) { "PASS: $name" } else { "FAIL: $name"; $script:fail++ } }
function Q([string] $db, [string] $sql) { Invoke-DbaQuery -SqlInstance $s -Database $db -Query $sql -EnableException }

# Seed a client user database we must never touch.
Q master "IF DB_ID('ClientApp') IS NULL CREATE DATABASE ClientApp"
Q ClientApp "IF OBJECT_ID('dbo.Orders') IS NULL BEGIN CREATE TABLE dbo.Orders (Id int PRIMARY KEY, Amount money); INSERT dbo.Orders VALUES (1, 10), (2, 20); END"
$fp = "SELECT COUNT(*) AS c, CHECKSUM_AGG(CHECKSUM(name, type, modify_date)) AS h FROM sys.objects"
$cBefore = Q ClientApp $fp
$mBefore = Q master "SELECT COUNT(*) AS c FROM sys.objects WHERE is_ms_shipped = 0"
$jBefore = (Q msdb "SELECT COUNT(*) AS c FROM dbo.sysjobs").c

# 1. Refusals.
try { & "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Database master -Tools WhoIsActive | Out-Null; Check 'refuse system db' $false } catch { Check 'refuse system db' ($_ -match 'system database') }
try { & "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Database ClientApp -Tools WhoIsActive | Out-Null; Check 'refuse existing non-toolkit db' $false } catch { Check 'refuse existing non-toolkit db' ($_ -match 'not a toolkit database') }
try { & "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -IncludeMaintenance -InstallMaintenanceJobs -Tools WhoIsActive | Out-Null; Check 'refuse jobs without sign-off' $false } catch { Check 'refuse jobs without sign-off' ($_ -match 'ClientSignOff') }
Check 'no DBA db after refusals' (-not (Get-DbaDatabase -SqlInstance $s -Database DBA))
$wi = & "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -WhatIf
Check 'WhatIf reports and creates nothing' ((($wi | Out-String) -match 'WhatIf: would') -and -not [bool](Q master "SELECT 1 AS x FROM sys.databases WHERE name = 'DBA'"))

# 2. Default install (diagnostics only).
& "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred
$procs = @(Q DBA "SELECT name FROM sys.procedures" | ForEach-Object name)
"procs in DBA: $($procs.Count)"
foreach ($p in 'sp_Blitz', 'sp_BlitzFirst', 'sp_BlitzIndex', 'sp_WhoIsActive', 'sp_PressureDetector', 'sp_QuickieStore') { Check "installed $p" ($p -in $procs) }
Check 'no Ola objects by default' (-not ('CommandExecute' -in $procs))
Check 'msdb jobs unchanged (default)' ((Q msdb "SELECT COUNT(*) AS c FROM dbo.sysjobs").c -eq $jBefore)
Check 'master unchanged' ((Q master "SELECT COUNT(*) AS c FROM sys.objects WHERE is_ms_shipped = 0").c -eq $mBefore.c)
$blitz = @(Invoke-DbaQuery -SqlInstance $s -Database DBA -Query "EXEC dbo.sp_Blitz @CheckServerInfo = 0" -EnableException)
"sp_Blitz rows: $($blitz.Count)"
Check 'sp_Blitz runs' ($blitz.Count -gt 0)

# 3. Opt-in maintenance with sign-off.
& "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Tools @() -IncludeMaintenance -InstallMaintenanceJobs -ClientSignOff 'LAB test, 2026-10-29' -BackupDirectory /var/opt/mssql/data
$jobs = @(Q DBA "SELECT ItemName FROM dbo.DbaToolkitManifest WHERE ItemType = 'JOB'" | ForEach-Object ItemName)
"jobs recorded: $($jobs.Count)"
Check 'maintenance jobs recorded' ($jobs.Count -gt 0)
Check 'CommandExecute in DBA' ((@(Q DBA "SELECT name FROM sys.procedures" | ForEach-Object name)) -contains 'CommandExecute')

# 3b. Review fixes: no ReplaceExisting takeover, manifest poisoning, foreign objects.
try { & "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Tools @() -IncludeMaintenance | Out-Null; Check 'refuse Ola when pieces exist' $false } catch { Check 'refuse Ola when pieces exist' ($_ -match 'already exist') }
try { & "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Database DBA3 -Tools @() -IncludeMaintenance | Out-Null; Check 'Ola refusal on new db' $false } catch { Check 'Ola refusal on new db' ($_ -match 'already exist') }
Check 'Ola refusal left no DBA3 db' (-not [bool](Q master "SELECT 1 AS x FROM sys.databases WHERE name = 'DBA3'"))
Q msdb "EXEC dbo.sp_add_job @job_name = N'ClientNightly', @description = N'client job (not ours)'"
$cj = Q msdb "SELECT CAST(job_id AS nvarchar(64)) AS id FROM dbo.sysjobs WHERE name = N'ClientNightly'"
# Forged rows: by name with a bogus id, and with the real id but a wrong date.
Q DBA "INSERT dbo.DbaToolkitManifest (ItemType, ItemName, ItemId, ItemCreated, Tool) VALUES ('JOB', N'ClientNightly', N'00000000-0000-0000-0000-000000000000', GETDATE(), 'forged'), ('JOB', N'ClientNightly', N'$($cj.id)', '2001-01-01', 'forged')"
Q master "IF SUSER_ID('lab_writer') IS NULL CREATE LOGIN lab_writer WITH PASSWORD = N'Lw-$([guid]::NewGuid())', CHECK_POLICY = OFF"
Q DBA "CREATE USER lab_writer FOR LOGIN lab_writer; ALTER ROLE db_datawriter ADD MEMBER lab_writer"
$denied = $false
try { Q DBA "EXECUTE AS USER = 'lab_writer'; INSERT dbo.DbaToolkitManifest (ItemType, ItemName, ItemId, ItemCreated, Tool) VALUES ('JOB', N'x', N'x', GETDATE(), 'x'); REVERT" } catch { $denied = $_ -match 'denied' }
Q DBA "IF USER_NAME() <> 'dbo' REVERT"
Check 'db_datawriter cannot write manifest' $denied
Q DBA "DROP USER lab_writer"; Q master "DROP LOGIN lab_writer"
Q DBA "CREATE TABLE dbo.SomeoneElses (i int)"
try { & "$kit/Uninstall-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Confirm:$false | Out-Null; Check 'uninstall refuses foreign object' $false } catch { Check 'uninstall refuses foreign object' ($_ -match 'did not install') }
Check 'DBA kept after refusal' ([bool](Get-DbaDatabase -SqlInstance $s -Database DBA))
Check 'refusal removed no jobs' ((Q msdb "SELECT COUNT(*) AS c FROM dbo.sysjobs").c -eq $jBefore + 11)
$jBefore += 1   # ClientNightly is the client's: it must survive uninstall

# 4. Client DB untouched by install.
$cAfter = Q ClientApp $fp
Check 'ClientApp objects unchanged' ($cAfter.c -eq $cBefore.c -and $cAfter.h -eq $cBefore.h)
Check 'ClientApp rows unchanged' ((Q ClientApp "SELECT SUM(Amount) AS s FROM dbo.Orders").s -eq 30)

# 5. Uninstall removes everything.
$un = & "$kit/Uninstall-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Confirm:$false -Force
$un
Check 'uninstall reports forged rows it left alone' ((($un | Out-String) -split "`n" | Where-Object { $_ -match 'left alone.*ClientNightly' }).Count -eq 2)
Check 'forged rows ignored: client job survives' ([bool](Q msdb "SELECT 1 AS x FROM dbo.sysjobs WHERE name = N'ClientNightly'"))
Check 'DBA db gone' (-not (Get-DbaDatabase -SqlInstance $s -Database DBA))
Check 'msdb jobs back to baseline' ((Q msdb "SELECT COUNT(*) AS c FROM dbo.sysjobs").c -eq $jBefore)
Check 'master unchanged after uninstall' ((Q master "SELECT COUNT(*) AS c FROM sys.objects WHERE is_ms_shipped = 0").c -eq $mBefore.c)
$cEnd = Q ClientApp $fp
Check 'ClientApp unchanged after uninstall' ($cEnd.c -eq $cBefore.c -and $cEnd.h -eq $cBefore.h)

# 6. Reuse path: existing toolkit db not created by us -> drops objects only.
Q master "CREATE DATABASE DBA2"
& "$kit/Install-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Database DBA2 -Tools WhoIsActive -AllowExistingDatabase | Out-Null
Q DBA2 "CREATE TABLE dbo.KeepMe (i int)"
& "$kit/Uninstall-DbaToolkit.ps1" -SqlInstance $inst -SqlCredential $cred -Database DBA2 -Confirm:$false
$left = @(Q DBA2 "SELECT name FROM sys.objects WHERE is_ms_shipped = 0 AND parent_object_id = 0" | ForEach-Object name)
"DBA2 objects left: $($left -join ',')"
$dba2 = [bool](Q master "SELECT 1 AS x FROM sys.databases WHERE name = 'DBA2'")
Check 'reuse: kept db + KeepMe, toolkit objects gone' ($dba2 -and (($left -join ',') -eq 'KeepMe'))

"RESULT: $fail failure(s)"
exit $fail
