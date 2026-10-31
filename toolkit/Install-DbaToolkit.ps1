<#
.SYNOPSIS
  Install the DBA toolkit into its OWN database (default: DBA) with dbatools.

.DESCRIPTION
  Installs community diagnostic tools into one dedicated database. It never
  creates, changes or drops objects in any other database, except SQL Agent
  jobs in msdb, and only when you opt in with -InstallMaintenanceJobs.

  Default set (diagnostics, read-only when run):
    FirstResponderKit  Brent Ozar Unlimited, MIT    (sp_Blitz, sp_BlitzFirst, ...)
    DarlingData        Erik Darling, MIT            (sp_PressureDetector, sp_QuickieStore, ...)
    WhoIsActive        Adam Machanic, GPL-3.0       (sp_WhoIsActive; installed unmodified)

  Opt-in (writes: backups, index and stats maintenance, DBCC):
    MaintenanceSolution Ola Hallengren, MIT. Needs -IncludeMaintenance.
    Its Agent jobs need -InstallMaintenanceJobs AND -ClientSignOff "<who, when>".

  Every object and job the toolkit adds is written to dbo.DbaToolkitManifest in
  the toolkit database. Uninstall-DbaToolkit.ps1 removes exactly those.

.EXAMPLE
  $cred = Get-Credential
  ./Install-DbaToolkit.ps1 -SqlInstance sql01 -SqlCredential $cred
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)] [string] $SqlInstance,
  [pscredential] $SqlCredential,
  [string] $Database = 'DBA',
  [ValidateSet('FirstResponderKit', 'DarlingData', 'WhoIsActive')]
  [string[]] $Tools = @('FirstResponderKit', 'DarlingData', 'WhoIsActive'),
  [switch] $IncludeMaintenance,
  [switch] $InstallMaintenanceJobs,
  [string] $ClientSignOff,
  [string] $BackupDirectory,
  [switch] $TrustServerCertificate,
  [switch] $AllowExistingDatabase
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
Import-Module dbatools
if ($TrustServerCertificate) { Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null }

if ($Database -in @('master', 'model', 'msdb', 'tempdb')) { throw "Refusing: '$Database' is a system database. Use a dedicated toolkit database." }
if ($InstallMaintenanceJobs -and -not $IncludeMaintenance) { throw '-InstallMaintenanceJobs needs -IncludeMaintenance.' }
if ($InstallMaintenanceJobs -and [string]::IsNullOrWhiteSpace($ClientSignOff)) {
  throw 'Refusing: maintenance jobs write to client databases. Pass -ClientSignOff "<name, date>" after the client signs off.'
}

$server = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $SqlCredential
$q = @{ SqlInstance = $server; EnableException = $true }
function Invoke-Q([string] $db, [string] $sql, [hashtable] $params = @{}) {
  Invoke-DbaQuery @q -Database $db -Query $sql -SqlParameter $params
}

# 0. Ola's installer with -ReplaceExisting deletes every Hallengren job on the server
# and drops CommandLog. We never pass it; instead refuse, before any change, if any
# Ola job exists on the server or any Ola object exists in the toolkit database.
if ($IncludeMaintenance) {
  $olaJobs = @(Invoke-Q 'msdb' "SELECT name AS n FROM dbo.sysjobs WHERE description LIKE '%hallengren%' OR name IN ('CommandLog Cleanup', 'Output File Cleanup', 'sp_delete_backuphistory', 'sp_purge_jobhistory') OR name LIKE 'DatabaseBackup - %' OR name LIKE 'DatabaseIntegrityCheck - %' OR name LIKE 'IndexOptimize - %'")
  $olaObjs = @()
  if (Get-DbaDatabase @q -Database $Database) {
    $olaObjs = @(Invoke-Q $Database "SELECT name AS n FROM sys.objects WHERE schema_id = 1 AND name IN ('CommandExecute', 'CommandLog', 'DatabaseBackup', 'DatabaseIntegrityCheck', 'IndexOptimize', 'Queue', 'QueueDatabase')")
  }
  if ($olaJobs.Count -or $olaObjs.Count) {
    throw ("Refusing: Maintenance Solution pieces already exist (jobs: " + (($olaJobs | ForEach-Object n) -join ', ') + "; objects: " + (($olaObjs | ForEach-Object n) -join ', ') + "). Leave the client's setup alone, or remove it with the client first.")
  }
}

# -WhatIf: report what would happen and change nothing.
if ($WhatIfPreference) {
  "WhatIf: would create or reuse '$Database', create its manifest, and install: " + (@($Tools) + @(if ($IncludeMaintenance) { 'MaintenanceSolution' + $(if ($InstallMaintenanceJobs) { ' + Agent jobs' } else { '' }) }) -join ', ')
  return
}

# 1. Toolkit database: create it, or refuse to reuse an unknown one.
$created = $false
$existing = Get-DbaDatabase @q -Database $Database
if (-not $existing) {
  if ($PSCmdlet.ShouldProcess($Database, 'create toolkit database')) {
    New-DbaDatabase @q -Name $Database -RecoveryModel Simple | Out-Null
    $created = $true
  }
} else {
  $hasManifest = Invoke-Q $Database "SELECT 1 AS x FROM sys.tables WHERE name = 'DbaToolkitManifest' AND schema_id = 1"
  if (-not $hasManifest -and -not $AllowExistingDatabase) {
    throw "Database '$Database' exists and is not a toolkit database. Pick another -Database or pass -AllowExistingDatabase."
  }
}

Invoke-Q $Database @"
IF OBJECT_ID('dbo.DbaToolkitManifest') IS NULL
CREATE TABLE dbo.DbaToolkitManifest (
  Id int IDENTITY PRIMARY KEY,
  ItemType varchar(20) NOT NULL,      -- DATABASE | OBJECT | JOB
  ItemName nvarchar(400) NOT NULL,
  ItemId nvarchar(64) NOT NULL,       -- object_id | job_id | database_id
  ItemCreated datetime NOT NULL,      -- create_date / date_created, checked on uninstall
  Tool varchar(40) NOT NULL,
  InstalledAt datetime2 NOT NULL DEFAULT SYSUTCDATETIME(),
  InstalledBy nvarchar(256) NOT NULL DEFAULT SUSER_SNAME(),
  Note nvarchar(400) NULL);
DENY INSERT, UPDATE, DELETE ON dbo.DbaToolkitManifest TO public;
"@
if ($created) {
  Invoke-Q $Database "INSERT dbo.DbaToolkitManifest (ItemType, ItemName, ItemId, ItemCreated, Tool) SELECT 'DATABASE', name, CAST(database_id AS nvarchar(64)), create_date, 'toolkit' FROM sys.databases WHERE name = @n" @{ n = $Database }
}

# Snapshots are keyed by id + create date, never by name alone, so a same-named
# object or job made later by someone else is not claimed (or removed) by uninstall.
$objSql = "SELECT CAST(o.object_id AS nvarchar(64)) AS id, s.name + '.' + o.name AS n, o.create_date AS d FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id WHERE o.is_ms_shipped = 0 AND o.parent_object_id = 0 AND o.object_id <> OBJECT_ID('dbo.DbaToolkitManifest')"
$jobSql = "SELECT CAST(job_id AS nvarchar(64)) AS id, name AS n, date_created AS d FROM msdb.dbo.sysjobs"
function Snap-Objects { @(Invoke-Q $Database $objSql) }
function Snap-Jobs { @(Invoke-Q 'msdb' $jobSql) }

function Record([string] $tool, [scriptblock] $install) {
  $beforeO = @(Snap-Objects | ForEach-Object id); $beforeJ = @(Snap-Jobs | ForEach-Object id)
  & $install
  $newO = @(Snap-Objects | Where-Object { $_.id -notin $beforeO })
  $newJ = @(Snap-Jobs | Where-Object { $_.id -notin $beforeJ })
  $ins = "INSERT dbo.DbaToolkitManifest (ItemType, ItemName, ItemId, ItemCreated, Tool, Note) VALUES (@k, @n, @i, @d, @t, @s)"
  foreach ($o in $newO) { Invoke-Q $Database $ins @{ k = 'OBJECT'; n = $o.n; i = $o.id; d = $o.d; t = $tool; s = [DBNull]::Value } }
  foreach ($j in $newJ) { Invoke-Q $Database $ins @{ k = 'JOB'; n = $j.n; i = $j.id; d = $j.d; t = $tool; s = "sign-off: $ClientSignOff" } }
  [pscustomobject]@{ Tool = $tool; Objects = $newO.Count; Jobs = $newJ.Count }
}


$results = @()
foreach ($t in $Tools) {
  if (-not $PSCmdlet.ShouldProcess("$SqlInstance/$Database", "install $t")) { continue }
  switch ($t) {
    'FirstResponderKit' { $results += Record $t { Install-DbaFirstResponderKit @q -Database $Database -Force | Out-Null } }
    'DarlingData'       { $results += Record $t { Install-DbaDarlingData @q -Database $Database -Force | Out-Null } }
    'WhoIsActive'       { $results += Record $t { Install-DbaWhoIsActive @q -Database $Database -Force | Out-Null } }
  }
}
if ($IncludeMaintenance -and $PSCmdlet.ShouldProcess("$SqlInstance/$Database", 'install MaintenanceSolution')) {
  $m = @{ Database = $Database; LogToTable = $true; Force = $true }
  if ($InstallMaintenanceJobs) {
    $m.InstallJobs = $true
    if ($BackupDirectory) { $m.BackupLocation = $BackupDirectory }
  }
  $results += Record 'MaintenanceSolution' { Install-DbaMaintenanceSolution @q @m | Out-Null }
}
$results | Format-Table -AutoSize | Out-String | Write-Output
"Manifest: $Database.dbo.DbaToolkitManifest. Remove with Uninstall-DbaToolkit.ps1 -SqlInstance $SqlInstance -Database $Database"
