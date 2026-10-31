<#
.SYNOPSIS
  Remove everything Install-DbaToolkit.ps1 added, using its manifest.

.DESCRIPTION
  Reads dbo.DbaToolkitManifest in the toolkit database. An item is removed only
  when its id AND creation time still match what the installer recorded, so a
  same-named job or object made by someone else is left alone, and a forged
  manifest row cannot point at an unrelated job or database.
  Removes the matching SQL Agent jobs, then: if the toolkit created the
  database, drops the database (refuses when it holds objects the toolkit did
  not install, unless -Force); otherwise drops only the matching objects and
  the manifest table.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)] [string] $SqlInstance,
  [pscredential] $SqlCredential,
  [string] $Database = 'DBA',
  [switch] $TrustServerCertificate,
  [switch] $Force
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
Import-Module dbatools
if ($TrustServerCertificate) { Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null }
if ($Database -in @('master', 'model', 'msdb', 'tempdb')) { throw "Refusing: '$Database' is a system database." }

$server = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $SqlCredential
$q = @{ SqlInstance = $server; EnableException = $true }
function Invoke-Q([string] $db, [string] $sql, [hashtable] $params = @{}) {
  Invoke-DbaQuery @q -Database $db -Query $sql -SqlParameter $params
}
if (-not (Get-DbaDatabase @q -Database $Database)) { "Database '$Database' not found: nothing to remove."; return }
if (-not (Invoke-Q $Database "SELECT 1 AS x FROM sys.tables WHERE name = 'DbaToolkitManifest' AND schema_id = 1")) {
  throw "No dbo.DbaToolkitManifest in '$Database': not a toolkit database, refusing."
}

# Jobs: match on job_id + date_created recorded at install time.
$jobs = @(Invoke-Q $Database @"
SELECT CAST(j.job_id AS nvarchar(64)) AS id, j.name AS n
FROM dbo.DbaToolkitManifest m
JOIN msdb.dbo.sysjobs j ON CAST(j.job_id AS nvarchar(64)) = m.ItemId AND j.date_created = m.ItemCreated
WHERE m.ItemType = 'JOB' AND j.description LIKE '%hallengren%'   -- the toolkit only ever creates Ola jobs
"@)
# Say what will NOT be removed, so nobody assumes it is gone.
$stale = @(Invoke-Q $Database @"
SELECT m.ItemType AS k, m.ItemName AS n FROM dbo.DbaToolkitManifest m
WHERE (m.ItemType = 'JOB' AND NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs j WHERE CAST(j.job_id AS nvarchar(64)) = m.ItemId
          AND j.date_created = m.ItemCreated AND j.description LIKE '%hallengren%'))
   OR (m.ItemType = 'OBJECT' AND NOT EXISTS (SELECT 1 FROM sys.objects o WHERE CAST(o.object_id AS nvarchar(64)) = m.ItemId
          AND o.create_date = m.ItemCreated))
"@)
foreach ($s in $stale) { "left alone (gone, or id/date no longer match the manifest): $($s.k) $($s.n)" }
function Remove-Jobs {  # runs only after every refusal check has passed
  foreach ($j in $jobs) {
    if ($PSCmdlet.ShouldProcess($j.n, 'remove Agent job')) {
      Invoke-Q 'msdb' 'EXEC dbo.sp_delete_job @job_id = @id' @{ id = [guid] $j.id }
      "removed job: $($j.n)"
    }
  }
}

# Database: drop only if this exact database (id + create_date) was created by the toolkit.
$createdDb = Invoke-Q $Database @"
SELECT 1 AS x FROM dbo.DbaToolkitManifest m
JOIN sys.databases d ON CAST(d.database_id AS nvarchar(64)) = m.ItemId AND d.create_date = m.ItemCreated AND d.name = m.ItemName
WHERE m.ItemType = 'DATABASE' AND d.database_id = DB_ID()
"@

$objSql = @"
SELECT s.name AS sch, o.name AS n, RTRIM(o.type) AS t
FROM dbo.DbaToolkitManifest m
JOIN sys.objects o ON CAST(o.object_id AS nvarchar(64)) = m.ItemId AND o.create_date = m.ItemCreated
JOIN sys.schemas s ON s.schema_id = o.schema_id
WHERE m.ItemType = 'OBJECT'
"@

if ($createdDb) {
  $foreign = @(Invoke-Q $Database @"
SELECT s.name + '.' + o.name AS n FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
WHERE o.is_ms_shipped = 0 AND o.parent_object_id = 0 AND o.object_id <> OBJECT_ID('dbo.DbaToolkitManifest')
  AND NOT EXISTS (SELECT 1 FROM dbo.DbaToolkitManifest m WHERE m.ItemType = 'OBJECT'
                  AND m.ItemId = CAST(o.object_id AS nvarchar(64)) AND m.ItemCreated = o.create_date)
"@)
  if ($foreign.Count -and -not $Force) {
    throw ("Refusing to drop '$Database': it holds objects the toolkit did not install: " + (($foreign | ForEach-Object n) -join ', ') + '. Move them, or pass -Force.')
  }
  Remove-Jobs
  if ($PSCmdlet.ShouldProcess($Database, 'drop toolkit database')) {
    Remove-DbaDatabase @q -Database $Database -Confirm:$false | Out-Null
    "dropped database: $Database"
  }
  return
}

Remove-Jobs
foreach ($o in @(Invoke-Q $Database $objSql)) {
  $kind = switch ($o.t) {
    'P' { 'PROCEDURE' } 'U' { 'TABLE' } 'V' { 'VIEW' }
    { $_ -in 'FN', 'IF', 'TF', 'FS', 'FT' } { 'FUNCTION' } default { $null }
  }
  $label = "$($o.sch).$($o.n)"
  if (-not $kind) { "skipped (type $($o.t)): $label"; continue }
  $name = '[' + $o.sch.Replace(']', ']]') + '].[' + $o.n.Replace(']', ']]') + ']'
  if ($PSCmdlet.ShouldProcess($label, "drop $kind")) {
    Invoke-Q $Database "DROP $kind $name"
    "dropped $kind`: $label"
  }
}
if ($PSCmdlet.ShouldProcess('dbo.DbaToolkitManifest', 'drop manifest')) {
  Invoke-Q $Database 'DROP TABLE dbo.DbaToolkitManifest'
  'dropped manifest'
}
