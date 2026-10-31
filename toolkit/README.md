# DBA toolkit installer

Installs well-known community SQL Server tools into **one dedicated database**
(default `DBA`) with [dbatools](https://dbatools.io). Client user databases are
never changed. A manifest table records every object and job it adds, and
`Uninstall-DbaToolkit.ps1` removes exactly those.

## What it installs

| Tool | Author | License | Default | Writes when run? |
|---|---|---|---|---|
| First Responder Kit (sp_Blitz, sp_BlitzFirst, sp_BlitzIndex, ...) | Brent Ozar Unlimited | MIT | yes | no (diagnostics) |
| DarlingData (sp_PressureDetector, sp_QuickieStore, ...) | Erik Darling | MIT | yes | no (diagnostics) |
| sp_WhoIsActive | Adam Machanic | GPL-3.0 | yes | no (diagnostics) |
| Maintenance Solution (backups, index/stats, DBCC jobs) | Ola Hallengren | MIT | **opt-in** | **yes** |

dbatools downloads each tool from its upstream project at install time. This
repo does not bundle or modify their code. sp_WhoIsActive is GPL-3.0: it is
installed unmodified from upstream, and its license applies to it.

## Safety rules

- Refuses `master`, `model`, `msdb` and `tempdb` as the toolkit database.
- Refuses an existing database that has no toolkit manifest (pass
  `-AllowExistingDatabase` only for a database you own for this purpose).
- Ola's Agent jobs change client databases (backups, index rebuilds, DBCC).
  They need `-IncludeMaintenance -InstallMaintenanceJobs -ClientSignOff "<name, date>"`.
  The sign-off text is stored next to each job in the manifest.
- Refuses the Maintenance Solution, before any change, when any Ola job exists
  on the server or any Ola object exists in the toolkit database. It never uses dbatools' `-ReplaceExisting`, which deletes every
  Hallengren job on the server.
- The manifest stores each item's id and creation time. Uninstall removes an
  item only when both still match (and, for jobs, only Ola-described jobs), so
  a same-named job made later by someone else stays. It lists every manifest
  row it leaves alone. `public` is denied writes to the manifest.
- Uninstall drops the database only if the toolkit created that exact
  database, and refuses when it holds objects the toolkit did not install
  (`-Force` overrides). Otherwise it drops only the manifest's objects.
  All refusal checks run before anything is removed.

## Use

```powershell
Install-Module dbatools -Scope CurrentUser
$cred = Get-Credential   # a sysadmin login: installing procedures needs it
./Install-DbaToolkit.ps1   -SqlInstance sql01 -SqlCredential $cred
./Uninstall-DbaToolkit.ps1 -SqlInstance sql01 -SqlCredential $cred
```

Both scripts support `-WhatIf`. The installer then runs its refusal checks,
prints its plan and changes nothing.

## Lab proof

`bash toolkit/lab/run-lab.sh` starts a throwaway SQL Server 2022 container (Agent
on) and a PowerShell container, then checks: the three refusals, the default
install, that `sp_Blitz` runs, the opt-in jobs, that a seeded client database
and `master` stay unchanged, that uninstall returns `msdb` jobs to baseline,
and the reuse path. Both containers are removed at the end.
