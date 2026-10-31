#!/usr/bin/env bash
# LAB ONLY: throwaway SQL Server 2022 (Agent on) + pwsh/dbatools container on a
# private network; runs lab-test.ps1; removes both containers at the end.
# Random sa password, passed by env name only. ACCEPT_EULA=Y accepts the
# SQL Server Developer Edition licence for this lab container.
# Usage: DOCKER="sudo -n --preserve-env=MSSQL_SA_PASSWORD docker" bash toolkit/lab/run-lab.sh
set -uo pipefail
DOCKER="${DOCKER:-docker}"
SUF="${SUF:-test}"
NET="dbakit-net-$SUF"; SQL="dbakit-sql-$SUF"; PS="dbakit-ps-$SUF"
VOL="${PSMOD_VOLUME:-dbakit-psmod-test}"   # caches the dbatools module between runs
HERE="$(cd "$(dirname "$0")" && pwd)"; KIT="$(dirname "$HERE")"
export MSSQL_SA_PASSWORD="Lab-$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(18))')9a!"
cleanup() { $DOCKER rm -f "$SQL" "$PS" >/dev/null 2>&1; $DOCKER network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT
$DOCKER network create "$NET" >/dev/null
$DOCKER run -d --name "$SQL" --network "$NET" -e ACCEPT_EULA=Y -e MSSQL_AGENT_ENABLED=true -e MSSQL_SA_PASSWORD \
  mcr.microsoft.com/mssql/server:2022-latest >/dev/null
for _ in $(seq 1 60); do
  # The container already holds MSSQL_SA_PASSWORD; read it there, never on a host command line.
  $DOCKER exec "$SQL" sh -c 'SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -Q "SELECT 1"' >/dev/null 2>&1 && break
  sleep 2
done
echo "sql up: $SQL"
$DOCKER run --rm --name "$PS" --network "$NET" -e MSSQL_SA_PASSWORD -e LAB_SQL="$SQL" \
  -v "$VOL":/root/.local/share/powershell/Modules -v "$KIT":/kit:ro \
  mcr.microsoft.com/powershell:latest pwsh -NoLogo -NoProfile -File /kit/lab/lab-test.ps1
rc=$?
echo "LAB rc=$rc"
exit $rc
