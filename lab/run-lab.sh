#!/usr/bin/env bash
# LAB ONLY: start a throwaway SQL Server 2022 container, seed the DemoShop demo
# database with planted defects, create the least-privilege login, replay a
# workload, then run the health check as that login.
#
# Passwords are random, live in this process's environment, and are never passed
# as command-line values. The container keeps MSSQL_SA_PASSWORD in its own config
# (visible to docker inspect) until you remove it. ACCEPT_EULA=Y below accepts the
# Microsoft SQL Server Developer Edition licence on your behalf.
#
# Usage: bash lab/run-lab.sh [CONTAINER_NAME] [OUT_DIR]
#   DOCKER="sudo -n --preserve-env=MSSQL_SA_PASSWORD,SQLCMDPASSWORD,HC_PW docker" bash lab/run-lab.sh
# Clean up: docker rm -f <CONTAINER_NAME>
set -euo pipefail
NAME="${1:-sqlhc-lab}"
OUT="${2:-lab-out}"
DOCKER="${DOCKER:-docker}"
IMAGE="${IMAGE:-mcr.microsoft.com/mssql/server:2022-latest}"
SQLCMD=/opt/mssql-tools18/bin/sqlcmd
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"

randpw() { python3 -c 'import secrets; print("Lab-" + secrets.token_urlsafe(18) + "9a!")'; }
export MSSQL_SA_PASSWORD="$(randpw)"
export HC_PW="$(randpw)"

$DOCKER run -d --name "$NAME" -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD "$IMAGE" >/dev/null
echo "started $NAME; waiting for SQL Server"
for _ in $(seq 1 60); do
  if SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" $DOCKER exec -e SQLCMDPASSWORD "$NAME" \
       $SQLCMD -S localhost -U sa -C -Q "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

as_sa() {  # $1 = sql file; fed on stdin, output withheld (failed batches can echo values)
  if ! SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" $DOCKER exec -i -e SQLCMDPASSWORD -e HC_PW "$NAME" \
       $SQLCMD -S localhost -U sa -C -b -i /dev/stdin < "$1" >/dev/null 2>&1; then
    echo "FAILED: $(basename "$1") (output withheld)"; exit 1
  fi
  echo "ok: $(basename "$1")"
}
as_sa "$HERE/seed-demo.sql"
as_sa "$ROOT/sql/grant-reader.sql"
as_sa "$HERE/workload.sql"

cd "$ROOT"

# Proof 1: the tool refuses a powerful login (sa) before running any check.
if SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" python3 -m sqlhc --server localhost --user sa --trust-cert \
     --sqlcmd "$SQLCMD" --docker "$NAME" --docker-cmd "$DOCKER" --out "$OUT-sa" 2>"$OUT-sa.err"; then
  echo "FAIL: tool ran as sa"; exit 1
fi
grep -q "refusing to run" "$OUT-sa.err" && echo "proof: tool refused sa login" || { echo "FAIL: sa not refused"; exit 1; }
rm -f "$OUT-sa.err"

# Proof 2: the reader login itself is read-only (server enforces it, not just our guard).
export SQLCMDPASSWORD="$HC_PW"
for q in "UPDATE DemoShop.dbo.Orders SET Status = 9 WHERE OrderID = 1" \
         "SELECT TOP 1 Email FROM DemoShop.dbo.Customers" \
         "EXEC sp_configure 'show advanced options', 1; RECONFIGURE" \
         "CREATE TABLE DemoShop.dbo.hc_probe (i int)"; do
  if echo "$q" | $DOCKER exec -i -e SQLCMDPASSWORD "$NAME" $SQLCMD -S localhost -U hc_reader -C -b -i /dev/stdin >/dev/null 2>&1; then
    echo "FAIL: hc_reader was allowed: $q"; exit 1
  fi
  echo "proof: DENIED for hc_reader: ${q%% *} ..."
done

python3 -m sqlhc --server localhost --user hc_reader --trust-cert \
  --sqlcmd "$SQLCMD" --docker "$NAME" --docker-cmd "$DOCKER" --out "$OUT"
