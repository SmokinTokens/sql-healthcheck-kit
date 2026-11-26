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

# --pull=never: use only an image already on this host; never pull during a lab run.
$DOCKER run -d --pull=never --name "$NAME" -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD "$IMAGE" >/dev/null
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
as_sa "$HERE/seed-tlog.sql"
as_sa "$HERE/seed-qs.sql"
as_sa "$HERE/seed-certs.sql"
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

# Proof 3: the reader login can read both corruption sources (S22, S23).
python3 "$HERE/assert-integrity.py" "$OUT/results.json"

# Proof 4: the reader login finds the planted orphaned user and guest CONNECT (D07, D08).
python3 "$HERE/assert-security.py" "$OUT/results.json"

# Log the REAL LogSprawl VLF count (read as sa, independent of D09) before proof 5, so a
# seed shortfall can be told apart from a D09 query fault.
VLFS=$(echo "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.dm_db_log_info(DB_ID('LogSprawl'));" |
  SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" $DOCKER exec -i -e SQLCMDPASSWORD "$NAME" \
  $SQLCMD -S localhost -U sa -C -b -h -1 -W -i /dev/stdin 2>/dev/null | tr -d '[:space:]') || VLFS=""
case "$VLFS" in ''|*[!0-9]*) echo "FAIL: could not read the LogSprawl VLF count as sa"; exit 1;; esac
echo "ok: LogSprawl VLF count (sa, sys.dm_db_log_info) = $VLFS"

# Proof 5: the reader login can read the transaction-log sources (D09 VLFs, D10 reuse wait).
python3 "$HERE/assert-tlog.py" "$OUT/results.json"

# Proof 6: the reader login judged the planted backups (S26, S27): plain, CHECKSUM, copy-only.
python3 "$HERE/assert-backup-quality.py" "$OUT/results.json"

# Proof 7: the reader login read Query Store state (D11): QsReadOnly listed, DemoShop not.
python3 "$HERE/assert-qs.py" "$OUT/results.json"

# Proof 8: the reader login judged the planted certificates (S29): TDE key never exported,
# backup certificate expiring in 10 days; exported and unused certificates are not listed.
python3 "$HERE/assert-certs.py" "$OUT/results.json"
