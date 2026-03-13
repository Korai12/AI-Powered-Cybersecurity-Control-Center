#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

pass(){ printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1"; exit 1; }

LOGIN=$(curl -fsS -c "$COOKIE_JAR" -H 'Content-Type: application/json' -d '{"username":"analyst","password":"analyst123"}' "$BASE_URL/auth/login") || fail "login failed"
TOKEN=$(python3 - <<'PY' "$LOGIN"
import json,sys
print(json.loads(sys.argv[1])['access_token'])
PY
)

for _ in 1 2 3 4 5; do
  curl -fsS -H 'Content-Type: application/json' -d '{"raw_log":"CEF:0|ACCC|Demo|1|200|baseline|9|src=9.9.9.9 dst=10.0.0.10 spt=5555 dpt=22 act=alert"}' "$BASE_URL/api/v1/events/ingest" >/dev/null || true
  sleep 1
done
pass "seeded burst events for baseline"

SUMMARY=$(curl -fsS -b "$COOKIE_JAR" -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/dashboard/summary") || fail "dashboard summary unavailable"
python3 - <<'PY' "$SUMMARY" || fail "baseline output missing"
import json,sys
payload=json.loads(sys.argv[1])
assert 'baseline' in payload
assert 'anomalies' in payload
print('anomalies', len(payload['anomalies']))
PY
pass "baseline output available through dashboard summary"

docker compose exec -T backend python - <<'PY' || fail "baseline refresh execution failed"
import asyncio
from services.baseline import refresh_baselines
async def main():
    result = await refresh_baselines()
    assert 'entities_processed' in result
asyncio.run(main())
PY
pass "baseline service executable"
