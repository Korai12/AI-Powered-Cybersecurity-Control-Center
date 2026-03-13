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

curl -fsS -b "$COOKIE_JAR" -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/events/stats?time_range=24h" >/dev/null || fail "stats endpoint unavailable"
pass "stats endpoint works"

GEO=$(curl -fsS -b "$COOKIE_JAR" -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/events?geo=true&limit=20&severity=CRITICAL,HIGH,MEDIUM") || fail "geo event query failed"
python3 - <<'PY' "$GEO" || fail "geo event query unusable"
import json,sys
payload=json.loads(sys.argv[1])
assert 'events' in payload
print('geo events count', len(payload['events']))
PY
pass "geo event data path works"

docker compose exec -T backend python - <<'PY' "$TOKEN" || fail "real-time ws event delivery failed"
import asyncio, json, sys, aiohttp
TOKEN=sys.argv[1]
async def main():
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(f'http://localhost:8000/ws/events?token={TOKEN}', timeout=10) as ws:
            await ws.receive(timeout=10)
            async with session.post('http://localhost:8000/api/v1/events/ingest', json={'raw_log':'CEF:0|ACCC|Demo|1|100|validator|8|src=8.8.8.8 dst=10.0.0.5 spt=443 dpt=8080 act=alert'}, timeout=10) as resp:
                assert resp.status == 200, resp.status
            for _ in range(5):
                msg = await ws.receive(timeout=10)
                data = json.loads(msg.data)
                if data.get('event_id'):
                    return
            raise AssertionError('no event payload received')
asyncio.run(main())
PY
pass "real-time ws event delivery works"
