#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

pass(){ printf 'PASS: %s\n' "$1"; }
fail(){ printf 'FAIL: %s\n' "$1"; exit 1; }

curl -fsS "$FRONTEND_URL" >/dev/null || fail "frontend not reachable"
pass "frontend reachable"

LOGIN=$(curl -fsS -c "$COOKIE_JAR" -H 'Content-Type: application/json' -d '{"username":"analyst","password":"analyst123"}' "$BASE_URL/auth/login") || fail "login failed"
TOKEN=$(python3 - <<'PY' "$LOGIN"
import json,sys
print(json.loads(sys.argv[1])['access_token'])
PY
)
[ -n "$TOKEN" ] || fail "access token missing"
pass "login works"

curl -fsS -b "$COOKIE_JAR" -H "Authorization: Bearer $TOKEN" "$BASE_URL/auth/me" >/dev/null || fail "auth/me failed"
pass "auth/me works"

curl -fsS -b "$COOKIE_JAR" -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/dashboard/summary" >/dev/null || fail "dashboard summary unavailable"
pass "dashboard summary works"

curl -fsS -b "$COOKIE_JAR" -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/events?limit=5" >/dev/null || fail "protected events list unavailable"
pass "protected events list works"

docker compose exec -T backend python - <<'PY' "$TOKEN" || fail "ws/events handshake failed"
import asyncio, json, sys, aiohttp
TOKEN=sys.argv[1]
async def main():
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(f'http://localhost:8000/ws/events?token={TOKEN}', timeout=10) as ws:
            msg = await ws.receive(timeout=10)
            data = json.loads(msg.data)
            assert data.get('type') == 'connected', data
asyncio.run(main())
PY
pass "ws/events handshake works"
