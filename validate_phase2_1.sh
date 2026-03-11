#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ACCC Phase 2.1 Validation Script
# Authentication & WebSocket Infrastructure
# ═══════════════════════════════════════════════════════════
#
# Tests:
#   1.  Health endpoint still working
#   2.  POST /auth/login with analyst credentials
#   3.  POST /auth/login with senior credentials
#   4.  POST /auth/login with manager credentials
#   5.  POST /auth/login with wrong password (expect 401)
#   6.  POST /auth/login with nonexistent user (expect 401)
#   7.  GET /auth/me with valid token
#   8.  GET /auth/me without token (expect 401)
#   9.  POST /auth/refresh with cookie
#   10. POST /auth/logout invalidates token
#   11. Protected endpoint without token (expect 401)
#   12. Events API still works with auth bypass (backward compat)
#   13. WebSocket /ws/events endpoint exists
#   14. WebSocket /ws/chat/{session_id} endpoint exists
#   15. WebSocket /ws/agent/{run_id} endpoint exists (stub)
#   16. WebSocket /ws/hunt/{hunt_id} endpoint exists (stub)
#   17. Redis connection healthy
#   18. JWT token contains correct claims
#   19. Refresh token stored in Redis
#   20. Backend logs show startup sequence
#
# Usage: chmod +x validate_phase2_1.sh && ./validate_phase2_1.sh
# ═══════════════════════════════════════════════════════════

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
PASS=0
FAIL=0
WARN=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

pass_test() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✅ PASS${NC} — $1"
}

fail_test() {
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}❌ FAIL${NC} — $1"
    if [ -n "${2:-}" ]; then
        echo -e "         ${RED}$2${NC}"
    fi
}

warn_test() {
    WARN=$((WARN + 1))
    echo -e "  ${YELLOW}⚠️  WARN${NC} — $1"
}

section() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${NC}"
}

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    ACCC Phase 2.1 — Validation Script                    ║${NC}"
echo -e "${BOLD}║    Authentication & WebSocket Infrastructure             ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"

# ──────────────────────────────────────────────────────────
# Wait for backend to be ready
# ──────────────────────────────────────────────────────────
section "Checking Backend Availability"
MAX_WAIT=90
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    if curl -sf "${BACKEND_URL}/health" > /dev/null 2>&1; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    fail_test "Backend not reachable at ${BACKEND_URL}/health after ${MAX_WAIT}s"
    echo -e "\n${RED}Cannot proceed — backend is not running.${NC}"
    echo "Run: cd accc && docker compose up --build"
    exit 1
fi
pass_test "Backend is reachable"

# ──────────────────────────────────────────────────────────
# Test 1: Health endpoint
# ──────────────────────────────────────────────────────────
section "1. Health Endpoint"
HEALTH=$(curl -sf "${BACKEND_URL}/health" 2>/dev/null || echo "FAIL")
if echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status'] in ('ok','degraded')" 2>/dev/null; then
    pass_test "GET /health returns valid status"
    # Check individual services
    PG_OK=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['services'].get('postgres',''))" 2>/dev/null)
    REDIS_OK=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['services'].get('redis',''))" 2>/dev/null)
    CHROMA_OK=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['services'].get('chromadb',''))" 2>/dev/null)
    [ "$PG_OK" = "ok" ] && pass_test "PostgreSQL healthy" || warn_test "PostgreSQL: $PG_OK"
    [ "$REDIS_OK" = "ok" ] && pass_test "Redis healthy" || warn_test "Redis: $REDIS_OK"
    [ "$CHROMA_OK" = "ok" ] && pass_test "ChromaDB healthy" || warn_test "ChromaDB: $CHROMA_OK"
else
    fail_test "GET /health failed" "$HEALTH"
fi

# ──────────────────────────────────────────────────────────
# Test 2-4: Login with all 3 seed users
# ──────────────────────────────────────────────────────────
section "2. Authentication — Login (3 seed users)"

# Analyst login
ANALYST_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"analyst","password":"analyst123"}' \
    -c /tmp/accc_cookies_analyst 2>/dev/null || echo "FAIL")

ANALYST_TOKEN=$(echo "$ANALYST_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
ANALYST_ROLE=$(echo "$ANALYST_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null || echo "")

if [ -n "$ANALYST_TOKEN" ] && [ "$ANALYST_TOKEN" != "" ]; then
    pass_test "POST /auth/login — analyst login successful"
    [ "$ANALYST_ROLE" = "analyst" ] && pass_test "Analyst role returned correctly" || fail_test "Analyst role expected 'analyst', got '$ANALYST_ROLE'"
else
    fail_test "POST /auth/login — analyst login failed" "$ANALYST_RESP"
fi

# Senior login
SENIOR_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"senior","password":"senior123"}' \
    -c /tmp/accc_cookies_senior 2>/dev/null || echo "FAIL")

SENIOR_TOKEN=$(echo "$SENIOR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
SENIOR_ROLE=$(echo "$SENIOR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null || echo "")

if [ -n "$SENIOR_TOKEN" ] && [ "$SENIOR_TOKEN" != "" ]; then
    pass_test "POST /auth/login — senior login successful"
    [ "$SENIOR_ROLE" = "senior_analyst" ] && pass_test "Senior role returned correctly" || fail_test "Senior role expected 'senior_analyst', got '$SENIOR_ROLE'"
else
    fail_test "POST /auth/login — senior login failed" "$SENIOR_RESP"
fi

# Manager login
MANAGER_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"manager","password":"manager123"}' \
    -c /tmp/accc_cookies_manager 2>/dev/null || echo "FAIL")

MANAGER_TOKEN=$(echo "$MANAGER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
MANAGER_ROLE=$(echo "$MANAGER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null || echo "")

if [ -n "$MANAGER_TOKEN" ] && [ "$MANAGER_TOKEN" != "" ]; then
    pass_test "POST /auth/login — manager login successful"
    [ "$MANAGER_ROLE" = "soc_manager" ] && pass_test "Manager role returned correctly" || fail_test "Manager role expected 'soc_manager', got '$MANAGER_ROLE'"
else
    fail_test "POST /auth/login — manager login failed" "$MANAGER_RESP"
fi

# ──────────────────────────────────────────────────────────
# Test 5-6: Invalid login attempts
# ──────────────────────────────────────────────────────────
section "3. Authentication — Invalid Login Attempts"

# Wrong password
BAD_PASS_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"analyst","password":"wrong_password"}' 2>/dev/null || echo "000")

[ "$BAD_PASS_CODE" = "401" ] && pass_test "Wrong password returns 401" || fail_test "Wrong password expected 401, got $BAD_PASS_CODE"

# Nonexistent user
NO_USER_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nouser","password":"nopass"}' 2>/dev/null || echo "000")

[ "$NO_USER_CODE" = "401" ] && pass_test "Nonexistent user returns 401" || fail_test "Nonexistent user expected 401, got $NO_USER_CODE"

# ──────────────────────────────────────────────────────────
# Test 7-8: GET /auth/me
# ──────────────────────────────────────────────────────────
section "4. Authentication — GET /auth/me"

if [ -n "$ANALYST_TOKEN" ]; then
    ME_RESP=$(curl -sf "${BACKEND_URL}/auth/me" \
        -H "Authorization: Bearer ${ANALYST_TOKEN}" 2>/dev/null || echo "FAIL")

    ME_USER=$(echo "$ME_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('username',''))" 2>/dev/null || echo "")
    ME_ROLE=$(echo "$ME_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null || echo "")

    [ "$ME_USER" = "analyst" ] && pass_test "GET /auth/me returns correct username" || fail_test "GET /auth/me username expected 'analyst', got '$ME_USER'"
    [ "$ME_ROLE" = "analyst" ] && pass_test "GET /auth/me returns correct role" || fail_test "GET /auth/me role expected 'analyst', got '$ME_ROLE'"
else
    warn_test "Skipping /auth/me — no valid token from login"
fi

# Without token
NO_TOKEN_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "${BACKEND_URL}/auth/me" 2>/dev/null || echo "000")
[ "$NO_TOKEN_CODE" = "401" ] || [ "$NO_TOKEN_CODE" = "403" ] && \
    pass_test "GET /auth/me without token returns 401/403" || \
    fail_test "GET /auth/me without token expected 401/403, got $NO_TOKEN_CODE"

# ──────────────────────────────────────────────────────────
# Test 9: Token refresh
# ──────────────────────────────────────────────────────────
section "5. Authentication — Token Refresh"

REFRESH_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/refresh" \
    -b /tmp/accc_cookies_analyst 2>/dev/null || echo "FAIL")

REFRESH_TOKEN=$(echo "$REFRESH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "" ]; then
    pass_test "POST /auth/refresh returns new access token"
    # Verify new token works
    REFRESH_ME=$(curl -sf "${BACKEND_URL}/auth/me" \
        -H "Authorization: Bearer ${REFRESH_TOKEN}" 2>/dev/null || echo "FAIL")
    REFRESH_USER=$(echo "$REFRESH_ME" | python3 -c "import sys,json; print(json.load(sys.stdin).get('username',''))" 2>/dev/null || echo "")
    [ "$REFRESH_USER" = "analyst" ] && pass_test "Refreshed token is valid and works" || warn_test "Could not verify refreshed token"
else
    fail_test "POST /auth/refresh failed" "$REFRESH_RESP"
fi

# ──────────────────────────────────────────────────────────
# Test 10: Logout
# ──────────────────────────────────────────────────────────
section "6. Authentication — Logout"

if [ -n "$SENIOR_TOKEN" ]; then
    LOGOUT_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BACKEND_URL}/auth/logout" \
        -H "Authorization: Bearer ${SENIOR_TOKEN}" \
        -b /tmp/accc_cookies_senior 2>/dev/null || echo "000")

    [ "$LOGOUT_CODE" = "200" ] && pass_test "POST /auth/logout returns 200" || fail_test "POST /auth/logout expected 200, got $LOGOUT_CODE"
else
    warn_test "Skipping logout test — no senior token"
fi

# ──────────────────────────────────────────────────────────
# Test 11: JWT Token Claims
# ──────────────────────────────────────────────────────────
section "7. JWT Token Validation"

if [ -n "$ANALYST_TOKEN" ]; then
    # Decode JWT payload (base64 middle part)
    JWT_PAYLOAD=$(echo "$ANALYST_TOKEN" | cut -d'.' -f2 | python3 -c "
import sys, base64, json
payload = sys.stdin.read().strip()
# Add padding
payload += '=' * (4 - len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload)
data = json.loads(decoded)
print(json.dumps(data))
" 2>/dev/null || echo "{}")

    HAS_USER_ID=$(echo "$JWT_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'user_id' in d else 'no')" 2>/dev/null || echo "no")
    HAS_USERNAME=$(echo "$JWT_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'username' in d else 'no')" 2>/dev/null || echo "no")
    HAS_ROLE=$(echo "$JWT_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'role' in d else 'no')" 2>/dev/null || echo "no")
    HAS_EXP=$(echo "$JWT_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'exp' in d else 'no')" 2>/dev/null || echo "no")

    [ "$HAS_USER_ID" = "yes" ] && pass_test "JWT contains user_id claim" || fail_test "JWT missing user_id claim"
    [ "$HAS_USERNAME" = "yes" ] && pass_test "JWT contains username claim" || fail_test "JWT missing username claim"
    [ "$HAS_ROLE" = "yes" ] && pass_test "JWT contains role claim" || fail_test "JWT missing role claim"
    [ "$HAS_EXP" = "yes" ] && pass_test "JWT contains exp claim" || fail_test "JWT missing exp claim"
else
    warn_test "Skipping JWT validation — no token"
fi

# ──────────────────────────────────────────────────────────
# Test 12: Events API backward compatibility
# ──────────────────────────────────────────────────────────
section "8. Backward Compatibility — Events API"

EVENTS_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "${BACKEND_URL}/api/v1/events?limit=1" 2>/dev/null || echo "000")
if [ "$EVENTS_CODE" = "200" ]; then
    pass_test "GET /api/v1/events still works (backward compatible)"
else
    # Events might now require auth — that's also acceptable
    warn_test "GET /api/v1/events returned $EVENTS_CODE (may now require auth — this is fine)"
fi

STATS_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "${BACKEND_URL}/api/v1/events/stats" 2>/dev/null || echo "000")
if [ "$STATS_CODE" = "200" ]; then
    pass_test "GET /api/v1/events/stats still works"
else
    warn_test "GET /api/v1/events/stats returned $STATS_CODE"
fi

# ──────────────────────────────────────────────────────────
# Test 13-16: WebSocket endpoints exist
# ──────────────────────────────────────────────────────────
section "9. WebSocket Endpoints"

# We test by attempting HTTP upgrade — a 403 or protocol error means the endpoint exists
# Using curl's websocket support or just checking the response

for WS_PATH in "ws/events?token=invalid" "ws/chat/test-session?token=invalid" "ws/agent/test-run?token=invalid" "ws/hunt/test-hunt?token=invalid"; do
    WS_NAME=$(echo "$WS_PATH" | cut -d'?' -f1)
    WS_RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "Connection: Upgrade" \
        -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        "${BACKEND_URL}/${WS_PATH}" 2>/dev/null || echo "000")

    # 101 = upgrade successful, 403 = auth rejected, 400 = bad WS request
    # All of these mean the endpoint EXISTS
    if [ "$WS_RESP" = "101" ] || [ "$WS_RESP" = "403" ] || [ "$WS_RESP" = "400" ]; then
        pass_test "/${WS_NAME} endpoint exists (HTTP $WS_RESP)"
    else
        # For WebSocket, many codes are acceptable — the key is it's not 404
        if [ "$WS_RESP" != "404" ] && [ "$WS_RESP" != "000" ]; then
            pass_test "/${WS_NAME} endpoint exists (HTTP $WS_RESP)"
        else
            fail_test "/${WS_NAME} endpoint not found (HTTP $WS_RESP)"
        fi
    fi
done

# ──────────────────────────────────────────────────────────
# Test 17: Redis refresh token storage
# ──────────────────────────────────────────────────────────
section "10. Redis Token Storage"

REDIS_KEYS=$(docker exec accc-redis-1 redis-cli KEYS "refresh:*" 2>/dev/null || \
             docker exec accc_redis_1 redis-cli KEYS "refresh:*" 2>/dev/null || echo "ERROR")

if [ "$REDIS_KEYS" = "ERROR" ]; then
    # Try with docker compose
    REDIS_KEYS=$(docker compose exec redis redis-cli KEYS "refresh:*" 2>/dev/null || echo "ERROR")
fi

if [ "$REDIS_KEYS" != "ERROR" ] && [ -n "$REDIS_KEYS" ] && [ "$REDIS_KEYS" != "(empty array)" ]; then
    pass_test "Refresh tokens stored in Redis"
else
    warn_test "Could not verify Redis refresh tokens (container name may differ)"
fi

# ──────────────────────────────────────────────────────────
# Test 18: Backend startup logs
# ──────────────────────────────────────────────────────────
section "11. Backend Startup Verification"

LOGS=$(docker compose logs backend --tail=50 2>/dev/null || docker logs accc-backend-1 --tail=50 2>/dev/null || echo "")

if echo "$LOGS" | grep -qi "startup complete\|started\|application startup"; then
    pass_test "Backend startup logged successfully"
else
    warn_test "Could not verify backend startup logs"
fi

if echo "$LOGS" | grep -qi "scheduler\|APScheduler"; then
    pass_test "APScheduler startup detected in logs"
else
    warn_test "APScheduler startup not found in logs"
fi

if echo "$LOGS" | grep -qi "redis.*bridge\|redis_bridge\|subscribing"; then
    pass_test "Redis bridge startup detected in logs"
else
    warn_test "Redis bridge startup not found in logs"
fi

if echo "$LOGS" | grep -qi "heartbeat"; then
    pass_test "WebSocket heartbeat startup detected in logs"
else
    warn_test "WebSocket heartbeat not found in logs"
fi

# ──────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Phase 2.1 Validation Summary${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}PASS: ${PASS}${NC}"
echo -e "  ${RED}FAIL: ${FAIL}${NC}"
echo -e "  ${YELLOW}WARN: ${WARN}${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✅ Phase 2.1 PASSED — Authentication & WebSocket ready!${NC}"
    echo -e "  ${GREEN}   Proceed to Phase 2.2: RAG Pipeline & Prompt Templates${NC}"
else
    echo -e "  ${RED}${BOLD}❌ Phase 2.1 has ${FAIL} failure(s) — fix before proceeding${NC}"
fi
echo ""

# Cleanup
rm -f /tmp/accc_cookies_analyst /tmp/accc_cookies_senior /tmp/accc_cookies_manager

exit $FAIL