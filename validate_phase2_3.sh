## `validate_phase2_3.sh`
#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ACCC Phase 2.3 Validation Script
# AI Alert Triage Engine
# ═══════════════════════════════════════════════════════════

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

pass_test() { PASS=$((PASS + 1)); echo -e "  ${GREEN}✅ PASS${NC} — $1"; }
fail_test() { FAIL=$((FAIL + 1)); echo -e "  ${RED}❌ FAIL${NC} — $1"; [ -n "${2:-}" ] && echo -e "         ${RED}$2${NC}"; }
warn_test() { WARN=$((WARN + 1)); echo -e "  ${YELLOW}⚠️  WARN${NC} — $1"; }
section() { echo ""; echo -e "${BOLD}━━━ $1 ━━━${NC}"; }

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    ACCC Phase 2.3 — Validation Script                    ║${NC}"
echo -e "${BOLD}║    AI Alert Triage Engine                                ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"

section "1. Backend Health"
MAX_WAIT=90
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    if curl -sf "${BACKEND_URL}/health" > /dev/null 2>&1; then break; fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    fail_test "Backend not reachable after ${MAX_WAIT}s"
    exit 1
fi
pass_test "Backend is healthy"

BACKEND_CONTAINER=$(docker compose ps -q backend 2>/dev/null || docker ps -qf "name=backend" 2>/dev/null || echo "")

section "2. Prompt File + Module Imports"
if [ -z "$BACKEND_CONTAINER" ]; then
    fail_test "Could not determine backend container ID"
    exit 1
fi

PROMPT_EXISTS=$(docker exec "$BACKEND_CONTAINER" test -f /app/backend/services/ai/prompts/triage.txt && echo yes || echo no)
if [ "$PROMPT_EXISTS" = "yes" ]; then
    PROMPT_SIZE=$(docker exec "$BACKEND_CONTAINER" sh -c "wc -c < /app/backend/services/ai/prompts/triage.txt" 2>/dev/null || echo "0")
    pass_test "triage prompt exists (${PROMPT_SIZE} bytes)"
else
    fail_test "triage prompt missing in backend container"
fi

IMPORT_TRIAGE=$(docker exec -i "$BACKEND_CONTAINER" python3 - <<'PY'
import sys
import traceback

sys.path.insert(0, "/app/backend")

try:
    from services.ai.triage import triage_event_by_id, triage_pending_events
    print("OK")
except Exception:
    traceback.print_exc()
PY
)
if echo "$IMPORT_TRIAGE" | grep -q "OK"; then
    pass_test "triage module imports successfully"
else
    fail_test "triage module import failed" "${IMPORT_TRIAGE:0:300}"
fi

section "3. Authentication"
LOGIN_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"analyst","password":"analyst123"}' \
    -c /tmp/accc_phase23_cookies 2>/dev/null || echo "FAIL")

TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
if [ -n "$TOKEN" ]; then
    pass_test "analyst login successful"
else
    fail_test "analyst login failed" "$LOGIN_RESP"
    exit 1
fi

section "4. Create Test Event"
INGEST_BODY=$(python3 - <<'PY'
import json
raw_log = json.dumps({
    "timestamp": "2026-03-11T22:30:00Z",
    "source": "phase2.3-validator",
    "event_type": "auth_failure",
    "severity": "high",
    "src_ip": "185.220.101.45",
    "dst_ip": "10.0.0.5",
    "username": "administrator",
    "hostname": "dc01",
    "action": "deny",
    "rule_id": "AUTH-401",
    "tags": ["failed_login", "bruteforce"],
    "message": "15 failed login attempts observed against administrator account"
})
print(json.dumps({"raw_log": raw_log}))
PY
)

INGEST_RESP=$(curl -sf -X POST "${BACKEND_URL}/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d "$INGEST_BODY" 2>/dev/null || echo "FAIL")

EVENT_ID=$(echo "$INGEST_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null || echo "")
if [ -n "$EVENT_ID" ]; then
    pass_test "test event ingested successfully (${EVENT_ID})"
else
    fail_test "test event ingest failed" "$INGEST_RESP"
    exit 1
fi

section "5. Triage Endpoint Security"
NOAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BACKEND_URL}/api/v1/events/${EVENT_ID}/triage" 2>/dev/null || echo "000")
if [ "$NOAUTH_CODE" = "401" ] || [ "$NOAUTH_CODE" = "403" ]; then
    pass_test "triage endpoint rejects unauthenticated access (${NOAUTH_CODE})"
else
    fail_test "triage endpoint should reject unauthenticated access" "HTTP ${NOAUTH_CODE}"
fi

section "6. AI Triage Execution"
TRIAGE_RESP=$(curl -sf "${BACKEND_URL}/api/v1/events/${EVENT_ID}/triage?force=true" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "FAIL")

TRIAGE_CHECK=$(python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data["event_id"]
assert data["status"] in ("triaged", "already_triaged")
assert data["triage_status"] == "triaged"
assert data["verdict"] in {"true_positive", "false_positive", "suspicious"}
assert 0.0 <= float(data["confidence"]) <= 1.0
assert 0.0 <= float(data["severity_score"]) <= 1.0
assert data["severity"] in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
assert isinstance(data["tags"], list)
assert isinstance(data["rag_sources"], dict)
print("OK")
' <<< "$TRIAGE_RESP" 2>/dev/null || echo "FAIL")

if [ "$TRIAGE_CHECK" = "OK" ]; then
    pass_test "AI triage endpoint returned valid structured response"
else
    fail_test "AI triage response structure invalid" "${TRIAGE_RESP:0:400}"
fi

section "7. Persistence Check"
EVENT_RESP=$(curl -sf "${BACKEND_URL}/api/v1/events/${EVENT_ID}" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "FAIL")

EVENT_CHECK=$(python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data["id"]
assert data["triage_status"] == "triaged"
assert data["ai_triage_notes"]
assert data["severity_score"] is not None
assert data["mitre_tactic"]
assert isinstance(data["tags"], list)
print("OK")
' <<< "$EVENT_RESP" 2>/dev/null || echo "FAIL")

if [ "$EVENT_CHECK" = "OK" ]; then
    pass_test "triage results persisted back to events table"
else
    fail_test "persisted event fields invalid" "${EVENT_RESP:0:400}"
fi

section "8. Batch Helper For Pending Events"
INGEST_BODY_2=$(python3 - <<'PY'
import json
raw_log = json.dumps({
    "timestamp": "2026-03-11T22:31:00Z",
    "source": "phase2.3-validator",
    "event_type": "port_scan",
    "severity": "medium",
    "src_ip": "198.51.100.77",
    "dst_ip": "10.0.0.25",
    "hostname": "web01",
    "action": "alert",
    "rule_id": "SCAN-778",
    "tags": ["scan", "external_recon"],
    "message": "Sequential port scan detected against web01"
})
print(json.dumps({"raw_log": raw_log}))
PY
)

INGEST_RESP_2=$(curl -sf -X POST "${BACKEND_URL}/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d "$INGEST_BODY_2" 2>/dev/null || echo "FAIL")
EVENT_ID_2=$(echo "$INGEST_RESP_2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null || echo "")

if [ -n "$EVENT_ID_2" ]; then
    pass_test "second pending event created for batch triage helper"
else
    fail_test "could not create second event for batch triage helper" "$INGEST_RESP_2"
fi

BATCH_TRIAGE=$(docker exec -i "$BACKEND_CONTAINER" python3 - <<'PY'
import asyncio
import json
import sys
sys.path.insert(0, "/app/backend")
from services.ai.triage import triage_pending_events

async def main():
    result = await triage_pending_events(limit=5)
    print(json.dumps(result))

asyncio.run(main())
PY
)

BATCH_CHECK=$(python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data["processed"] >= 1
assert data["triaged"] >= 1
assert isinstance(data["event_ids"], list)
print("OK")
' <<< "$BATCH_TRIAGE" 2>/dev/null || echo "FAIL")

if [ "$BATCH_CHECK" = "OK" ]; then
    pass_test "triage_pending_events helper processed pending events"
else
    fail_test "triage_pending_events helper failed" "${BATCH_TRIAGE:0:400}"
fi

section "9. PATCH Regression"
PATCH_RESP=$(curl -sf -X PATCH "${BACKEND_URL}/api/v1/events/${EVENT_ID}/triage" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"triage_status":"closed"}' 2>/dev/null || echo "FAIL")

PATCH_STATUS=$(echo "$PATCH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
if [ "$PATCH_STATUS" = "updated" ]; then
    pass_test "manual PATCH triage endpoint still works"
else
    fail_test "manual PATCH triage regression" "$PATCH_RESP"
fi

echo ""
echo -e "${BOLD}Phase 2.3 Validation Summary${NC}"
echo -e "PASS: ${GREEN}${PASS}${NC}"
echo -e "FAIL: ${RED}${FAIL}${NC}"
echo -e "WARN: ${YELLOW}${WARN}${NC}"

if [ $FAIL -eq 0 ]; then
    echo -e ""
    echo -e "${GREEN}✅ Phase 2.3 PASSED — AI Alert Triage Engine ready!${NC}"
    exit 0
else
    echo -e ""
    echo -e "${RED}❌ Phase 2.3 has ${FAIL} failure(s) — fix before proceeding.${NC}"
    exit 1
fi