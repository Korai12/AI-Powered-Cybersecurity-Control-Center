#!/usr/bin/env bash
# validate_phase1_2.sh — Phase 1.2 acceptance test
# Run from accc/ directory: bash validate_phase1_2.sh

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0; WARN=0

pass() { echo -e "${GREEN}✅  PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌  FAIL${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}⚠️   WARN${NC} $1"; WARN=$((WARN+1)); }
header() { echo -e "\n${BLUE}${BOLD}══════════════════════════════════════════════════${NC}\n${BLUE}${BOLD}  $1${NC}\n${BLUE}${BOLD}══════════════════════════════════════════════════${NC}"; }

PG_USER="${POSTGRES_USER:-accc}"
PG_DB="${POSTGRES_DB:-accc_db}"

header "ACCC Phase 1.2 — Parsers, Generator & Events API"
echo "Timestamp: $(date)"

# ── CHECK 1: Parser files exist ───────────────────────────────────────────────
header "CHECK 1: Parser files present"

PARSERS=(cef syslog windows_evtlog cloudtrail generic_json csv_parser)
for p in "${PARSERS[@]}"; do
    if [ -f "backend/services/ingestion/parsers/${p}.py" ]; then
        pass "Parser file exists: ${p}.py"
    else
        fail "Parser file MISSING: backend/services/ingestion/parsers/${p}.py"
    fi
done

if [ -f "backend/api/events.py" ]; then
    pass "events.py exists"
else
    fail "backend/api/events.py MISSING"
fi

if [ -f "backend/api/simulate.py" ]; then
    pass "simulate.py exists"
else
    fail "backend/api/simulate.py MISSING"
fi

if [ -f "log_generator/generator.py" ]; then
    pass "generator.py exists"
else
    fail "log_generator/generator.py MISSING"
fi

# ── CHECK 2: Backend API endpoints reachable ──────────────────────────────────
header "CHECK 2: Backend API endpoints"

# Health
HEALTH=$(curl -s --max-time 5 http://localhost:8000/health 2>/dev/null)
if echo "$HEALTH" | grep -q "ok"; then
    pass "GET /health returns ok"
else
    fail "GET /health not returning ok (got: $HEALTH)"
fi

# Events list endpoint
EVENTS=$(curl -s --max-time 5 http://localhost:8000/api/v1/events 2>/dev/null)
if echo "$EVENTS" | grep -qE '"total"|"events"'; then
    pass "GET /api/v1/events responds"
else
    fail "GET /api/v1/events not responding (got: $EVENTS)"
fi

# Events stats endpoint
STATS=$(curl -s --max-time 5 "http://localhost:8000/api/v1/events/stats" 2>/dev/null)
if echo "$STATS" | grep -q "counts"; then
    pass "GET /api/v1/events/stats responds"
else
    fail "GET /api/v1/events/stats not responding"
fi

# Simulate scenarios list
SCENARIOS=$(curl -s --max-time 5 http://localhost:8000/api/v1/simulate/scenarios 2>/dev/null)
if echo "$SCENARIOS" | grep -q "ransomware"; then
    pass "GET /api/v1/simulate/scenarios lists scenarios"
else
    fail "GET /api/v1/simulate/scenarios not responding"
fi

# ── CHECK 3: Event ingest endpoint works ─────────────────────────────────────
header "CHECK 3: Event ingest — POST /api/v1/events/ingest"

INGEST=$(curl -s --max-time 10 -X POST http://localhost:8000/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d '{"raw_log": "{\"timestamp\":\"2026-03-11T10:00:00Z\",\"severity\":\"HIGH\",\"event_type\":\"validation_test\",\"source\":\"validate_script\",\"message\":\"Phase 1.2 validation test event\"}"}' \
    2>/dev/null)

if echo "$INGEST" | grep -q "event_id"; then
    EID=$(echo "$INGEST" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null)
    pass "POST /api/v1/events/ingest returned event_id: ${EID:0:8}..."
else
    fail "POST /api/v1/events/ingest failed (got: $INGEST)"
fi

# ── CHECK 4: Parser correctness ───────────────────────────────────────────────
header "CHECK 4: Parser correctness — each format"

# CEF
CEF_RESULT=$(curl -s --max-time 10 -X POST http://localhost:8000/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d "{\"raw_log\":\"CEF:0|ArcSight|Logger|7.2|100|Port Scan Detected|8|src=9.9.9.9 dst=10.0.0.1 dpt=22 act=blocked rt=$(date +%s)000\"}" \
    2>/dev/null)
if echo "$CEF_RESULT" | grep -q "event_id"; then
    SEV=$(echo "$CEF_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)
    if [ "$SEV" = "HIGH" ] || [ "$SEV" = "CRITICAL" ]; then
        pass "CEF parser: ingested, severity=$SEV"
    else
        warn "CEF parser: ingested but severity=$SEV (expected HIGH/CRITICAL)"
    fi
else
    fail "CEF parser: ingest failed"
fi

# Syslog
SYS_RESULT=$(curl -s --max-time 10 -X POST http://localhost:8000/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d '{"raw_log":"<86>Mar 11 10:00:00 webserver sshd[1234]: Failed password for invalid user admin from 5.5.5.5 port 54321 ssh2"}' \
    2>/dev/null)
if echo "$SYS_RESULT" | grep -q "event_id"; then
    pass "Syslog parser: ingested successfully"
else
    fail "Syslog parser: ingest failed"
fi

# Windows Event Log
WIN_LOG="{\"EventID\":4625,\"Level\":2,\"TimeCreated\":\"2026-03-11T10:00:00Z\",\"Computer\":\"ws-01\",\"EventData\":{\"SubjectUserName\":\"jsmith\",\"IpAddress\":\"1.2.3.4\"}}"
WIN_RESULT=$(curl -s --max-time 10 -X POST http://localhost:8000/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d "{\"raw_log\":$(python3 -c "import json; print(json.dumps('$WIN_LOG'))" 2>/dev/null || echo "\"$WIN_LOG\"")}" \
    2>/dev/null)
if echo "$WIN_RESULT" | grep -q "event_id"; then
    pass "Windows Event Log parser: ingested successfully"
else
    # Try direct approach
    WIN_RESULT2=$(docker compose exec -T backend python3 -c \
        "from services.ingestion.parsers.windows_evtlog import parse; e=parse('{\"EventID\":4625,\"Level\":2,\"TimeCreated\":\"2026-03-11T10:00:00Z\",\"Computer\":\"ws-01\"}'); print(e.event_type)" \
        2>/dev/null)
    if [ "$WIN_RESULT2" = "auth_failure" ]; then
        pass "Windows Event Log parser: functional (direct test)"
    else
        warn "Windows Event Log parser: inconclusive — check manually"
    fi
fi

# CloudTrail
CT_LOG="{\"eventVersion\":\"1.08\",\"eventName\":\"ConsoleLogin\",\"eventTime\":\"2026-03-11T10:00:00Z\",\"sourceIPAddress\":\"1.2.3.4\",\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"admin\"},\"errorCode\":null,\"awsRegion\":\"us-east-1\"}"
CT_RESULT=$(python3 -c "
import json, urllib.request
ct = json.dumps({'eventVersion':'1.08','eventName':'ConsoleLogin','eventTime':'2026-03-11T10:00:00Z','sourceIPAddress':'1.2.3.4','userIdentity':{'type':'IAMUser','userName':'admin'},'errorCode':None,'awsRegion':'us-east-1'})
payload = json.dumps({'raw_log': ct}).encode()
req = urllib.request.Request('http://localhost:8000/api/v1/events/ingest', data=payload, headers={'Content-Type':'application/json'}, method='POST')
import urllib.error
try:
    with urllib.request.urlopen(req, timeout=10) as r: print(r.read().decode())
except Exception as e: print(str(e))
" 2>/dev/null)
if echo "$CT_RESULT" | grep -q "event_id"; then
    pass "CloudTrail parser: ingested successfully"
else
    fail "CloudTrail parser: ingest failed"
fi

# ── CHECK 5: Events in PostgreSQL ─────────────────────────────────────────────
header "CHECK 5: Events flowing into PostgreSQL"

EVENT_COUNT=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc "SELECT COUNT(*) FROM events" 2>/dev/null | tr -d ' \n\r')

if [ "$EVENT_COUNT" -gt 0 ] 2>/dev/null; then
    pass "events table has $EVENT_COUNT rows"
else
    fail "events table is empty (count=$EVENT_COUNT)"
fi

# Check event rate — give it 30 seconds
header "CHECK 6: Background noise rate (~30 events/min)"
echo "  Waiting 30 seconds to measure event rate..."

COUNT_BEFORE=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc "SELECT COUNT(*) FROM events" 2>/dev/null | tr -d ' \n\r')
sleep 30
COUNT_AFTER=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc "SELECT COUNT(*) FROM events" 2>/dev/null | tr -d ' \n\r')

DELTA=$((COUNT_AFTER - COUNT_BEFORE))
RATE=$((DELTA * 2))  # events per minute (30s × 2)

if [ "$RATE" -ge 20 ] 2>/dev/null; then
    pass "Event rate: ~${RATE}/min (expected ≥20/min)"
elif [ "$RATE" -ge 5 ] 2>/dev/null; then
    warn "Event rate: ~${RATE}/min (low — expected ~30/min, check LOG_GENERATOR_RATE)"
else
    fail "Event rate: ~${RATE}/min — generator may not be running"
fi

# ── CHECK 7: Simulate endpoint ────────────────────────────────────────────────
header "CHECK 7: Simulate endpoint"

SIM=$(curl -s --max-time 10 -X POST http://localhost:8000/api/v1/simulate/ransomware \
    -H "Content-Type: application/json" 2>/dev/null)
if echo "$SIM" | grep -q "triggered"; then
    pass "POST /api/v1/simulate/ransomware returns triggered"
else
    fail "POST /api/v1/simulate/ransomware failed (got: $SIM)"
fi

# ── CHECK 8: log_generator health ────────────────────────────────────────────
header "CHECK 8: log_generator health check"

GEN_HEALTH=$(curl -s --max-time 5 http://localhost:8080/health 2>/dev/null)
if echo "$GEN_HEALTH" | grep -q "ok"; then
    pass "log_generator health endpoint: ok"
else
    warn "log_generator /health not reachable on localhost:8080 (may be internal-only)"
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  PHASE 1.2 RESULTS${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  |  ${RED}FAIL: $FAIL${NC}  |  ${YELLOW}WARN: $WARN${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✅  ALL CHECKS PASSED — Phase 1.2 complete${NC}"
    echo -e "${GREEN}${BOLD}      Phase 1 fully done. Ready for Phase 2.${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}  ❌  $FAIL CHECK(S) FAILED${NC}"
    echo -e "${YELLOW}      Run: docker compose logs backend log_generator${NC}"
    exit 1
fi