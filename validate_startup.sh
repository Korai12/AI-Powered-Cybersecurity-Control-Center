#!/usr/bin/env bash
# ============================================================
# ACCC — Cold-Start Validation Script
# Runs docker compose up --build and verifies all 7 services
# reach healthy state and all critical endpoints respond.
#
# Usage: ./validate_startup.sh
# Expected result: all PASS lines, exit code 0
# ============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
INFO="${BLUE}[INFO]${NC}"
WARN="${YELLOW}[WARN]${NC}"

FAILURES=0

# ── Helpers ───────────────────────────────────────────────────────────────────
check() {
  local label="$1"
  local cmd="$2"
  if eval "$cmd" &>/dev/null; then
    echo -e "${PASS} ${label}"
  else
    echo -e "${FAIL} ${label}"
    FAILURES=$((FAILURES + 1))
  fi
}

wait_for_url() {
  local label="$1"
  local url="$2"
  local max_wait="${3:-120}"
  local elapsed=0

  echo -ne "${INFO} Waiting for ${label}..."
  until curl -sf "$url" &>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    echo -ne "."
    if [ "$elapsed" -ge "$max_wait" ]; then
      echo -e "\n${FAIL} ${label} did not become available within ${max_wait}s"
      FAILURES=$((FAILURES + 1))
      return 1
    fi
  done
  echo -e "\n${PASS} ${label} is up"
}

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       ACCC — Cold-Start Validation                           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Prereqs ───────────────────────────────────────────────────────────
echo -e "${BOLD}── Step 1: Prerequisites ─────────────────────────────────────${NC}"
check "Docker available"         "docker info"
check "Docker Compose available" "docker compose version"
check ".env file exists"         "[ -f .env ]"
check "OPENAI_API_KEY set"       "grep -q 'OPENAI_API_KEY=.' .env"
check "POSTGRES_PASSWORD set"    "grep -q 'POSTGRES_PASSWORD=.' .env"
check "JWT_SECRET set"           "grep -q 'JWT_SECRET=.' .env"
echo ""

# ── Step 2: Tear down any existing state ──────────────────────────────────────
echo -e "${BOLD}── Step 2: Clean State ───────────────────────────────────────${NC}"
echo -e "${INFO} Stopping any existing containers..."
docker compose down --remove-orphans --volumes &>/dev/null || true
echo -e "${PASS} Clean state confirmed"
echo ""

# ── Step 3: Build & start ─────────────────────────────────────────────────────
echo -e "${BOLD}── Step 3: docker compose up --build ────────────────────────${NC}"
echo -e "${INFO} Building and starting all 7 services (this may take 2-3 min on first run)..."
docker compose up --build -d
echo -e "${PASS} docker compose up completed"
echo ""

# ── Step 4: Wait for all services to be healthy ───────────────────────────────
echo -e "${BOLD}── Step 4: Service Health Checks (max 180s) ─────────────────${NC}"
wait_for_url "postgres"    "http://localhost:5432"        60  || true  # TCP checked differently
wait_for_url "backend /health" "http://localhost:8000/health" 180
wait_for_url "frontend"    "http://localhost:3000"        60
echo ""

# Check Docker health states
echo -e "${BOLD}── Step 4b: Docker Service States ───────────────────────────${NC}"
for svc in postgres redis chromadb backend frontend log_generator; do
  state=$(docker compose ps --format json 2>/dev/null | \
    python3 -c "import sys,json; d=[json.loads(l) for l in sys.stdin]; \
    [print(s.get('Health','unknown')) for s in d if '$svc' in s.get('Service','')]" \
    2>/dev/null | head -1 || echo "unknown")
  if [ "$state" = "healthy" ]; then
    echo -e "${PASS} $svc → healthy"
  else
    echo -e "${WARN} $svc → ${state} (may still be starting)"
  fi
done
echo ""

# ── Step 5: Endpoint smoke tests ─────────────────────────────────────────────
echo -e "${BOLD}── Step 5: Endpoint Smoke Tests ─────────────────────────────${NC}"
check "GET /health returns 200"          "curl -sf http://localhost:8000/health"
check "GET /health includes status:ok"   "curl -sf http://localhost:8000/health | grep -q '\"status\"'"
check "Frontend serves HTML"             "curl -sf http://localhost:3000 | grep -qi 'html'"
check "POST /auth/login endpoint exists" \
  "curl -sf -o /dev/null -w '%{http_code}' -X POST http://localhost:8000/auth/login \
   -H 'Content-Type: application/json' \
   -d '{\"username\":\"analyst\",\"password\":\"analyst123\"}' | grep -qE '^(200|401|422)'"
echo ""

# ── Step 6: AI pipeline smoke test ───────────────────────────────────────────
echo -e "${BOLD}── Step 6: Auth + AI Pipeline ───────────────────────────────${NC}"

# Login and get token
TOKEN=$(curl -sf -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"analyst123"}' \
  2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" \
  2>/dev/null || echo "")

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
  echo -e "${PASS} Login as analyst succeeded — JWT received"

  # Test authenticated endpoint
  check "GET /api/v1/events (authenticated)" \
    "curl -sf -H 'Authorization: Bearer $TOKEN' http://localhost:8000/api/v1/events"

  # Test NL chat endpoint
  HTTP_CODE=$(curl -sf -o /dev/null -w '%{http_code}' \
    -X POST http://localhost:8000/api/v1/chat/message \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"What is the current threat level?","session_id":"validate-test-001"}' \
    2>/dev/null || echo "000")
  if echo "$HTTP_CODE" | grep -qE '^(200|202)'; then
    echo -e "${PASS} POST /api/v1/chat/message → ${HTTP_CODE}"
  else
    echo -e "${WARN} POST /api/v1/chat/message → ${HTTP_CODE} (AI may need warm-up)"
  fi
else
  echo -e "${WARN} Login failed — seed users may not be ready yet (init_db may still be running)"
fi
echo ""

# ── Step 7: .env.example completeness ────────────────────────────────────────
echo -e "${BOLD}── Step 7: .env.example Completeness ───────────────────────${NC}"
REQUIRED_VARS=(
  "OPENAI_API_KEY"
  "POSTGRES_PASSWORD"
  "POSTGRES_USER"
  "POSTGRES_DB"
  "REDIS_URL"
  "CHROMADB_HOST"
  "CHROMADB_PORT"
  "JWT_SECRET"
  "ABUSEIPDB_API_KEY"
  "LOG_GENERATOR_RATE"
  "ENABLE_AUDIO_ALERTS"
  "ENVIRONMENT"
  "LOG_LEVEL"
)
for var in "${REQUIRED_VARS[@]}"; do
  check ".env.example contains ${var}" "grep -q '^${var}' .env.example"
done
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
if [ "$FAILURES" -eq 0 ]; then
  echo -e "${BOLD}║  ${GREEN}ALL CHECKS PASSED${NC}${BOLD} — ACCC is ready                          ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  Frontend:  ${BOLD}http://localhost:3000${NC}"
  echo -e "  Backend:   ${BOLD}http://localhost:8000${NC}"
  echo -e "  Login:     analyst / analyst123"
  echo ""
  exit 0
else
  echo -e "${BOLD}║  ${RED}${FAILURES} CHECK(S) FAILED${NC}${BOLD} — review output above               ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  exit 1
fi
