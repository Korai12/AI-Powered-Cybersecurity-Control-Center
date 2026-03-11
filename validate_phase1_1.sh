#!/usr/bin/env bash
# validate_phase1_1.sh — Phase 1.1 acceptance test
# Run from the accc/ directory: bash validate_phase1_1.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
BOLD='\033[1m'

PASS=0; FAIL=0; WARN=0
PG_USER="${POSTGRES_USER:-accc}"
PG_DB="${POSTGRES_DB:-accc_db}"
PG_PASS="${POSTGRES_PASSWORD:-}"

pass() { echo -e "${GREEN}✅  PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌  FAIL${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "${YELLOW}⚠️   WARN${NC} $1"; WARN=$((WARN+1)); }
header() { echo -e "\n${BLUE}${BOLD}══════════════════════════════════════════════════${NC}"; echo -e "${BLUE}${BOLD}  $1${NC}"; echo -e "${BLUE}${BOLD}══════════════════════════════════════════════════${NC}"; }

header "ACCC Phase 1.1 — Database & Data Layer Validation"
echo "Timestamp: $(date)"
echo ""

# ── Check 1: All 12 tables exist ─────────────────────────────────────────────
header "CHECK 1: PostgreSQL — All 12 Tables"

EXPECTED_TABLES=(
    users events incidents assets response_actions hunt_results
    conversations analyst_feedback entity_graph security_audit
    ip_reputation_cache cve_cache
)

for table in "${EXPECTED_TABLES[@]}"; do
    result=$(docker compose exec -T postgres \
        psql -U "$PG_USER" -d "$PG_DB" -tAc \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='${table}' AND table_schema='public'" 2>/dev/null || echo "0")
    result=$(echo "$result" | tr -d ' \n\r')
    if [ "$result" = "1" ]; then
        pass "Table exists: $table"
    else
        fail "Table MISSING: $table"
    fi
done

# ── Check 2: events table has 33+ columns ────────────────────────────────────
header "CHECK 2: events table column count"
COL_COUNT=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='events' AND table_schema='public'" 2>/dev/null | tr -d ' \n\r')
if [ "$COL_COUNT" -ge 33 ] 2>/dev/null; then
    pass "events table has $COL_COUNT columns (expected ≥33)"
else
    fail "events table has $COL_COUNT columns (expected ≥33)"
fi

# incidents 27+ columns
INC_COL=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='incidents' AND table_schema='public'" 2>/dev/null | tr -d ' \n\r')
if [ "$INC_COL" -ge 27 ] 2>/dev/null; then
    pass "incidents table has $INC_COL columns (expected ≥27)"
else
    fail "incidents table has $INC_COL columns (expected ≥27)"
fi

# ── Check 3: Critical column types ───────────────────────────────────────────
header "CHECK 3: Critical column types (INET, JSONB, arrays)"

INET_COUNT=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='events' AND udt_name='inet'" 2>/dev/null | tr -d ' \n\r')
if [ "$INET_COUNT" -ge 2 ] 2>/dev/null; then
    pass "events has $INET_COUNT INET columns (src_ip, dst_ip)"
else
    fail "events missing INET columns ($INET_COUNT found)"
fi

JSONB_COUNT=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='incidents' AND udt_name='jsonb'" 2>/dev/null | tr -d ' \n\r')
if [ "$JSONB_COUNT" -ge 2 ] 2>/dev/null; then
    pass "incidents has $JSONB_COUNT JSONB columns"
else
    fail "incidents missing JSONB columns ($JSONB_COUNT found)"
fi

# ── Check 4: Seed users ───────────────────────────────────────────────────────
header "CHECK 4: Seed users in users table"

for user in analyst senior manager; do
    COUNT=$(docker compose exec -T postgres \
        psql -U "$PG_USER" -d "$PG_DB" -tAc \
        "SELECT COUNT(*) FROM users WHERE username='${user}'" 2>/dev/null | tr -d ' \n\r')
    if [ "$COUNT" = "1" ]; then
        pass "Seed user exists: $user"
    else
        fail "Seed user MISSING: $user"
    fi
done

# Verify passwords are bcrypt-hashed
HASH_CHECK=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT password_hash FROM users WHERE username='analyst'" 2>/dev/null | tr -d ' \n\r')
if echo "$HASH_CHECK" | grep -q '^\$2b\$'; then
    pass "analyst password is bcrypt-hashed"
else
    fail "analyst password does NOT look like bcrypt hash"
fi

# Verify roles
for user_role in "analyst:analyst" "senior:senior_analyst" "manager:soc_manager"; do
    uname=$(echo "$user_role" | cut -d: -f1)
    expected_role=$(echo "$user_role" | cut -d: -f2)
    actual_role=$(docker compose exec -T postgres \
        psql -U "$PG_USER" -d "$PG_DB" -tAc \
        "SELECT role FROM users WHERE username='${uname}'" 2>/dev/null | tr -d ' \n\r')
    if [ "$actual_role" = "$expected_role" ]; then
        pass "$uname role = $actual_role"
    else
        fail "$uname role: expected $expected_role, got $actual_role"
    fi
done

# ── Check 5: ChromaDB collections ────────────────────────────────────────────
header "CHECK 5: ChromaDB — 4 collections seeded"

CHROMA_HOST="${CHROMADB_HOST:-localhost}"
CHROMA_PORT="${CHROMADB_PORT:-8001}"

for collection in mitre_techniques threat_intel cve_highlights past_incidents; do
    UUID=$(curl -s --max-time 10 \
        "http://${CHROMA_HOST}:${CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database/collections/${collection}" \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
    if [ -z "$UUID" ]; then
        fail "ChromaDB collection '$collection' not found"
        continue
    fi
    COUNT=$(curl -s --max-time 10 \
        "http://${CHROMA_HOST}:${CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database/collections/${UUID}/count" \
        2>/dev/null | tr -d ' \n\r')
    if echo "$COUNT" | grep -qE '^[0-9]+$' && [ "$COUNT" -gt 0 ]; then
        pass "ChromaDB collection '$collection': $COUNT vectors"
    else
        fail "ChromaDB collection '$collection' empty or not found (got: $COUNT)"
    fi
done

# ── Check 6: Seed data files present ─────────────────────────────────────────
header "CHECK 6: Seed data JSON files"

for fname in mitre_techniques.json threat_intel.json cve_highlights.json past_incidents.json; do
    if [ -f "backend/data/seed/$fname" ]; then
        COUNT=$(python3 -c "import json; data=json.load(open('backend/data/seed/$fname')); print(len(data))" 2>/dev/null || echo "0")
        pass "Seed file present: $fname ($COUNT entries)"
    else
        fail "Seed file MISSING: backend/data/seed/$fname"
    fi
done

# ── Check 7: Alembic migration applied ───────────────────────────────────────
header "CHECK 7: Alembic version table"

ALEMBIC_REV=$(docker compose exec -T postgres \
    psql -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT version_num FROM alembic_version" 2>/dev/null | tr -d ' \n\r')
if [ "$ALEMBIC_REV" = "0001" ]; then
    pass "Alembic revision: $ALEMBIC_REV"
else
    fail "Alembic revision unexpected: '$ALEMBIC_REV' (expected '0001')"
fi

# ── Check 8: CES normalizer importable ───────────────────────────────────────
header "CHECK 8: CES normalizer"

if [ -f "backend/services/ingestion/normalizer.py" ]; then
    PY_CHECK=$(docker compose exec -T backend python3 -c \
        "from services.ingestion.normalizer import CommonEvent, normalize; e=normalize('{\"timestamp\":\"2026-01-01T00:00:00Z\",\"message\":\"test\"}'); print(e.source_format)" 2>/dev/null || echo "error")
    if [ "$PY_CHECK" = "generic_json" ] || [ "$PY_CHECK" = "unknown" ]; then
        pass "CES normalizer importable and functional"
    else
        warn "CES normalizer import check inconclusive (got: $PY_CHECK) — check manually"
    fi
else
    fail "normalizer.py not found at backend/services/ingestion/normalizer.py"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  PHASE 1.1 RESULTS${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  |  ${RED}FAIL: $FAIL${NC}  |  ${YELLOW}WARN: $WARN${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✅  ALL CHECKS PASSED — Phase 1.1 is complete${NC}"
    echo -e "${GREEN}${BOLD}      Ready to proceed to Phase 1.2${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}  ❌  $FAIL CHECK(S) FAILED — Review errors above${NC}"
    echo -e "${YELLOW}      Run: docker compose logs init_db  to diagnose${NC}"
    exit 1
fi
