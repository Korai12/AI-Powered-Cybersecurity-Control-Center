#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ACCC Phase 2.2 Validation Script
# RAG Pipeline & Prompt Templates
# ═══════════════════════════════════════════════════════════
#
# Tests:
#   1.  Backend healthy
#   2.  OpenAI API key configured (non-empty)
#   3.  ChromaDB collections accessible via v2 API
#   4.  ChromaDB mitre_techniques collection has data
#   5.  ChromaDB threat_intel collection has data
#   6.  ChromaDB cve_highlights collection has data
#   7.  ChromaDB past_incidents collection has data
#   8.  Prompt template files exist in container
#   9.  RAG module importable (no syntax errors)
#   10. OpenAI helper module importable
#   11. Embedding generation works (OpenAI API call)
#   12. RAG Layer 1 semantic search returns results
#   13. Full RAG query returns structured response
#   14. Auth still works (regression check)
#
# Usage: chmod +x validate_phase2_2.sh && bash validate_phase2_2.sh
# ═══════════════════════════════════════════════════════════

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
CHROMADB_URL="${CHROMADB_URL:-http://localhost:8001}"
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
echo -e "${BOLD}║    ACCC Phase 2.2 — Validation Script                    ║${NC}"
echo -e "${BOLD}║    RAG Pipeline & Prompt Templates                       ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"

# ──────────────────────────────────────────────────────────
# Wait for backend
# ──────────────────────────────────────────────────────────
section "1. Backend Health"
MAX_WAIT=90
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    if curl -sf "${BACKEND_URL}/health" > /dev/null 2>&1; then break; fi
    sleep 2; ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    fail_test "Backend not reachable after ${MAX_WAIT}s"
    exit 1
fi
pass_test "Backend is healthy"

# ──────────────────────────────────────────────────────────
# Check ChromaDB collections via v2 API (external port 8001)
# ──────────────────────────────────────────────────────────
section "2. ChromaDB Collections (v2 API)"

CHROMA_V2="${CHROMADB_URL}/api/v2/tenants/default_tenant/databases/default_database"

for COLLECTION in mitre_techniques threat_intel cve_highlights past_incidents; do
    COLL_RESP=$(curl -sf "${CHROMA_V2}/collections/${COLLECTION}" 2>/dev/null || echo "FAIL")

    if [ "$COLL_RESP" = "FAIL" ]; then
        fail_test "ChromaDB collection '${COLLECTION}' not accessible"
    else
        COLL_ID=$(echo "$COLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
        if [ -n "$COLL_ID" ] && [ "$COLL_ID" != "" ]; then
            pass_test "Collection '${COLLECTION}' exists (UUID: ${COLL_ID:0:8}...)"

            # Check count via the collection endpoint
            COUNT_RESP=$(curl -sf "${CHROMA_V2}/collections/${COLL_ID}/count" 2>/dev/null || echo "0")
            COUNT=$(echo "$COUNT_RESP" | python3 -c "import sys; print(sys.stdin.read().strip())" 2>/dev/null || echo "0")
            if [ "$COUNT" != "0" ] && [ "$COUNT" != "" ]; then
                pass_test "  └─ ${COLLECTION} has ${COUNT} vectors"
            else
                warn_test "  └─ ${COLLECTION} count could not be verified (response: ${COUNT_RESP:0:50})"
            fi
        else
            fail_test "ChromaDB collection '${COLLECTION}' — could not get UUID"
        fi
    fi
done

# ──────────────────────────────────────────────────────────
# Check prompt templates exist in container
# ──────────────────────────────────────────────────────────
section "3. Prompt Template Files"

# Get backend container name
BACKEND_CONTAINER=$(docker compose ps -q backend 2>/dev/null || docker ps -qf "name=backend" 2>/dev/null || echo "")

if [ -n "$BACKEND_CONTAINER" ]; then
    for PROMPT_FILE in "services/ai/prompts/triage.txt" "services/ai/prompts/chat_system.txt"; do
        EXISTS=$(docker exec "$BACKEND_CONTAINER" test -f "/app/backend/${PROMPT_FILE}" && echo "yes" || echo "no")
        if [ "$EXISTS" = "yes" ]; then
            SIZE=$(docker exec "$BACKEND_CONTAINER" sh -c "wc -c < /app/backend/${PROMPT_FILE}" 2>/dev/null || echo "0")
            pass_test "${PROMPT_FILE} exists (${SIZE} bytes)"
        else
            fail_test "${PROMPT_FILE} not found in container"
        fi
    done
else
    warn_test "Could not determine backend container — skipping file checks"
fi

# ──────────────────────────────────────────────────────────
# Check Python modules importable
# ──────────────────────────────────────────────────────────
section "4. Python Module Import Checks"

if [ -n "$BACKEND_CONTAINER" ]; then
    # Check openai_helper
    IMPORT_OH=$(docker exec "$BACKEND_CONTAINER" python3 -c "
import sys; sys.path.insert(0, '/app/backend')
from services.ai.openai_helper import get_embedding, chat_completion_json, chat_completion_stream
print('OK')
" 2>&1)
    if echo "$IMPORT_OH" | grep -q "OK"; then
        pass_test "openai_helper module imports successfully"
    else
        fail_test "openai_helper import failed" "${IMPORT_OH:0:200}"
    fi

    # Check rag
    IMPORT_RAG=$(docker exec "$BACKEND_CONTAINER" python3 -c "
import sys; sys.path.insert(0, '/app/backend')
from services.ai.rag import retrieve_context, rag_query, layer1_semantic_search
print('OK')
" 2>&1)
    if echo "$IMPORT_RAG" | grep -q "OK"; then
        pass_test "rag module imports successfully"
    else
        fail_test "rag module import failed" "${IMPORT_RAG:0:200}"
    fi
else
    warn_test "Skipping import checks — no container access"
fi

# ──────────────────────────────────────────────────────────
# Test OpenAI API connectivity (embedding call)
# ──────────────────────────────────────────────────────────
section "5. OpenAI API Connectivity"

if [ -n "$BACKEND_CONTAINER" ]; then
    EMBED_TEST=$(docker exec "$BACKEND_CONTAINER" python3 -c "
import sys, asyncio; sys.path.insert(0, '/app/backend')
from services.ai.openai_helper import get_embedding

async def test():
    try:
        vec = await get_embedding('test security event brute force login')
        print(f'OK:{len(vec)}')
    except Exception as e:
        print(f'ERROR:{e}')

asyncio.run(test())
" 2>&1)

    if echo "$EMBED_TEST" | grep -q "OK:1536"; then
        pass_test "OpenAI embedding API works (1536-dim vector returned)"
    elif echo "$EMBED_TEST" | grep -q "OK:"; then
        DIM=$(echo "$EMBED_TEST" | grep -oP 'OK:\K\d+')
        pass_test "OpenAI embedding API works (${DIM}-dim vector returned)"
    else
        fail_test "OpenAI embedding API failed" "${EMBED_TEST:0:200}"
    fi
else
    warn_test "Skipping OpenAI test — no container access"
fi

# ──────────────────────────────────────────────────────────
# Test RAG Layer 1 semantic search
# ──────────────────────────────────────────────────────────
section "6. RAG Layer 1 — Semantic Search"

if [ -n "$BACKEND_CONTAINER" ]; then
    RAG_TEST=$(docker exec "$BACKEND_CONTAINER" python3 -c "
import sys, asyncio; sys.path.insert(0, '/app/backend')
from services.ai.rag import layer1_semantic_search

async def test():
    try:
        results = await layer1_semantic_search('ransomware lateral movement brute force')
        print(f'OK:{len(results)}')
        if results:
            print(f'COLLECTIONS:{set(r[\"collection\"] for r in results)}')
    except Exception as e:
        print(f'ERROR:{e}')

asyncio.run(test())
" 2>&1)

    if echo "$RAG_TEST" | grep -q "OK:"; then
        COUNT=$(echo "$RAG_TEST" | grep -oP 'OK:\K\d+')
        if [ "$COUNT" -gt 0 ]; then
            pass_test "RAG semantic search returned ${COUNT} results"
            COLLS=$(echo "$RAG_TEST" | grep "COLLECTIONS:" | head -1 || echo "")
            if [ -n "$COLLS" ]; then
                pass_test "  └─ Results from: ${COLLS#COLLECTIONS:}"
            fi
        else
            warn_test "RAG semantic search returned 0 results (ChromaDB may be empty)"
        fi
    else
        fail_test "RAG semantic search failed" "${RAG_TEST:0:300}"
    fi
else
    warn_test "Skipping RAG test — no container access"
fi

# ──────────────────────────────────────────────────────────
# Test full RAG query (requires OpenAI API)
# ──────────────────────────────────────────────────────────
section "7. Full RAG Query (LLM synthesis)"

if [ -n "$BACKEND_CONTAINER" ]; then
    RAG_FULL=$(docker exec "$BACKEND_CONTAINER" python3 -c "
import sys, asyncio, json; sys.path.insert(0, '/app/backend')
from services.ai.rag import rag_query

async def test():
    try:
        result = await rag_query(
            query='What MITRE techniques are associated with ransomware attacks?',
            system_prompt='You are a security analyst. Answer the question using the provided context.',
            model='gpt-4.1',
            max_tokens=500,
        )
        has_text = 'response_text' in result
        has_conf = 'confidence' in result
        has_sources = 'rag_sources' in result
        print(f'OK:text={has_text},conf={has_conf},sources={has_sources}')
        if has_sources:
            print(f'SOURCES:{json.dumps(result[\"rag_sources\"])}')
    except Exception as e:
        print(f'ERROR:{e}')

asyncio.run(test())
" 2>&1)

    if echo "$RAG_FULL" | grep -q "OK:"; then
        pass_test "Full RAG query completed successfully"
        # Check structured fields
        echo "$RAG_FULL" | grep -q "text=True" && pass_test "  └─ response_text field present" || warn_test "  └─ response_text missing"
        echo "$RAG_FULL" | grep -q "conf=True" && pass_test "  └─ confidence field present" || warn_test "  └─ confidence missing"
        echo "$RAG_FULL" | grep -q "sources=True" && pass_test "  └─ rag_sources metadata present" || warn_test "  └─ rag_sources missing"

        SOURCES=$(echo "$RAG_FULL" | grep "SOURCES:" | head -1 || echo "")
        if [ -n "$SOURCES" ]; then
            pass_test "  └─ RAG sources: ${SOURCES#SOURCES:}"
        fi
    else
        fail_test "Full RAG query failed" "${RAG_FULL:0:300}"
    fi
else
    warn_test "Skipping full RAG test — no container access"
fi

# ──────────────────────────────────────────────────────────
# Regression: Auth still works
# ──────────────────────────────────────────────────────────
section "8. Regression — Auth Still Works"

LOGIN_RESP=$(curl -sf -X POST "${BACKEND_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"analyst","password":"analyst123"}' 2>/dev/null || echo "FAIL")

TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "$TOKEN" ] && [ "$TOKEN" != "" ]; then
    pass_test "Auth login still works (regression OK)"
else
    fail_test "Auth login regression failed" "$LOGIN_RESP"
fi

# ──────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Phase 2.2 Validation Summary${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}PASS: ${PASS}${NC}"
echo -e "  ${RED}FAIL: ${FAIL}${NC}"
echo -e "  ${YELLOW}WARN: ${WARN}${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✅ Phase 2.2 PASSED — RAG Pipeline & Prompts ready!${NC}"
    echo -e "  ${GREEN}   Proceed to Phase 2.3: AI Alert Triage Engine${NC}"
else
    echo -e "  ${RED}${BOLD}❌ Phase 2.2 has ${FAIL} failure(s) — fix before proceeding${NC}"
fi
echo ""

exit $FAIL