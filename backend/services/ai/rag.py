"""
ACCC RAG Pipeline — backend/services/ai/rag.py
Phase 2.2: 4-Layer Hybrid RAG Pipeline (F-09 Base)

Called by every AI feature that needs context. Assembles context from 4 layers
before making the LLM call.

    Layer 1 — Semantic (ChromaDB): Vector similarity search across 4 collections
    Layer 2 — Live IP Intel (AbuseIPDB): STUB → Full in Phase 3
    Layer 3 — Live CVE Intel (NVD): STUB → Full in Phase 3
    Layer 4 — Feedback Context (F-21): STUB → Full in Phase 7

ChromaDB v2 API only. All operations via direct HTTP (no SDK dependency).
"""

import json
import logging
import re
from typing import Optional
import httpx

from config import settings
from services.ai.openai_helper import (
    get_embedding,
    chat_completion_text,
    chat_completion_json,
    chat_completion_stream,
    PRIMARY_MODEL,
)

from services.intel.abuseipdb import lookup_abuseipdb
from services.intel.geoip import lookup_geoip
from services.intel.nvd_cve import lookup_cve

logger = logging.getLogger("accc.rag")

# ChromaDB v2 API base
CHROMA_BASE = f"http://{settings.CHROMADB_HOST}:{settings.CHROMADB_PORT}"
CHROMA_V2 = f"{CHROMA_BASE}/api/v2/tenants/default_tenant/databases/default_database"

# Collections to search
RAG_COLLECTIONS = [
    "mitre_techniques",
    "threat_intel",
    "cve_highlights",
    "past_incidents",
]

# Top-k results per collection
TOP_K = 5

# Cache for collection UUIDs (avoids repeated lookups)
_collection_uuid_cache: dict[str, str] = {}


# ──────────────────────────────────────────────────────────
# ChromaDB Helpers (v2 API)
# ──────────────────────────────────────────────────────────

async def _get_collection_uuid(name: str) -> Optional[str]:
    """Get collection UUID by name from ChromaDB v2 API. Cached."""
    if name in _collection_uuid_cache:
        return _collection_uuid_cache[name]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{CHROMA_V2}/collections/{name}")
            if resp.status_code == 200:
                data = resp.json()
                uuid = data.get("id")
                if uuid:
                    _collection_uuid_cache[name] = uuid
                    return uuid
            else:
                logger.warning(f"ChromaDB collection '{name}' not found: {resp.status_code}")
    except Exception as e:
        logger.error(f"ChromaDB connection error for '{name}': {e}")
    return None


async def _query_collection(
    collection_name: str,
    query_embedding: list[float],
    n_results: int = TOP_K,
) -> list[dict]:
    """
    Query a ChromaDB collection by vector similarity.
    Returns list of {document, metadata, distance} dicts.
    """
    uuid = await _get_collection_uuid(collection_name)
    if not uuid:
        return []

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{CHROMA_V2}/collections/{uuid}/query",
                json={
                    "query_embeddings": [query_embedding],
                    "n_results": n_results,
                    "include": ["documents", "metadatas", "distances"],
                },
            )
            if resp.status_code != 200:
                logger.warning(f"ChromaDB query failed for '{collection_name}': {resp.status_code} {resp.text[:200]}")
                return []

            data = resp.json()
            results = []
            documents = data.get("documents", [[]])[0]
            metadatas = data.get("metadatas", [[]])[0]
            distances = data.get("distances", [[]])[0]

            for doc, meta, dist in zip(documents, metadatas, distances):
                if doc:  # skip None documents
                    results.append({
                        "document": doc,
                        "metadata": meta or {},
                        "distance": dist,
                        "collection": collection_name,
                    })

            return results

    except Exception as e:
        logger.error(f"ChromaDB query error for '{collection_name}': {e}")
        return []


# ──────────────────────────────────────────────────────────
# Layer 1 — Semantic Search (ChromaDB)
# ──────────────────────────────────────────────────────────

async def layer1_semantic_search(query: str) -> list[dict]:
    """
    Vector similarity search across all 4 ChromaDB collections.
    Returns top-k results per collection, sorted by relevance.
    """
    try:
        query_embedding = await get_embedding(query)
    except Exception as e:
        logger.error(f"Failed to get query embedding: {e}")
        return []

    all_results = []
    for collection_name in RAG_COLLECTIONS:
        results = await _query_collection(collection_name, query_embedding, TOP_K)
        all_results.extend(results)

    # Sort all results by distance (lower = more similar)
    all_results.sort(key=lambda x: x.get("distance", 999))

    logger.info(f"Layer 1 semantic search: {len(all_results)} results for query '{query[:80]}...'")
    return all_results


# ──────────────────────────────────────────────────────────
# Layer 2 — Live IP Intel (AbuseIPDB) — STUB
# ──────────────────────────────────────────────────────────

async def layer2_ip_intel(query: str, event_context: Optional[dict] = None) -> list[dict]:
    """If query or event context contains external IPs, inject live-or-cached IP intel."""
    ips = _extract_ips(query)
    if event_context:
        for field in ["src_ip", "dst_ip"]:
            ip = event_context.get(field)
            if ip and not _is_private_ip(ip):
                ips.add(str(ip))

    results: list[dict] = []
    for ip in list(ips)[:5]:
        geo = await lookup_geoip(ip)
        reputation = await lookup_abuseipdb(ip)
        if geo or reputation:
            results.append(
                {
                    "ip": ip,
                    "geo": geo,
                    "reputation": reputation,
                }
            )

    return results


# ──────────────────────────────────────────────────────────
# Layer 3 — Live CVE Intel (NVD) — STUB
# ──────────────────────────────────────────────────────────

async def layer3_cve_intel(query: str, event_context: Optional[dict] = None) -> list[dict]:
    """If query or event context contains CVE IDs, inject live-or-cached NVD data."""
    cves = {cve.upper() for cve in _extract_cves(query)}
    if event_context:
        for cve_id in event_context.get("relevant_cves") or []:
            cves.add(str(cve_id).upper())

    results: list[dict] = []
    for cve_id in list(cves)[:5]:
        details = await lookup_cve(cve_id)
        if details:
            results.append(details)

    return results


# ──────────────────────────────────────────────────────────
# Layer 4 — Feedback Context (F-21) — STUB
# ──────────────────────────────────────────────────────────

async def layer4_feedback_context(query: str, event_context: Optional[dict] = None) -> list[dict]:
    """
    Retrieve recent analyst verdicts on similar events from analyst_feedback table.
    Inject as: 'Note: analyst marked 3 similar patterns as false positive last week.'

    STUB — Full implementation in Phase 7.
    Returns empty list until feedback loop is built.
    """
    return []


# ──────────────────────────────────────────────────────────
# Full RAG Pipeline — Assemble Context
# ──────────────────────────────────────────────────────────

async def retrieve_context(
    query: str,
    event_context: Optional[dict] = None,
) -> dict:
    """
    Run all 4 RAG layers and assemble the context dict.
    Called by chat, triage, and other AI features before LLM call.

    Returns:
        {
            "semantic_results": [...],       # Layer 1 ChromaDB results
            "ip_intel": [...],               # Layer 2 AbuseIPDB data
            "cve_intel": [...],              # Layer 3 NVD data
            "feedback_context": [...],       # Layer 4 analyst feedback
            "formatted_context": "...",      # Pre-formatted text for LLM prompt
        }
    """
    # Run all layers
    semantic_results = await layer1_semantic_search(query)
    ip_intel = await layer2_ip_intel(query, event_context)
    cve_intel = await layer3_cve_intel(query, event_context)
    feedback_context = await layer4_feedback_context(query, event_context)

    # Format context for LLM injection
    formatted = _format_context_for_llm(
        semantic_results, ip_intel, cve_intel, feedback_context
    )

    return {
        "semantic_results": semantic_results,
        "ip_intel": ip_intel,
        "cve_intel": cve_intel,
        "feedback_context": feedback_context,
        "formatted_context": formatted,
    }


async def rag_query(
    query: str,
    system_prompt: str,
    event_context: Optional[dict] = None,
    model: str = PRIMARY_MODEL,
    temperature: float = 0.3,
    max_tokens: int = 2000,
) -> dict:
    """
    Full RAG query: retrieve context → synthesize with LLM → return structured response.

    Returns parsed JSON with: response_text, confidence, evidence, suggested_actions
    """
    # Retrieve context from all 4 layers
    context = await retrieve_context(query, event_context)

    # Build messages with injected context
    messages = [
        {
            "role": "system",
            "content": f"{system_prompt}\n\n"
                       f"--- RETRIEVED THREAT INTELLIGENCE CONTEXT ---\n"
                       f"{context['formatted_context']}\n"
                       f"--- END CONTEXT ---\n\n"
                       f"You MUST respond with valid JSON containing: "
                       f"response_text (string), confidence (float 0.0-1.0), "
                       f"evidence (array of strings), suggested_actions (array of strings)."
        },
        {"role": "user", "content": query},
    ]

    result = await chat_completion_json(messages, model, temperature, max_tokens)

    # Ensure required fields exist
    if "response_text" not in result:
        result["response_text"] = result.get("error", "AI analysis completed.")
    if "confidence" not in result:
        result["confidence"] = 0.5
    if "evidence" not in result:
        result["evidence"] = []
    if "suggested_actions" not in result:
        result["suggested_actions"] = []

    # Attach RAG metadata
    result["rag_sources"] = {
        "semantic_count": len(context["semantic_results"]),
        "ip_intel_count": len(context["ip_intel"]),
        "cve_intel_count": len(context["cve_intel"]),
        "feedback_count": len(context["feedback_context"]),
    }

    return result


async def rag_query_stream(
    query: str,
    system_prompt: str,
    event_context: Optional[dict] = None,
    model: str = PRIMARY_MODEL,
    temperature: float = 0.3,
    max_tokens: int = 2000,
):
    """
    Streaming RAG query: retrieve context → stream LLM tokens.
    Yields individual text tokens as they arrive from OpenAI.
    Used by chat WebSocket streaming.

    Returns the context dict separately (caller collects streamed text).
    """
    context = await retrieve_context(query, event_context)

    messages = [
        {
            "role": "system",
            "content": f"{system_prompt}\n\n"
                       f"--- RETRIEVED THREAT INTELLIGENCE CONTEXT ---\n"
                       f"{context['formatted_context']}\n"
                       f"--- END CONTEXT ---"
        },
        {"role": "user", "content": query},
    ]

    return context, chat_completion_stream(messages, model, temperature, max_tokens)


# ──────────────────────────────────────────────────────────
# Context Formatting
# ──────────────────────────────────────────────────────────

def _format_context_for_llm(
    semantic_results: list[dict],
    ip_intel: list[dict],
    cve_intel: list[dict],
    feedback_context: list[dict],
) -> str:
    """Format all RAG layer results into a single text block for LLM prompt injection."""
    sections = []

    # Layer 1 — Semantic search results
    if semantic_results:
        sections.append("## Threat Intelligence Knowledge Base")
        for i, result in enumerate(semantic_results[:15], 1):
            collection = result.get("collection", "unknown")
            doc = result.get("document", "")
            meta = result.get("metadata", {})

            if collection == "mitre_techniques":
                name = meta.get("name", meta.get("technique_name", ""))
                tactic = meta.get("tactic", "")
                sections.append(f"[MITRE] {name} ({tactic}): {doc[:300]}")
            elif collection == "threat_intel":
                name = meta.get("name", meta.get("actor_name", ""))
                sections.append(f"[THREAT INTEL] {name}: {doc[:300]}")
            elif collection == "cve_highlights":
                cve_id = meta.get("cve_id", "")
                cvss = meta.get("cvss", meta.get("cvss_score", ""))
                sections.append(f"[CVE] {cve_id} (CVSS: {cvss}): {doc[:300]}")
            elif collection == "past_incidents":
                title = meta.get("title", "")
                sections.append(f"[PAST INCIDENT] {title}: {doc[:300]}")
            else:
                sections.append(f"[{collection.upper()}] {doc[:300]}")

    # Layer 2 — IP Intel (Phase 3)
    if ip_intel:
        sections.append("\n## IP Reputation Intelligence")
        for entry in ip_intel:
            rep = entry.get("reputation") or {}
            geo = entry.get("geo") or {}
            sections.append(
                f"IP {entry.get('ip', 'N/A')}: "
                f"abuse_score={rep.get('abuse_score', 'N/A')}, "
                f"country={geo.get('geo_country', 'N/A')}, "
                f"city={geo.get('geo_city', 'N/A')}"
            )

    # Layer 3 — CVE Intel (Phase 3)
    if cve_intel:
        sections.append("\n## CVE Intelligence")
        for entry in cve_intel:
            sections.append(
                f"{entry.get('cve_id', 'N/A')}: "
                f"CVSS={entry.get('cvss_score', 'N/A')} — "
                f"{entry.get('description', '')[:200]}"
            )

    # Layer 4 — Feedback (Phase 7)
    if feedback_context:
        sections.append("\n## Analyst Feedback History")
        for entry in feedback_context:
            sections.append(f"Note: {entry.get('note', '')}")

    if not sections:
        return "No relevant threat intelligence context found for this query."

    return "\n".join(sections)


# ──────────────────────────────────────────────────────────
# Utility Helpers
# ──────────────────────────────────────────────────────────

def _extract_ips(text: str) -> set[str]:
    """Extract IPv4 addresses from text, excluding private IPs."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    found = re.findall(ip_pattern, text)
    return {ip for ip in found if not _is_private_ip(ip)}


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC1918 private range."""
    try:
        parts = ip.split(".")
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        return False
    except (ValueError, IndexError):
        return False


def _extract_cves(text: str) -> list[str]:
    """Extract CVE IDs from text (e.g., CVE-2021-44228)."""
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return re.findall(cve_pattern, text, re.IGNORECASE)