from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional, Union
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from services.ai.openai_helper import FAST_MODEL, chat_completion_json
from services.ai.rag import retrieve_context

logger = logging.getLogger("accc.triage")

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "triage.txt"
VALID_VERDICTS = {"true_positive", "false_positive", "suspicious"}
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

SEVERITY_DEFAULTS = {
    "CRITICAL": 0.90,
    "HIGH": 0.70,
    "MEDIUM": 0.50,
    "LOW": 0.30,
    "INFO": 0.10,
}


def _load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8").strip()


def _clamp(value: Any, minimum: float = 0.0, maximum: float = 1.0, default: float = 0.5) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, numeric))


def _default_score_from_event(event: dict[str, Any]) -> float:
    score = event.get("severity_score")
    if score is not None:
        try:
            return float(score)
        except (TypeError, ValueError):
            pass
    return float(SEVERITY_DEFAULTS.get(str(event.get("severity", "MEDIUM")).upper(), 0.50))


def _score_to_severity(score: float) -> str:
    if score >= 0.80:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score >= 0.20:
        return "LOW"
    return "INFO"


def _extract_technique_id(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    match = TECHNIQUE_RE.search(value)
    if match:
        return match.group(0).upper()
    trimmed = value.strip()
    return trimmed[:50] if trimmed else None


def _normalise_tags(existing_tags: Any, ai_tags: Any) -> list[str]:
    combined: list[str] = []

    for source in (existing_tags or [], ai_tags or []):
        if isinstance(source, str):
            items = [source]
        elif isinstance(source, (list, tuple, set)):
            items = list(source)
        else:
            items = []

        for item in items:
            cleaned = str(item).strip().lower().replace(" ", "_")
            if cleaned and cleaned not in combined:
                combined.append(cleaned[:50])

    return combined


def _row_to_serialisable(row: dict[str, Any]) -> dict[str, Any]:
    serialised: dict[str, Any] = {}
    for key, value in row.items():
        if value is None:
            serialised[key] = None
        elif isinstance(value, (str, int, float, bool, list, dict)):
            serialised[key] = value
        else:
            serialised[key] = str(value)
    return serialised


def _build_triage_query(event: dict[str, Any]) -> str:
    parts = [
        f"event_type={event.get('event_type')}",
        f"severity={event.get('severity')}",
        f"source={event.get('source_identifier')}",
    ]

    for field in ("src_ip", "dst_ip", "username", "hostname", "process_name", "action", "rule_id"):
        value = event.get(field)
        if value:
            parts.append(f"{field}={value}")

    relevant_cves = event.get("relevant_cves") or []
    if isinstance(relevant_cves, list) and relevant_cves:
        parts.append(f"relevant_cves={', '.join(map(str, relevant_cves))}")

    tags = event.get("tags") or []
    if isinstance(tags, list) and tags:
        parts.append(f"tags={', '.join(map(str, tags))}")

    raw_log = event.get("raw_log")
    if raw_log:
        parts.append(f"raw_log={raw_log}")

    return " | ".join(parts)


def _format_ai_notes(result: dict[str, Any], rag_sources: dict[str, int]) -> str:
    lines = [
        f"Verdict: {result['verdict']}",
        f"Confidence: {result['confidence']:.2f}",
        f"Severity Score: {result['severity_score']:.2f} ({result['severity']})",
        f"MITRE Tactic: {result.get('mitre_tactic') or 'Unknown'}",
        f"MITRE Technique: {result.get('mitre_technique_full') or result.get('mitre_technique') or 'Unknown'}",
        f"Reasoning: {result.get('reasoning') or 'No reasoning provided.'}",
        f"Recommended Action: {result.get('recommended_action') or 'Investigate further.'}",
        (
            "RAG Sources: "
            f"semantic={rag_sources.get('semantic_count', 0)}, "
            f"ip_intel={rag_sources.get('ip_intel_count', 0)}, "
            f"cve_intel={rag_sources.get('cve_intel_count', 0)}, "
            f"feedback={rag_sources.get('feedback_count', 0)}"
        ),
    ]
    return "\n".join(lines)


def _normalise_llm_result(llm_result: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    verdict = str(llm_result.get("verdict", "suspicious")).strip().lower()
    if verdict not in VALID_VERDICTS:
        verdict = "suspicious"

    confidence = _clamp(llm_result.get("confidence"), default=0.55)
    severity_score = _clamp(
        llm_result.get("severity_override"),
        default=_default_score_from_event(event),
    )

    technique_full = str(llm_result.get("mitre_technique") or "").strip() or None

    return {
        "verdict": verdict,
        "confidence": confidence,
        "severity_score": severity_score,
        "severity": _score_to_severity(severity_score),
        "mitre_tactic": str(llm_result.get("mitre_tactic") or "").strip()[:100] or None,
        "mitre_technique": _extract_technique_id(technique_full),
        "mitre_technique_full": technique_full,
        "reasoning": str(llm_result.get("reasoning") or "").strip()[:4000],
        "recommended_action": str(
            llm_result.get("recommended_action")
            or "Investigate the event, validate host context, and contain if malicious."
        ).strip()[:1000],
        "tags": _normalise_tags(event.get("tags"), llm_result.get("tags")),
        "is_false_positive": verdict == "false_positive",
    }


async def _fetch_event_row(db: AsyncSession, event_id: str) -> Optional[dict[str, Any]]:
    result = await db.execute(text("SELECT * FROM events WHERE id = :id"), {"id": event_id})
    row = result.mappings().first()
    return dict(row) if row else None


async def triage_event_by_id(
    db: AsyncSession,
    event_id: Union[str, UUID],
    analyst_id: Optional[str] = None,
    force: bool = False,
) -> dict[str, Any]:
    event_id_str = str(event_id)
    row = await _fetch_event_row(db, event_id_str)
    if row is None:
        raise ValueError(f"Event {event_id_str} not found")

    event = _row_to_serialisable(row)

    if not force and event.get("triage_status") == "triaged" and event.get("ai_triage_notes"):
        return {
            "event_id": event_id_str,
            "status": "already_triaged",
            "triage_status": "triaged",
            "verdict": "false_positive" if event.get("is_false_positive") else "suspicious",
            "confidence": _default_score_from_event(event),
            "severity_score": _default_score_from_event(event),
            "severity": event.get("severity"),
            "mitre_tactic": event.get("mitre_tactic"),
            "mitre_technique": event.get("mitre_technique"),
            "mitre_technique_full": event.get("mitre_technique"),
            "reasoning": event.get("ai_triage_notes") or "",
            "recommended_action": "",
            "tags": event.get("tags") or [],
            "rag_sources": {
                "semantic_count": 0,
                "ip_intel_count": 0,
                "cve_intel_count": 0,
                "feedback_count": 0,
            },
            "model": FAST_MODEL,
            "analyst_id": analyst_id,
            "is_false_positive": bool(event.get("is_false_positive")),
        }

    triage_query = _build_triage_query(event)
    rag_context = await retrieve_context(triage_query, event_context=event)

    system_prompt = (
        f"{_load_prompt()}\n\n"
        f"--- RETRIEVED THREAT INTELLIGENCE CONTEXT ---\n"
        f"{rag_context['formatted_context']}\n"
        f"--- END CONTEXT ---\n\n"
        "Return only valid JSON."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "event": event,
                    "instructions": "Analyse this event and produce the exact triage JSON schema.",
                },
                ensure_ascii=False,
            ),
        },
    ]

    llm_result = await chat_completion_json(
        messages=messages,
        model=FAST_MODEL,
        temperature=0.1,
        max_tokens=900,
    )

    if llm_result.get("error"):
        raise RuntimeError(f"OpenAI triage call failed: {llm_result['error']}")

    triage = _normalise_llm_result(llm_result, event)

    rag_sources = {
        "semantic_count": len(rag_context["semantic_results"]),
        "ip_intel_count": len(rag_context["ip_intel"]),
        "cve_intel_count": len(rag_context["cve_intel"]),
        "feedback_count": len(rag_context["feedback_context"]),
    }

    ai_notes = _format_ai_notes(triage, rag_sources)

    await db.execute(
        text(
            """
            UPDATE events
            SET triage_status = :triage_status,
                is_false_positive = :is_false_positive,
                ai_triage_notes = :ai_triage_notes,
                mitre_tactic = :mitre_tactic,
                mitre_technique = :mitre_technique,
                severity_score = :severity_score,
                severity = :severity,
                tags = :tags
            WHERE id = :id
            """
        ),
        {
            "id": event_id_str,
            "triage_status": "triaged",
            "is_false_positive": triage["is_false_positive"],
            "ai_triage_notes": ai_notes,
            "mitre_tactic": triage["mitre_tactic"],
            "mitre_technique": triage["mitre_technique"],
            "severity_score": triage["severity_score"],
            "severity": triage["severity"],
            "tags": triage["tags"],
        },
    )
    await db.commit()

    return {
        "event_id": event_id_str,
        "status": "triaged",
        "triage_status": "triaged",
        "verdict": triage["verdict"],
        "confidence": triage["confidence"],
        "severity_score": triage["severity_score"],
        "severity": triage["severity"],
        "mitre_tactic": triage["mitre_tactic"],
        "mitre_technique": triage["mitre_technique"],
        "mitre_technique_full": triage["mitre_technique_full"],
        "reasoning": triage["reasoning"],
        "recommended_action": triage["recommended_action"],
        "tags": triage["tags"],
        "is_false_positive": triage["is_false_positive"],
        "rag_sources": rag_sources,
        "model": FAST_MODEL,
        "analyst_id": analyst_id,
    }


async def triage_pending_events(limit: int = 25) -> dict[str, Any]:
    from database import async_session_factory

    processed = 0
    triaged = 0
    failed = 0
    event_ids: list[str] = []

    async with async_session_factory() as db:
        result = await db.execute(
            text(
                """
                SELECT id
                FROM events
                WHERE triage_status = 'pending'
                ORDER BY timestamp DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        )
        pending_rows = result.fetchall()

        for row in pending_rows:
            processed += 1
            try:
                triage_result = await triage_event_by_id(db, row[0], analyst_id=None, force=False)
                triaged += 1
                event_ids.append(triage_result["event_id"])
            except Exception as exc:
                failed += 1
                logger.exception("Pending triage failed for event %s: %s", row[0], exc)

    return {
        "processed": processed,
        "triaged": triaged,
        "failed": failed,
        "event_ids": event_ids,
    }