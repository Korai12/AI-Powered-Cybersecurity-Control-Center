# Stub — implemented in its respective phase
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session_factory
from models.event import Event
from models.hunt_result import HuntResult
from services.ai.openai_helper import FAST_MODEL, chat_completion_json
from services.ai.rag import retrieve_context
from websocket.manager import manager as ws_manager

logger = logging.getLogger("accc.hunt")

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "hunt.txt"
DEFAULT_LOOKBACK_HOURS = 2
MAX_RECENT_EVENTS = 150
MAX_AI_EVENTS = 40


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_uuid(value: str | UUID | None) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except Exception:
        return None


def _load_prompt() -> str:
    try:
        content = PROMPT_PATH.read_text(encoding="utf-8").strip()
        if content:
            return content
    except Exception:
        pass

    return """
You are ACCC's proactive threat hunting engine.

Your job:
1. Review the provided hunt hypothesis and recent security events.
2. Identify suspicious patterns that support or weaken the hypothesis.
3. Be conservative: do not invent evidence that is not present.
4. Prefer concrete indicators: IPs, usernames, hostnames, processes, MITRE techniques, timestamps.
5. Return ONLY valid JSON.

Required JSON shape:
{
  "findings": [
    {
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "description": "clear analyst-facing summary",
      "event_ids": ["uuid1", "uuid2"],
      "confidence": 0.0
    }
  ],
  "ai_narrative": "2-6 sentence narrative summary for the analyst",
  "technique_coverage": ["T1021", "T1110"]
}
""".strip()


def _event_blob(event: Event) -> str:
    parts = [
        event.event_type,
        event.severity,
        str(event.src_ip) if event.src_ip else None,
        str(event.dst_ip) if event.dst_ip else None,
        event.username,
        event.hostname,
        event.process_name,
        event.action,
        event.rule_id,
        event.mitre_tactic,
        event.mitre_technique,
        " ".join(event.tags or []),
        " ".join(event.relevant_cves or []),
        (event.raw_log or "")[:800],
    ]
    return " ".join(str(p).lower() for p in parts if p)


def _keyword_bonus(hypothesis: str, event: Event) -> int:
    hypothesis_words = [w.strip().lower() for w in hypothesis.split() if len(w.strip()) >= 4]
    blob = _event_blob(event)
    score = 0
    for word in hypothesis_words[:12]:
        if word in blob:
            score += 2
    return score


def _event_priority_score(event: Event, hypothesis: str) -> int:
    score = 0

    severity = (event.severity or "").upper()
    if severity == "CRITICAL":
        score += 12
    elif severity == "HIGH":
        score += 8
    elif severity == "MEDIUM":
        score += 4

    if (event.abuse_score or 0) >= 90:
        score += 8
    elif (event.abuse_score or 0) >= 60:
        score += 5
    elif (event.abuse_score or 0) >= 30:
        score += 2

    if event.mitre_technique:
        score += 3
    if event.mitre_tactic:
        score += 2
    if event.relevant_cves:
        score += min(len(event.relevant_cves), 3)
    if event.triage_status == "pending":
        score += 2
    if event.is_false_positive:
        score -= 6

    score += _keyword_bonus(hypothesis, event)
    return score


def _serialize_event(event: Event) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "event_type": event.event_type,
        "severity": event.severity,
        "src_ip": str(event.src_ip) if event.src_ip else None,
        "dst_ip": str(event.dst_ip) if event.dst_ip else None,
        "username": event.username,
        "hostname": event.hostname,
        "process_name": event.process_name,
        "action": event.action,
        "rule_id": event.rule_id,
        "abuse_score": event.abuse_score,
        "relevant_cves": event.relevant_cves or [],
        "mitre_tactic": event.mitre_tactic,
        "mitre_technique": event.mitre_technique,
        "tags": event.tags or [],
        "triage_status": event.triage_status,
        "raw_log": (event.raw_log or "")[:500],
    }


def _fallback_findings(events: list[Event]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for event in events[:5]:
        confidence = 0.45
        if (event.abuse_score or 0) >= 80:
            confidence = 0.78
        elif (event.abuse_score or 0) >= 50:
            confidence = 0.65

        description_parts = [
            event.event_type or "Suspicious event pattern",
            f"severity={event.severity}" if event.severity else None,
            f"src_ip={event.src_ip}" if event.src_ip else None,
            f"hostname={event.hostname}" if event.hostname else None,
            f"mitre={event.mitre_technique}" if event.mitre_technique else None,
        ]

        findings.append(
            {
                "severity": (event.severity or "MEDIUM").upper(),
                "description": " | ".join(part for part in description_parts if part),
                "event_ids": [str(event.id)],
                "confidence": confidence,
            }
        )

    return findings


def _normalize_findings(value: Any, fallback_events: list[Event]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return _fallback_findings(fallback_events)

    normalized: list[dict[str, Any]] = []
    for item in value[:20]:
        if not isinstance(item, dict):
            continue

        severity = str(item.get("severity") or "MEDIUM").upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = "MEDIUM"

        description = str(item.get("description") or "").strip()
        if not description:
            continue

        raw_ids = item.get("event_ids") or []
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]
        event_ids = [str(v) for v in raw_ids if str(v).strip()][:20]

        try:
            confidence = float(item.get("confidence", 0.5))
        except Exception:
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        normalized.append(
            {
                "severity": severity,
                "description": description[:1000],
                "event_ids": event_ids,
                "confidence": confidence,
            }
        )

    if not normalized:
        return _fallback_findings(fallback_events)

    return normalized


def _normalize_techniques(value: Any, fallback_events: list[Event]) -> list[str]:
    techniques: list[str] = []

    if isinstance(value, list):
        for item in value:
            technique = str(item).strip().upper()
            if technique and technique not in techniques:
                techniques.append(technique)

    for event in fallback_events:
        if event.mitre_technique:
            technique = str(event.mitre_technique).strip().upper()
            if technique and technique not in techniques:
                techniques.append(technique)

    return techniques[:50]


async def _emit_progress(hunt_id: str, payload: dict[str, Any]) -> None:
    await ws_manager.broadcast(f"hunt:{hunt_id}", payload)


async def _select_recent_events(
    db: AsyncSession,
    hypothesis: str,
    lookback_hours: int,
) -> tuple[list[Event], list[Event]]:
    cutoff = _utc_now() - timedelta(hours=lookback_hours)

    result = await db.execute(
        select(Event)
        .where(Event.timestamp >= cutoff)
        .order_by(Event.timestamp.desc())
        .limit(MAX_RECENT_EVENTS)
    )
    recent_events = list(result.scalars().all())

    ranked = sorted(
        recent_events,
        key=lambda e: (_event_priority_score(e, hypothesis), e.timestamp or _utc_now()),
        reverse=True,
    )
    candidate_events = ranked[:MAX_AI_EVENTS]

    return recent_events, candidate_events


async def _run_ai_hunt(
    hypothesis: str,
    candidate_events: list[Event],
) -> dict[str, Any]:
    all_cves: list[str] = []
    first_src_ip: str | None = None

    for event in candidate_events:
        for cve_id in event.relevant_cves or []:
            cve_id = str(cve_id).strip().upper()
            if cve_id and cve_id not in all_cves:
                all_cves.append(cve_id)

        if first_src_ip is None and event.src_ip:
            first_src_ip = str(event.src_ip)

    context = await retrieve_context(
        query=hypothesis,
        event_context={
            "src_ip": first_src_ip,
            "relevant_cves": all_cves[:5],
        },
    )

    messages = [
        {
            "role": "system",
            "content": (
                f"{_load_prompt()}\n\n"
                f"--- RETRIEVED CONTEXT ---\n"
                f"{context['formatted_context']}\n"
                f"--- END CONTEXT ---"
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "hypothesis": hypothesis,
                    "candidate_events": [_serialize_event(event) for event in candidate_events],
                },
                ensure_ascii=False,
                default=str,
            ),
        },
    ]

    result = await chat_completion_json(
        messages=messages,
        model=FAST_MODEL,
        temperature=0.2,
        max_tokens=1800,
    )

    return {
        "raw": result,
        "findings": _normalize_findings(result.get("findings"), candidate_events),
        "ai_narrative": str(
            result.get("ai_narrative")
            or "The hunt completed with limited AI narrative output. Review the findings and evidence manually."
        ).strip(),
        "technique_coverage": _normalize_techniques(result.get("technique_coverage"), candidate_events),
        "rag_sources": {
            "semantic_count": len(context.get("semantic_results", [])),
            "ip_intel_count": len(context.get("ip_intel", [])),
            "cve_intel_count": len(context.get("cve_intel", [])),
            "feedback_count": len(context.get("feedback_context", [])),
        },
    }


async def run_hunt(
    hypothesis: str,
    triggered_by: str = "scheduled",
    analyst_id: str | UUID | None = None,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    hunt_id: str | UUID | None = None,
) -> dict[str, Any]:
    hunt_uuid = _safe_uuid(hunt_id) or uuid4()
    analyst_uuid = _safe_uuid(analyst_id)
    started_at = _utc_now()

    transcript: list[dict[str, Any]] = [
        {
            "timestamp": started_at.isoformat(),
            "event": "hunt_started",
            "hypothesis": hypothesis,
            "triggered_by": triggered_by,
        }
    ]

    await _emit_progress(
        str(hunt_uuid),
        {
            "type": "progress",
            "stage": "started",
            "hunt_id": str(hunt_uuid),
            "hypothesis": hypothesis,
            "triggered_by": triggered_by,
            "started_at": started_at.isoformat(),
        },
    )

    async with async_session_factory() as db:
        hunt_row = HuntResult(
            hunt_id=hunt_uuid,
            hypothesis=hypothesis,
            triggered_by=triggered_by,
            analyst_id=analyst_uuid,
            started_at=started_at,
            status="running",
            events_examined=0,
            findings_count=0,
            findings=[],
            ai_narrative=None,
            technique_coverage=[],
            react_transcript=transcript,
        )
        db.add(hunt_row)
        await db.commit()

        try:
            recent_events, candidate_events = await _select_recent_events(db, hypothesis, lookback_hours)

            transcript.append(
                {
                    "timestamp": _utc_now().isoformat(),
                    "event": "events_selected",
                    "events_examined": len(recent_events),
                    "candidate_events": len(candidate_events),
                }
            )
            hunt_row.events_examined = len(recent_events)
            hunt_row.react_transcript = transcript
            await db.commit()

            await _emit_progress(
                str(hunt_uuid),
                {
                    "type": "progress",
                    "stage": "events_selected",
                    "hunt_id": str(hunt_uuid),
                    "events_examined": len(recent_events),
                    "candidate_events": len(candidate_events),
                },
            )

            ai_result = await _run_ai_hunt(hypothesis, candidate_events)

            transcript.append(
                {
                    "timestamp": _utc_now().isoformat(),
                    "event": "ai_analysis_completed",
                    "findings_count": len(ai_result["findings"]),
                    "rag_sources": ai_result["rag_sources"],
                }
            )

            hunt_row.findings = ai_result["findings"]
            hunt_row.findings_count = len(ai_result["findings"])
            hunt_row.ai_narrative = ai_result["ai_narrative"]
            hunt_row.technique_coverage = ai_result["technique_coverage"]
            hunt_row.completed_at = _utc_now()
            hunt_row.status = "completed"
            hunt_row.react_transcript = transcript
            await db.commit()
            await db.refresh(hunt_row)

            await _emit_progress(
                str(hunt_uuid),
                {
                    "type": "complete",
                    "stage": "completed",
                    "hunt_id": str(hunt_uuid),
                    "status": "completed",
                    "findings_count": hunt_row.findings_count,
                    "events_examined": hunt_row.events_examined,
                    "completed_at": hunt_row.completed_at.isoformat() if hunt_row.completed_at else None,
                },
            )

            return hunt_row.to_dict()

        except Exception as exc:
            logger.exception("Hunt %s failed: %s", hunt_uuid, exc)

            transcript.append(
                {
                    "timestamp": _utc_now().isoformat(),
                    "event": "hunt_failed",
                    "error": str(exc),
                }
            )

            hunt_row.status = "failed"
            hunt_row.completed_at = _utc_now()
            hunt_row.ai_narrative = f"Hunt failed: {str(exc)}"
            hunt_row.react_transcript = transcript
            await db.commit()
            await db.refresh(hunt_row)

            await _emit_progress(
                str(hunt_uuid),
                {
                    "type": "error",
                    "stage": "failed",
                    "hunt_id": str(hunt_uuid),
                    "status": "failed",
                    "error": str(exc),
                },
            )

            return hunt_row.to_dict()


async def run_scheduled_hunt(hypothesis: str | None = None) -> dict[str, Any]:
    return await run_hunt(
        hypothesis=hypothesis or "Detect lateral movement patterns",
        triggered_by="scheduled",
        analyst_id=None,
        lookback_hours=DEFAULT_LOOKBACK_HOURS,
    )


async def run_analyst_triggered_hunt(
    hunt_id: str,
    analyst_id: str,
    hypothesis: str,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
) -> dict[str, Any]:
    return await run_hunt(
        hypothesis=hypothesis,
        triggered_by="analyst",
        analyst_id=analyst_id,
        lookback_hours=lookback_hours,
        hunt_id=hunt_id,
    )