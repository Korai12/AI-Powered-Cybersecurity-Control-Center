# Stub — implemented in its respective phase
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session_factory
from models.asset import Asset
from models.entity_graph import EntityGraph
from models.event import Event
from models.feedback import AnalystFeedback
from services.ai.correlation import _call_llm_for_cluster
from services.ai.openai_helper import FAST_MODEL, chat_completion_json
from services.ai.rag import retrieve_context
from services.intel.abuseipdb import lookup_abuseipdb
from services.intel.nvd_cve import extract_cve_ids, lookup_cve
from websocket.manager import manager as ws_manager

logger = logging.getLogger("accc.react_agent")

MAX_ITERATIONS = 10
TIMEOUT_SECONDS = 120


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, default=str)
        return value
    except Exception:
        return str(value)


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


async def _emit(run_id: str, payload: dict[str, Any]) -> None:
    await ws_manager.broadcast(f"agent:{run_id}", payload)


async def _tool_query_events(db: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    limit = max(1, min(int(payload.get("limit", 20)), 50))

    stmt = select(Event).order_by(Event.timestamp.desc()).limit(limit)

    if payload.get("severity"):
        stmt = stmt.where(Event.severity == str(payload["severity"]).upper())
    if payload.get("hostname"):
        stmt = stmt.where(Event.hostname == str(payload["hostname"]))
    if payload.get("username"):
        stmt = stmt.where(Event.username == str(payload["username"]))
    if payload.get("src_ip"):
        stmt = stmt.where(Event.src_ip == str(payload["src_ip"]))
    if payload.get("dst_ip"):
        stmt = stmt.where(Event.dst_ip == str(payload["dst_ip"]))
    if payload.get("event_type"):
        stmt = stmt.where(Event.event_type == str(payload["event_type"]))
    if payload.get("rule_id"):
        stmt = stmt.where(Event.rule_id == str(payload["rule_id"]))

    result = await db.execute(stmt)
    events = list(result.scalars().all())

    return {
        "count": len(events),
        "events": [_serialize_event(event) for event in events],
    }


async def _tool_get_ip_reputation(_: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    ip = str(payload.get("ip") or "").strip()
    if not ip:
        return {"error": "ip is required"}
    try:
        result = await lookup_abuseipdb(ip)
        return result or {"ip": ip, "result": None}
    except Exception as exc:
        return {"error": str(exc), "ip": ip}


async def _tool_lookup_cve(_: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(payload.get("cve_id") or "").strip().upper()
    if not cve_id:
        return {"error": "cve_id is required"}
    try:
        result = await lookup_cve(cve_id)
        return result or {"cve_id": cve_id, "result": None}
    except Exception as exc:
        return {"error": str(exc), "cve_id": cve_id}


async def _tool_correlate_events(db: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    raw_ids = payload.get("event_ids") or []
    if not isinstance(raw_ids, list) or not raw_ids:
        return {"error": "event_ids must be a non-empty list"}

    event_ids: list[UUID] = []
    for item in raw_ids:
        try:
            event_ids.append(UUID(str(item)))
        except Exception:
            continue

    if not event_ids:
        return {"error": "No valid UUID event_ids supplied"}

    result = await db.execute(
        select(Event)
        .where(Event.id.in_(event_ids))
        .order_by(Event.timestamp.asc())
    )
    events = list(result.scalars().all())

    if not events:
        return {"count": 0, "events": [], "correlation": None}

    correlation = await _call_llm_for_cluster(events)

    return {
        "count": len(events),
        "events": [_serialize_event(event) for event in events],
        "correlation": correlation,
    }


async def _tool_search_threat_intel(_: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    query = str(payload.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}

    try:
        context = await retrieve_context(query=query, event_context={})
        return {
            "semantic_results": context.get("semantic_results", []),
            "formatted_context": context.get("formatted_context", ""),
        }
    except Exception as exc:
        return {"error": str(exc), "query": query}


async def _tool_get_asset_info(db: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    needle = str(payload.get("hostname_or_ip") or "").strip()
    if not needle:
        return {"error": "hostname_or_ip is required"}

    result = await db.execute(
        select(Asset)
        .where(
            or_(
                Asset.hostname == needle,
                Asset.ip_address == needle,
            )
        )
        .limit(1)
    )
    asset = result.scalars().first()

    if asset is None:
        return {"found": False, "query": needle}

    return {
        "found": True,
        "hostname": asset.hostname,
        "ip_address": str(asset.ip_address) if asset.ip_address else None,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "tags": asset.tags or [],
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


async def _tool_get_live_ip_reputation(_: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    ip = str(payload.get("ip") or "").strip()
    if not ip:
        return {"error": "ip is required"}

    # Repo-compatible implementation: currently uses the same lookup helper.
    try:
        result = await lookup_abuseipdb(ip)
        return result or {"ip": ip, "result": None}
    except Exception as exc:
        return {"error": str(exc), "ip": ip}


async def _tool_get_live_cve(_: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    value = str(payload.get("cve_id_or_product") or "").strip()
    if not value:
        return {"error": "cve_id_or_product is required"}

    try:
        cve_ids = extract_cve_ids(value)
        if cve_ids:
            result = await lookup_cve(cve_ids[0])
            return result or {"cve_id": cve_ids[0], "result": None}

        return {
            "warning": "No explicit CVE ID found in input; repository currently exposes CVE lookup by CVE ID.",
            "query": value,
        }
    except Exception as exc:
        return {"error": str(exc), "query": value}


async def _tool_get_analyst_feedback(db: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    pattern = str(payload.get("pattern") or "").strip()
    if not pattern:
        return {"error": "pattern is required"}

    result = await db.execute(
        select(AnalystFeedback)
        .where(
            or_(
                AnalystFeedback.notes.ilike(f"%{pattern}%"),
                AnalystFeedback.ai_verdict.ilike(f"%{pattern}%"),
                AnalystFeedback.analyst_verdict.ilike(f"%{pattern}%"),
            )
        )
        .order_by(AnalystFeedback.created_at.desc())
        .limit(10)
    )
    rows = list(result.scalars().all())

    return {
        "count": len(rows),
        "items": [
            {
                "id": str(row.id),
                "analyst_id": str(row.analyst_id) if row.analyst_id else None,
                "event_id": str(row.event_id) if row.event_id else None,
                "incident_id": str(row.incident_id) if row.incident_id else None,
                "ai_verdict": row.ai_verdict,
                "analyst_verdict": row.analyst_verdict,
                "notes": row.notes,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
    }


async def _tool_build_entity_graph(db: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    entity = str(payload.get("entity") or "").strip()
    if not entity:
        return {"error": "entity is required"}

    result = await db.execute(
        select(EntityGraph)
        .where(
            or_(
                EntityGraph.source_entity_value == entity,
                EntityGraph.target_entity_value == entity,
            )
        )
        .limit(50)
    )
    rows = list(result.scalars().all())

    return {
        "count": len(rows),
        "relationships": [
            {
                "id": str(row.id),
                "source_entity_type": row.source_entity_type,
                "source_entity_value": row.source_entity_value,
                "relationship_type": row.relationship_type,
                "target_entity_type": row.target_entity_type,
                "target_entity_value": row.target_entity_value,
                "interaction_count": row.interaction_count,
                "risk_score": row.risk_score,
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            for row in rows
        ],
    }


TOOLS: dict[str, Callable[[AsyncSession, dict[str, Any]], Awaitable[dict[str, Any]]]] = {
    "query_events": _tool_query_events,
    "get_ip_reputation": _tool_get_ip_reputation,
    "lookup_cve": _tool_lookup_cve,
    "correlate_events": _tool_correlate_events,
    "search_threat_intel": _tool_search_threat_intel,
    "get_asset_info": _tool_get_asset_info,
    "get_live_ip_reputation": _tool_get_live_ip_reputation,
    "get_live_cve": _tool_get_live_cve,
    "get_analyst_feedback": _tool_get_analyst_feedback,
    "build_entity_graph": _tool_build_entity_graph,
}


def _tools_schema() -> list[dict[str, Any]]:
    return [
        {"name": "query_events", "description": "Query the events table with filters like severity, hostname, username, src_ip, dst_ip, event_type, rule_id, limit."},
        {"name": "get_ip_reputation", "description": "Check IP reputation and abuse score for an IP."},
        {"name": "lookup_cve", "description": "Look up CVE details from NVD. Input: {cve_id}."},
        {"name": "correlate_events", "description": "Correlate a group of event IDs and summarize the pattern. Input: {event_ids:[...]}."},
        {"name": "search_threat_intel", "description": "Search semantic threat intelligence and MITRE knowledge. Input: {query}."},
        {"name": "get_asset_info", "description": "Look up asset inventory information for a hostname or IP. Input: {hostname_or_ip}."},
        {"name": "get_live_ip_reputation", "description": "Live-oriented IP reputation lookup tool. Input: {ip}."},
        {"name": "get_live_cve", "description": "Live-oriented CVE lookup tool. Input: {cve_id_or_product}."},
        {"name": "get_analyst_feedback", "description": "Look up historical analyst feedback about a similar pattern. Input: {pattern}."},
        {"name": "build_entity_graph", "description": "Map entity relationships for an IP, hostname, or username. Input: {entity}."},
    ]


def _system_prompt() -> str:
    return f"""
You are ACCC's Agentic ReAct Investigation Engine.

Investigate the analyst question step by step using the available tools.
You may only use the listed tools.
Maximum investigation steps: {MAX_ITERATIONS}.
At the final step, provide your best evidence-based conclusion.
Return ONLY JSON.

If you want to call a tool, respond with:
{{
  "type": "tool_call",
  "thought": "why you are taking this step",
  "tool_name": "query_events",
  "tool_input": {{"limit": 10}}
}}

If you are ready to conclude, respond with:
{{
  "type": "final",
  "thought": "why you are concluding",
  "summary": "clear analyst-facing summary",
  "confidence": 0.0,
  "evidence": ["fact 1", "fact 2"],
  "recommended_actions": ["action 1", "action 2"]
}}

Available tools:
{json.dumps(_tools_schema(), ensure_ascii=False)}
""".strip()


async def _llm_step(messages: list[dict[str, str]]) -> dict[str, Any]:
    result = await chat_completion_json(
        messages=messages,
        model=FAST_MODEL,
        temperature=0.2,
        max_tokens=1200,
    )

    if not isinstance(result, dict):
        return {
            "type": "final",
            "thought": "Model response was invalid, so I am concluding conservatively.",
            "summary": "Investigation ended with an invalid model response.",
            "confidence": 0.2,
            "evidence": ["Model response format was invalid."],
            "recommended_actions": ["Review related events manually."],
        }

    return result


async def run_react_investigation(
    run_id: str,
    analyst_query: str,
    incident_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident_context = incident_context or {}
    started_at = _utc_now()
    deadline = time.monotonic() + TIMEOUT_SECONDS

    transcript: list[dict[str, Any]] = []
    gathered_evidence: list[str] = []

    await _emit(
        run_id,
        {
            "type": "connected",
            "run_id": run_id,
            "status": "running",
            "started_at": started_at.isoformat(),
        },
    )

    messages: list[dict[str, str]] = [
        {"role": "system", "content": _system_prompt()},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "analyst_query": analyst_query,
                    "incident_context": incident_context,
                },
                ensure_ascii=False,
                default=str,
            ),
        },
    ]

    try:
        async with async_session_factory() as db:
            for iteration in range(1, MAX_ITERATIONS + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result = {
                        "run_id": run_id,
                        "status": "timed_out",
                        "summary": "Investigation timed out — partial results below.",
                        "confidence": 0.35,
                        "evidence": gathered_evidence[:20],
                        "recommended_actions": ["Review the transcript and continue manually if needed."],
                        "transcript": transcript,
                        "started_at": started_at.isoformat(),
                        "completed_at": _utc_now().isoformat(),
                    }
                    await _emit(
                        run_id,
                        {"type": "complete", "run_id": run_id, "status": "timed_out", "result": result},
                    )
                    return result

                if iteration == MAX_ITERATIONS:
                    messages.append(
                        {
                            "role": "system",
                            "content": "You have reached the maximum investigation steps. Provide your best conclusion based on evidence gathered so far.",
                        }
                    )

                decision = await asyncio.wait_for(
                    _llm_step(messages),
                    timeout=max(1, int(remaining)),
                )

                thought = str(decision.get("thought") or "").strip()
                if thought:
                    thought_entry = {
                        "timestamp": _utc_now().isoformat(),
                        "iteration": iteration,
                        "type": "thought",
                        "content": thought,
                    }
                    transcript.append(thought_entry)
                    await _emit(run_id, {"type": "thought", "run_id": run_id, **thought_entry})

                if decision.get("type") == "final":
                    status = "completed" if iteration < MAX_ITERATIONS else "max_iterations_reached"
                    result = {
                        "run_id": run_id,
                        "status": status,
                        "summary": str(decision.get("summary") or "Investigation complete.").strip(),
                        "confidence": float(decision.get("confidence", 0.5)),
                        "evidence": [str(x) for x in decision.get("evidence", [])][:20],
                        "recommended_actions": [str(x) for x in decision.get("recommended_actions", [])][:20],
                        "transcript": transcript,
                        "started_at": started_at.isoformat(),
                        "completed_at": _utc_now().isoformat(),
                    }
                    await _emit(
                        run_id,
                        {"type": "complete", "run_id": run_id, "status": status, "result": result},
                    )
                    return result

                tool_name = str(decision.get("tool_name") or "").strip()
                tool_input = decision.get("tool_input") or {}

                action_entry = {
                    "timestamp": _utc_now().isoformat(),
                    "iteration": iteration,
                    "type": "action",
                    "tool_name": tool_name,
                    "tool_input": _json_safe(tool_input),
                }
                transcript.append(action_entry)
                await _emit(run_id, {"type": "action", "run_id": run_id, **action_entry})

                if tool_name not in TOOLS:
                    observation = {"error": f"Unknown tool: {tool_name}"}
                else:
                    try:
                        observation = await TOOLS[tool_name](db, tool_input)
                    except Exception as exc:
                        logger.exception("Tool %s failed: %s", tool_name, exc)
                        observation = {"error": str(exc), "tool_name": tool_name}

                observation_entry = {
                    "timestamp": _utc_now().isoformat(),
                    "iteration": iteration,
                    "type": "observation",
                    "tool_name": tool_name,
                    "content": _json_safe(observation),
                }
                transcript.append(observation_entry)
                await _emit(run_id, {"type": "observation", "run_id": run_id, **observation_entry})

                gathered_evidence.append(
                    f"Step {iteration} using {tool_name}: {json.dumps(_json_safe(observation), default=str)[:500]}"
                )

                messages.append(
                    {
                        "role": "assistant",
                        "content": json.dumps(decision, ensure_ascii=False, default=str),
                    }
                )
                messages.append(
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "tool_result": {
                                    "tool_name": tool_name,
                                    "result": _json_safe(observation),
                                }
                            },
                            ensure_ascii=False,
                            default=str,
                        ),
                    }
                )

            result = {
                "run_id": run_id,
                "status": "max_iterations_reached",
                "summary": "Maximum investigation steps reached. Partial conclusion returned.",
                "confidence": 0.4,
                "evidence": gathered_evidence[:20],
                "recommended_actions": ["Review transcript and continue with manual investigation."],
                "transcript": transcript,
                "started_at": started_at.isoformat(),
                "completed_at": _utc_now().isoformat(),
            }
            await _emit(
                run_id,
                {"type": "complete", "run_id": run_id, "status": "max_iterations_reached", "result": result},
            )
            return result

    except asyncio.TimeoutError:
        result = {
            "run_id": run_id,
            "status": "timed_out",
            "summary": "Investigation timed out — partial results below.",
            "confidence": 0.35,
            "evidence": gathered_evidence[:20],
            "recommended_actions": ["Review transcript and continue manually if needed."],
            "transcript": transcript,
            "started_at": started_at.isoformat(),
            "completed_at": _utc_now().isoformat(),
        }
        await _emit(
            run_id,
            {"type": "complete", "run_id": run_id, "status": "timed_out", "result": result},
        )
        return result

    except Exception as exc:
        logger.exception("ReAct investigation %s failed: %s", run_id, exc)
        result = {
            "run_id": run_id,
            "status": "failed",
            "summary": f"Investigation failed: {str(exc)}",
            "confidence": 0.0,
            "evidence": gathered_evidence[:20],
            "recommended_actions": ["Check backend logs and retry the investigation."],
            "transcript": transcript,
            "started_at": started_at.isoformat(),
            "completed_at": _utc_now().isoformat(),
        }
        await _emit(
            run_id,
            {"type": "complete", "run_id": run_id, "status": "failed", "result": result},
        )
        return result