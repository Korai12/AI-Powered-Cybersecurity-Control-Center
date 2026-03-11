"""Generic JSON parser — for structured events with a timestamp field."""
from __future__ import annotations
import json, re
from datetime import datetime, timezone
from services.ingestion.normalizer import CommonEvent

_SEV_WORDS = {
    "critical": "CRITICAL", "crit": "CRITICAL",
    "high": "HIGH", "error": "HIGH", "err": "HIGH",
    "medium": "MEDIUM", "warn": "MEDIUM", "warning": "MEDIUM",
    "low": "LOW", "info": "LOW", "information": "LOW", "debug": "LOW",
}


def parse(raw_log: str) -> CommonEvent:
    try:
        data = json.loads(raw_log)

        # Timestamp — try common field names
        ts_val = (data.get("timestamp") or data.get("time") or data.get("@timestamp") or
                  data.get("datetime") or data.get("created_at") or data.get("date"))
        timestamp = _parse_ts(ts_val)

        # Severity
        sev_raw = str(data.get("severity") or data.get("level") or data.get("priority") or
                      data.get("log_level") or "medium").lower()
        severity = _SEV_WORDS.get(sev_raw, "MEDIUM")

        # Source identifier
        source_id = (data.get("source") or data.get("host") or data.get("hostname") or
                     data.get("device") or data.get("source_identifier") or "unknown")

        # Event type
        event_type = (data.get("event_type") or data.get("type") or data.get("action") or
                      data.get("category") or data.get("name") or "generic_event")
        event_type = str(event_type).lower().replace(" ", "_")[:100]

        return CommonEvent(
            timestamp=timestamp,
            source_format="generic_json",
            source_identifier=str(source_id),
            event_type=event_type,
            severity=severity,
            raw_log=raw_log,
            src_ip=data.get("src_ip") or data.get("source_ip") or data.get("client_ip"),
            dst_ip=data.get("dst_ip") or data.get("dest_ip") or data.get("destination_ip"),
            src_port=_safe_int(data.get("src_port") or data.get("source_port")),
            dst_port=_safe_int(data.get("dst_port") or data.get("dest_port")),
            protocol=data.get("protocol") or data.get("proto"),
            username=data.get("username") or data.get("user") or data.get("account"),
            hostname=data.get("hostname") or data.get("host"),
            process_name=data.get("process") or data.get("process_name") or data.get("app"),
            file_hash=data.get("hash") or data.get("sha256") or data.get("md5"),
            action=data.get("action") or data.get("outcome"),
            rule_id=str(data.get("rule_id") or data.get("rule") or data.get("sig_id") or ""),
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            tags=data.get("tags") or [],
        )
    except Exception as exc:
        return _fallback(raw_log, str(exc))


def _parse_ts(val) -> datetime:
    if not val:
        return datetime.now(timezone.utc)
    if isinstance(val, (int, float)):
        # Epoch seconds or ms
        if val > 1e12:
            val = val / 1000
        return datetime.fromtimestamp(val, tz=timezone.utc)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            return datetime.strptime(str(val), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _safe_int(val) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _fallback(raw_log: str, err: str = "generic_json_parse_error") -> CommonEvent:
    return CommonEvent(
        timestamp=datetime.now(timezone.utc),
        source_format="generic_json",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error=err,
    )