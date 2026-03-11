"""CSV log parser — comma-separated values with configurable column mapping."""
from __future__ import annotations
import csv, io
from datetime import datetime, timezone
from services.ingestion.normalizer import CommonEvent

# Common CSV column name variants → CES field
_COL_MAP = {
    "timestamp": "timestamp", "time": "timestamp", "datetime": "timestamp",
    "date": "timestamp", "@timestamp": "timestamp",
    "severity": "severity", "level": "severity", "priority": "severity",
    "src_ip": "src_ip", "source_ip": "src_ip", "srcip": "src_ip",
    "client_ip": "src_ip", "remote_addr": "src_ip",
    "dst_ip": "dst_ip", "dest_ip": "dst_ip", "dstip": "dst_ip",
    "src_port": "src_port", "source_port": "src_port", "sport": "src_port",
    "dst_port": "dst_port", "dest_port": "dst_port", "dport": "dst_port",
    "protocol": "protocol", "proto": "protocol",
    "username": "username", "user": "username", "account": "username",
    "hostname": "hostname", "host": "hostname",
    "process": "process_name", "process_name": "process_name",
    "event_type": "event_type", "type": "event_type", "action": "action",
    "rule_id": "rule_id", "rule": "rule_id",
    "message": "raw_message", "msg": "raw_message",
}

_SEV_WORDS = {
    "critical": "CRITICAL", "crit": "CRITICAL",
    "high": "HIGH", "error": "HIGH",
    "medium": "MEDIUM", "warn": "MEDIUM", "warning": "MEDIUM",
    "low": "LOW", "info": "LOW", "debug": "LOW",
}


def parse(raw_log: str) -> CommonEvent:
    try:
        reader = csv.DictReader(io.StringIO(raw_log.strip()))
        rows = list(reader)

        if not rows:
            # Try headerless — treat first row as data with positional mapping
            return _parse_headerless(raw_log)

        row = rows[0]
        # Normalize column names
        normalized = {_COL_MAP.get(k.strip().lower(), k.strip().lower()): v.strip()
                      for k, v in row.items()}

        timestamp = _parse_ts(normalized.get("timestamp"))
        severity = _SEV_WORDS.get(
            str(normalized.get("severity") or "medium").lower(), "MEDIUM"
        )
        event_type = str(normalized.get("event_type") or
                         normalized.get("action") or "csv_event").lower().replace(" ", "_")
        source_id = str(normalized.get("hostname") or
                        normalized.get("src_ip") or "unknown")

        return CommonEvent(
            timestamp=timestamp,
            source_format="csv",
            source_identifier=source_id,
            event_type=event_type,
            severity=severity,
            raw_log=raw_log,
            src_ip=normalized.get("src_ip") or None,
            dst_ip=normalized.get("dst_ip") or None,
            src_port=_safe_int(normalized.get("src_port")),
            dst_port=_safe_int(normalized.get("dst_port")),
            protocol=normalized.get("protocol") or None,
            username=normalized.get("username") or None,
            hostname=normalized.get("hostname") or None,
            process_name=normalized.get("process_name") or None,
            action=normalized.get("action") or None,
            rule_id=normalized.get("rule_id") or None,
        )
    except Exception as exc:
        return _fallback(raw_log, str(exc))


def _parse_headerless(raw_log: str) -> CommonEvent:
    """Best-effort parse of CSV with no header row."""
    parts = [p.strip() for p in raw_log.split(",")]
    timestamp = _parse_ts(parts[0] if parts else None)
    return CommonEvent(
        timestamp=timestamp,
        source_format="csv",
        source_identifier="unknown",
        event_type="csv_event",
        severity="MEDIUM",
        raw_log=raw_log,
    )


def _parse_ts(val: str | None) -> datetime:
    if not val:
        return datetime.now(timezone.utc)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
        "%d/%b/%Y:%H:%M:%S %z",
    ):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _safe_int(val: str | None) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _fallback(raw_log: str, err: str = "csv_parse_error") -> CommonEvent:
    return CommonEvent(
        timestamp=datetime.now(timezone.utc),
        source_format="csv",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error=err,
    )