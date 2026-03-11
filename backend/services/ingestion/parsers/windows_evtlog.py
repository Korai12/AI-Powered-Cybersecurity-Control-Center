"""Windows Event Log JSON parser.
Severity mapping: Level 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW, 5=LOW
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from services.ingestion.normalizer import CommonEvent

_LEVEL_SEV = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "LOW", 0: "INFO"}

# EventID → (event_type, default_severity_override)
_EVENTID_MAP = {
    4624: ("auth_success", None),
    4625: ("auth_failure", None),
    4634: ("logoff", "LOW"),
    4648: ("explicit_credential_logon", "HIGH"),
    4672: ("privilege_assigned", "MEDIUM"),
    4688: ("process_creation", None),
    4697: ("service_installed", "HIGH"),
    4698: ("scheduled_task_created", "HIGH"),
    4700: ("scheduled_task_enabled", "HIGH"),
    4702: ("scheduled_task_modified", "MEDIUM"),
    4720: ("user_account_created", "HIGH"),
    4726: ("user_account_deleted", "HIGH"),
    4728: ("member_added_to_group", "HIGH"),
    4732: ("member_added_local_group", "HIGH"),
    4756: ("member_added_universal_group", "HIGH"),
    4776: ("credential_validation", None),
    4799: ("local_group_enumeration", "MEDIUM"),
    4946: ("firewall_rule_added", "MEDIUM"),
    5001: ("antivirus_disabled", "CRITICAL"),
    5140: ("network_share_access", "MEDIUM"),
    7045: ("service_installed", "HIGH"),
    1102: ("audit_log_cleared", "CRITICAL"),
    4657: ("registry_modified", "MEDIUM"),
    4663: ("file_access", "LOW"),
    4670: ("permissions_changed", "HIGH"),
    4771: ("kerberos_preauth_failed", "HIGH"),
    4768: ("kerberos_tgt_requested", "LOW"),
    4769: ("kerberos_service_ticket", "LOW"),
}


def parse(raw_log: str) -> CommonEvent:
    try:
        data = json.loads(raw_log)
        event_id = int(data.get("EventID") or data.get("System", {}).get("EventID", 0))

        # Level: from root or System block
        level = int(data.get("Level") or data.get("System", {}).get("Level", 4))
        base_severity = _LEVEL_SEV.get(level, "MEDIUM")

        event_type, sev_override = _EVENTID_MAP.get(event_id, (f"eventid_{event_id}", None))
        severity = sev_override or base_severity

        # Timestamp
        ts_str = (data.get("TimeCreated") or
                  data.get("System", {}).get("TimeCreated", {}).get("@SystemTime") or
                  data.get("timestamp"))
        timestamp = _parse_ts(ts_str)

        # Source identifier: Computer field
        source_id = data.get("Computer") or data.get("System", {}).get("Computer") or "unknown"
        hostname = source_id

        # EventData block
        event_data = data.get("EventData") or data.get("UserData") or {}
        if isinstance(event_data, dict):
            ed = event_data
        else:
            ed = {}

        username = (ed.get("SubjectUserName") or ed.get("TargetUserName") or
                    data.get("username") or ed.get("AccountName"))
        src_ip = ed.get("IpAddress") or ed.get("SourceAddress") or data.get("IpAddress")
        # strip - placeholder IPs
        if src_ip in ("-", "::1", "127.0.0.1"):
            src_ip = None

        src_port = _safe_int(ed.get("SourcePort") or ed.get("IpPort"))
        dst_port = _safe_int(ed.get("DestPort"))

        process_name = (ed.get("Image") or ed.get("ProcessName") or
                        ed.get("NewProcessName") or data.get("ProcessName"))
        rule_id = ed.get("RuleId") or ed.get("FilterRTID") or str(event_id)

        return CommonEvent(
            timestamp=timestamp,
            source_format="windows_evtlog",
            source_identifier=source_id,
            event_type=event_type,
            severity=severity,
            raw_log=raw_log,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            username=_clean_username(username),
            hostname=hostname,
            process_name=process_name,
            rule_id=rule_id,
        )
    except Exception as exc:
        return _fallback(raw_log, str(exc))


def _parse_ts(val) -> datetime:
    if not val:
        return datetime.now(timezone.utc)
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
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


def _clean_username(username: str | None) -> str | None:
    if not username or username in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return None
    return username


def _fallback(raw_log: str, err: str = "windows_evtlog_parse_error") -> CommonEvent:
    return CommonEvent(
        timestamp=datetime.now(timezone.utc),
        source_format="windows_evtlog",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error=err,
    )