"""CEF (ArcSight Common Event Format) parser.
Severity mapping: 0-3=LOW, 4-6=MEDIUM, 7-8=HIGH, 9-10=CRITICAL
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from services.ingestion.normalizer import CommonEvent

_SEV_MAP = {
    0: "LOW", 1: "LOW", 2: "LOW", 3: "LOW",
    4: "MEDIUM", 5: "MEDIUM", 6: "MEDIUM",
    7: "HIGH", 8: "HIGH",
    9: "CRITICAL", 10: "CRITICAL",
}

_ACTION_MAP = {
    "blocked": "block", "block": "block",
    "allowed": "allow", "allow": "allow",
    "denied": "deny", "deny": "deny",
    "alert": "alert", "drop": "drop",
}

def parse(raw_log: str) -> CommonEvent:
    """Parse ArcSight CEF format log into CommonEvent."""
    try:
        # CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extensions
        cef_pattern = re.compile(
            r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)",
            re.DOTALL,
        )
        m = cef_pattern.match(raw_log.strip())
        if not m:
            return _fallback(raw_log)

        (version, vendor, product, dev_version,
         sig_id, name, sev_str, extensions) = m.groups()

        severity_num = int(sev_str) if sev_str.isdigit() else 5
        severity_num = max(0, min(10, severity_num))
        severity = _SEV_MAP.get(severity_num, "MEDIUM")

        # Parse key=value extensions
        ext = _parse_extensions(extensions)

        # Timestamp: prefer rt (receipt time) or deviceReceiptTime
        timestamp = _parse_cef_time(ext.get("rt") or ext.get("deviceReceiptTime") or ext.get("start"))

        # Source identifier: deviceAddress or dhost
        source_id = ext.get("deviceAddress") or ext.get("dhost") or vendor or "unknown"

        # Event type from name field
        event_type = _normalise_event_type(name)

        # IPs
        src_ip = ext.get("src") or ext.get("sourceAddress")
        dst_ip = ext.get("dst") or ext.get("destinationAddress")

        # Ports
        src_port = _safe_int(ext.get("spt") or ext.get("sourcePort"))
        dst_port = _safe_int(ext.get("dpt") or ext.get("destinationPort"))

        # Identity
        username = ext.get("suser") or ext.get("duser")
        hostname = ext.get("dhost") or ext.get("deviceHostName")
        process_name = ext.get("app")

        # Action
        raw_action = (ext.get("act") or "").lower()
        action = _ACTION_MAP.get(raw_action, raw_action or None)

        # Rule ID (cs1 is typically rule name)
        rule_id = ext.get("cs1") or ext.get("deviceExternalId") or sig_id or None

        return CommonEvent(
            timestamp=timestamp,
            source_format="cef",
            source_identifier=source_id,
            event_type=event_type,
            severity=severity,
            raw_log=raw_log,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=ext.get("proto"),
            username=username,
            hostname=hostname,
            process_name=process_name,
            action=action,
            rule_id=rule_id,
        )
    except Exception as exc:
        return _fallback(raw_log, str(exc))


def _parse_extensions(ext_str: str) -> dict:
    """Parse CEF extension key=value pairs (handles spaces in values)."""
    result = {}
    # Regex: key=value where value ends at next key= or end of string
    pattern = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)", re.DOTALL)
    for m in pattern.finditer(ext_str):
        result[m.group(1)] = m.group(2).strip()
    return result


def _parse_cef_time(val: str | None) -> datetime:
    if not val:
        return datetime.now(timezone.utc)
    # Unix epoch in ms
    if val.isdigit() and len(val) == 13:
        return datetime.fromtimestamp(int(val) / 1000, tz=timezone.utc)
    # Unix epoch in s
    if val.isdigit():
        return datetime.fromtimestamp(int(val), tz=timezone.utc)
    for fmt in ("%b %d %Y %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _normalise_event_type(name: str) -> str:
    name_lower = name.lower()
    if any(x in name_lower for x in ["brute", "login fail", "auth fail", "password"]):
        return "auth_failure"
    if any(x in name_lower for x in ["port scan", "scan", "sweep"]):
        return "port_scan"
    if any(x in name_lower for x in ["malware", "virus", "trojan", "ransomware"]):
        return "malware"
    if any(x in name_lower for x in ["lateral", "movement"]):
        return "lateral_movement"
    if any(x in name_lower for x in ["exfil", "data transfer", "upload"]):
        return "exfiltration"
    if any(x in name_lower for x in ["exploit", "vulnerability", "cve"]):
        return "exploitation"
    return name.lower().replace(" ", "_")[:100]


def _safe_int(val) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _fallback(raw_log: str, err: str = "cef_parse_error") -> CommonEvent:
    return CommonEvent(
        timestamp=datetime.now(timezone.utc),
        source_format="cef",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error=err,
    )