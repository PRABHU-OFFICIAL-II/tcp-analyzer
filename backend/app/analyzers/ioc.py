import os
import json
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from ..models.extended_report import IOCMetrics, IOCMatch

BLOCKLIST_PATH = Path(__file__).parent.parent.parent / "data" / "blocklist.txt"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT = 3


def _load_blocklist() -> set:
    if not BLOCKLIST_PATH.exists():
        return set()
    blocked = set()
    for line in BLOCKLIST_PATH.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            blocked.add(line)
    return blocked


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )


def _check_abuseipdb(ip: str, api_key: str):
    try:
        url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90"
        req = Request(url, headers={"Key": api_key, "Accept": "application/json"})
        with urlopen(req, timeout=ABUSEIPDB_TIMEOUT) as resp:
            data = json.loads(resp.read())
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        if score >= 50:
            return score
    except (URLError, Exception):
        pass
    return None


def analyze_ioc(packets) -> IOCMetrics:
    metrics = IOCMetrics()
    blocklist = _load_blocklist()
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    external_ips: set = set()
    for pkt in packets:
        if pkt.haslayer("IP"):
            for ip in (pkt["IP"].src, pkt["IP"].dst):
                if not _is_private(ip):
                    external_ips.add(ip)

    for ip in external_ips:
        if ip in blocklist:
            metrics.matches.append(IOCMatch(
                ip=ip,
                source="blocklist",
                detail=f"IP {ip} found in local blocklist",
                severity="critical",
            ))
        elif api_key:
            score = _check_abuseipdb(ip, api_key)
            if score is not None:
                metrics.matches.append(IOCMatch(
                    ip=ip,
                    source="abuseipdb",
                    detail=f"AbuseIPDB confidence score: {score}%",
                    severity="critical" if score >= 90 else "warning",
                ))

    return metrics
