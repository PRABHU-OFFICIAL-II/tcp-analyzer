from collections import defaultdict
from ..models.extended_report import FingerprintMetrics, HostFingerprint

TTL_OS_MAP = [
    (255, "Network Device (Cisco/Juniper)"),
    (128, "Windows"),
    (64,  "Linux / macOS"),
    (32,  "Older Windows (9x/NT)"),
]

APP_PORT_MAP = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS/TLS",
    445:  "SMB/Windows File Sharing",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


def _guess_os(ttl: int) -> str:
    best = "Unknown"
    best_diff = 256
    for ref_ttl, name in TTL_OS_MAP:
        diff = abs(ttl - ref_ttl)
        if diff < best_diff:
            best_diff = diff
            best = name
    return best


def analyze_fingerprint(packets) -> FingerprintMetrics:
    host_ttl: dict = {}             # ip -> min observed TTL (first hop closest to source)
    host_apps: dict = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue
        ip = pkt["IP"]
        src = ip.src
        ttl = ip.ttl

        # Keep the TTL from the SYN packet (most reliable for OS guess)
        if pkt.haslayer("TCP") and pkt["TCP"].flags == 0x002:
            host_ttl[src] = ttl
        elif src not in host_ttl:
            host_ttl[src] = ttl

        # App detection by port
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            for port in (tcp.sport, tcp.dport):
                if port in APP_PORT_MAP:
                    host_apps[src].add(APP_PORT_MAP[port])
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            for port in (udp.sport, udp.dport):
                if port in APP_PORT_MAP:
                    host_apps[src].add(APP_PORT_MAP[port])

    hosts = []
    for ip, ttl in host_ttl.items():
        hosts.append(HostFingerprint(
            ip=ip,
            os_guess=_guess_os(ttl),
            ttl_observed=ttl,
            detected_apps=sorted(host_apps.get(ip, [])),
        ))
    hosts.sort(key=lambda h: h.ip)

    return FingerprintMetrics(hosts=hosts)
