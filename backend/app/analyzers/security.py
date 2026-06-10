import re
from collections import defaultdict
from ..models.report import SecurityMetrics, AnomalyEntry

# Thresholds
PORT_SCAN_THRESHOLD = 20            # unique ports within scan window
EXFIL_BYTES_THRESHOLD = 5_000_000  # 5 MB outbound to a single unknown IP
LARGE_DNS_PAYLOAD = 512             # bytes — anomalous DNS packet size

# Protocols that should never appear on these ports
EXPECTED_PROTOCOLS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
}

CLEARTEXT_PATTERNS = [
    (re.compile(rb"(?i)user(?:name)?[=:]\s*([^\r\n&\s]{3,})", re.IGNORECASE), "Username"),
    (re.compile(rb"(?i)pass(?:word)?[=:]\s*([^\r\n&\s]{3,})", re.IGNORECASE), "Password"),
    (re.compile(rb"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE), "Basic Auth"),
    (re.compile(rb"(?i)pwd[=:]\s*([^\r\n&\s]{3,})", re.IGNORECASE), "Password (pwd)"),
]

CLEARTEXT_PORTS = {21, 23, 80}  # FTP, Telnet, HTTP


def analyze_security(packets) -> SecurityMetrics:
    metrics = SecurityMetrics()

    # Port scan: track SYN-only packets per source IP
    syn_targets: dict = defaultdict(set)       # src_ip -> set of dst_ports
    syn_first_seen: dict = {}                   # src_ip -> first timestamp
    flagged_scanners: set = set()

    # Outbound bytes per external IP
    outbound_bytes: dict = defaultdict(int)

    # Protocol/port mismatch: detect SSH-over-443 etc.
    flagged_mismatches: set = set()

    packet_number = 0

    for pkt in packets:
        packet_number += 1
        ts = float(pkt.time)

        ip_layer = pkt["IP"] if pkt.haslayer("IP") else None
        if ip_layer is None:
            continue

        src, dst = ip_layer.src, ip_layer.dst

        # --- Outbound exfiltration heuristic ---
        # Consider traffic going to non-RFC-1918 as outbound
        if not _is_private(dst):
            outbound_bytes[dst] += len(pkt)

        # --- DNS anomaly: oversized DNS packets ---
        if pkt.haslayer("DNS"):
            dns_payload_size = len(bytes(pkt["DNS"]))
            if dns_payload_size > LARGE_DNS_PAYLOAD:
                metrics.exfiltration_indicators.append(AnomalyEntry(
                    src_ip=src, dst_ip=dst,
                    packet_number=packet_number,
                    timestamp=ts,
                    detail=f"Oversized DNS packet ({dns_payload_size} bytes) — possible DNS tunneling",
                    severity="critical"
                ))

        if not pkt.haslayer("TCP"):
            continue

        tcp = pkt["TCP"]
        flags = tcp.flags
        sport, dport = tcp.sport, tcp.dport

        # --- Port scan detection: SYN with no ACK ---
        if flags == 0x002:  # pure SYN
            if src not in syn_first_seen:
                syn_first_seen[src] = ts
            syn_targets[src].add(dport)
            if len(syn_targets[src]) >= PORT_SCAN_THRESHOLD and src not in flagged_scanners:
                flagged_scanners.add(src)
                metrics.port_scan_sources.append(AnomalyEntry(
                    src_ip=src, dst_ip=dst,
                    packet_number=packet_number,
                    timestamp=ts,
                    detail=f"Port scan detected: {len(syn_targets[src])} unique ports targeted",
                    severity="critical"
                ))

        # --- Cleartext credential extraction ---
        if dport in CLEARTEXT_PORTS or sport in CLEARTEXT_PORTS:
            if pkt.haslayer("Raw"):
                payload = bytes(pkt["Raw"])
                for pattern, label in CLEARTEXT_PATTERNS:
                    match = pattern.search(payload)
                    if match:
                        value_preview = match.group(1)[:20].decode("utf-8", errors="replace")
                        metrics.cleartext_credentials.append(AnomalyEntry(
                            src_ip=src, dst_ip=dst,
                            src_port=sport, dst_port=dport,
                            packet_number=packet_number,
                            timestamp=ts,
                            detail=f"{label} transmitted in cleartext (preview: {value_preview!r})",
                            severity="critical"
                        ))

        # --- Protocol/port mismatch ---
        # Detect SSH banner on non-22 ports, or HTTP on 443, etc.
        if pkt.haslayer("Raw"):
            payload = bytes(pkt["Raw"])
            mismatch_key = (src, dst, sport, dport)
            if mismatch_key not in flagged_mismatches:
                # SSH on wrong port
                if payload.startswith(b"SSH-") and dport != 22 and sport != 22:
                    flagged_mismatches.add(mismatch_key)
                    metrics.protocol_port_mismatches.append(AnomalyEntry(
                        src_ip=src, dst_ip=dst,
                        src_port=sport, dst_port=dport,
                        packet_number=packet_number,
                        timestamp=ts,
                        detail=f"SSH traffic on non-standard port {dport} (expected 22) — possible firewall evasion",
                        severity="warning"
                    ))
                # HTTP on 443
                elif (payload.startswith(b"GET ") or payload.startswith(b"POST ")) and dport == 443:
                    flagged_mismatches.add(mismatch_key)
                    metrics.protocol_port_mismatches.append(AnomalyEntry(
                        src_ip=src, dst_ip=dst,
                        src_port=sport, dst_port=dport,
                        packet_number=packet_number,
                        timestamp=ts,
                        detail=f"Plaintext HTTP detected on port 443 (HTTPS port) — possible misconfiguration",
                        severity="warning"
                    ))

    # --- Exfiltration: high-volume outbound to single IP ---
    for dst_ip, total_bytes in outbound_bytes.items():
        if total_bytes >= EXFIL_BYTES_THRESHOLD:
            metrics.exfiltration_indicators.append(AnomalyEntry(
                src_ip="(multiple)", dst_ip=dst_ip,
                detail=f"High outbound volume to {dst_ip}: {total_bytes / 1_000_000:.2f} MB",
                severity="critical"
            ))

    return metrics


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
