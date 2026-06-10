import re
from collections import defaultdict
from ..models.report import ProtocolMetrics, AnomalyEntry
from .. import thresholds

TLS_HANDSHAKE = 22
TLS_ALERT = 21
HTTP_STATUS_RE = re.compile(rb"HTTP/\d\.\d (\d{3})")

# ICMP type codes that indicate network problems
ICMP_PROBLEM_TYPES = {
    3: "Destination Unreachable",
    4: "Source Quench",
    11: "Time Exceeded",
}


def analyze_protocol(packets) -> ProtocolMetrics:
    HIGH_DNS_LATENCY_MS = thresholds.get("protocol", "high_dns_latency_ms")

    metrics = ProtocolMetrics()

    total_connections = 0
    reset_count = 0

    connections: dict = defaultdict(lambda: {"state": "new", "syn_ts": None})
    dns_queries: dict = {}
    tls_client_hello: dict = {}
    flagged_tls: set = set()
    status_counts: dict = defaultdict(int)
    http_200 = 0
    http_total = 0
    packet_number = 0

    for pkt in packets:
        packet_number += 1
        ts = float(pkt.time)

        # ICMP unreachable / time-exceeded
        if pkt.haslayer("ICMP"):
            icmp = pkt["ICMP"]
            ip_layer = pkt["IP"] if pkt.haslayer("IP") else None
            if ip_layer and icmp.type in ICMP_PROBLEM_TYPES:
                metrics.icmp_errors.append(AnomalyEntry(
                    src_ip=ip_layer.src, dst_ip=ip_layer.dst,
                    packet_number=packet_number,
                    timestamp=ts,
                    detail=f"ICMP {ICMP_PROBLEM_TYPES[icmp.type]} (type={icmp.type} code={icmp.code})",
                    severity="warning"
                ))

        # DNS analysis
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            ip = pkt["IP"] if pkt.haslayer("IP") else None
            if ip:
                src, dst = ip.src, ip.dst
                qr = dns.qr
                qid = dns.id
                rcode = dns.rcode if hasattr(dns, "rcode") else 0

                if qr == 0:
                    dns_queries[qid] = (src, dst, ts, packet_number)
                elif qr == 1:
                    if rcode == 3:
                        qname = ""
                        if dns.qd and hasattr(dns.qd, "qname"):
                            try:
                                qname = dns.qd.qname.decode("utf-8", errors="replace")
                            except Exception:
                                qname = "(unknown)"
                        metrics.dns_errors.append(AnomalyEntry(
                            src_ip=src, dst_ip=dst,
                            packet_number=packet_number,
                            timestamp=ts,
                            detail=f"NXDOMAIN for {qname!r}",
                            severity="warning"
                        ))
                    elif rcode == 2:
                        metrics.dns_errors.append(AnomalyEntry(
                            src_ip=src, dst_ip=dst,
                            packet_number=packet_number,
                            timestamp=ts,
                            detail="DNS SERVFAIL — server-side resolution failure",
                            severity="warning"
                        ))

                    if qid in dns_queries:
                        q_src, q_dst, q_ts, q_pkt = dns_queries[qid]
                        latency_ms = (ts - q_ts) * 1000
                        if latency_ms > HIGH_DNS_LATENCY_MS:
                            metrics.dns_errors.append(AnomalyEntry(
                                src_ip=q_src, dst_ip=q_dst,
                                packet_number=packet_number,
                                timestamp=ts,
                                detail=f"Slow DNS resolution: {latency_ms:.0f} ms",
                                severity="warning"
                            ))
                        del dns_queries[qid]

        if not pkt.haslayer("TCP"):
            continue

        ip_layer = pkt["IP"] if pkt.haslayer("IP") else None
        if ip_layer is None:
            continue

        tcp = pkt["TCP"]
        src, dst = ip_layer.src, ip_layer.dst
        sport, dport = tcp.sport, tcp.dport
        flags = tcp.flags
        conn_key = (src, dst, sport, dport)

        if flags == 0x002:
            total_connections += 1
            connections[conn_key]["state"] = "syn"
            connections[conn_key]["syn_ts"] = ts

        if "R" in str(flags):
            reset_count += 1
            metrics.connection_resets.append(AnomalyEntry(
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=packet_number,
                timestamp=ts,
                detail="Connection reset (RST) — possible app crash or firewall kill",
                severity="warning"
            ))

        # TLS handshake failure detection
        if pkt.haslayer("Raw"):
            raw = bytes(pkt["Raw"])

            if len(raw) >= 5:
                content_type = raw[0]
                tls_version = (raw[1], raw[2])
                is_tls_version = tls_version in [(3, 0), (3, 1), (3, 2), (3, 3), (3, 4)]

                if is_tls_version and content_type == TLS_HANDSHAKE:
                    handshake_type = raw[5] if len(raw) > 5 else 0
                    if handshake_type == 1:
                        tls_client_hello[conn_key] = ts
                    elif handshake_type == 2:
                        if conn_key in tls_client_hello:
                            del tls_client_hello[conn_key]

                elif is_tls_version and content_type == TLS_ALERT:
                    rev_key = (dst, src, dport, sport)
                    if rev_key in tls_client_hello and rev_key not in flagged_tls:
                        flagged_tls.add(rev_key)
                        alert_level = raw[5] if len(raw) > 5 else 0
                        alert_desc = raw[6] if len(raw) > 6 else 0
                        metrics.tls_failures.append(AnomalyEntry(
                            src_ip=src, dst_ip=dst,
                            src_port=sport, dst_port=dport,
                            packet_number=packet_number,
                            timestamp=ts,
                            detail=f"TLS Alert (level={alert_level}, desc={alert_desc}) — handshake failure",
                            severity="critical"
                        ))
                        del tls_client_hello[rev_key]

            # HTTP status parsing
            if sport in (80, 8080, 8443, 3000, 5000) or dport in (80, 8080, 3000, 5000):
                for match in HTTP_STATUS_RE.finditer(raw):
                    code = match.group(1).decode("ascii", errors="replace")
                    status_counts[code] += 1
                    http_total += 1
                    if code.startswith("2"):
                        http_200 += 1

    metrics.total_connections = total_connections
    if total_connections > 0:
        metrics.reset_rate_pct = round(reset_count / total_connections * 100, 2)

    metrics.http_status_counts = dict(status_counts)
    error_total = sum(v for k, v in status_counts.items() if k.startswith("4") or k.startswith("5"))
    if http_total > 0:
        metrics.http_error_rate_pct = round(error_total / http_total * 100, 2)

    return metrics
