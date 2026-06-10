"""
Timeline Analyzer
=================
Collects notable events from all other analyzer outputs and builds a
unified chronological event stream sorted by timestamp.
"""
from ..models.extended_report import TimelineMetrics, TimelineEvent


def build_timeline(perf, sec, proto, arp, ioc, beacons, rst_forensics, start_ts: float) -> TimelineMetrics:
    events = []

    def add(ts, category, severity, detail, src=None, dst=None, pkt_num=None):
        events.append(TimelineEvent(
            timestamp=ts,
            time_offset_sec=round(ts - start_ts, 3) if start_ts else 0.0,
            category=category,
            severity=severity,
            src_ip=src,
            dst_ip=dst,
            detail=detail,
            packet_number=pkt_num,
        ))

    # Performance
    for e in perf.handshake_anomalies:
        if e.timestamp:
            add(e.timestamp, "performance", "warning", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in perf.zero_window_events:
        if e.timestamp:
            add(e.timestamp, "performance", "warning", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in (perf.slow_response_events or []):
        if e.timestamp:
            add(e.timestamp, "performance", "warning", e.detail, e.src_ip, e.dst_ip, e.packet_number)

    # Security
    for e in sec.port_scan_sources:
        if e.timestamp:
            add(e.timestamp, "security", "critical", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in sec.cleartext_credentials:
        if e.timestamp:
            add(e.timestamp, "security", "critical", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in sec.exfiltration_indicators:
        if e.timestamp:
            add(e.timestamp, "security", "critical", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in sec.protocol_port_mismatches:
        if e.timestamp:
            add(e.timestamp, "security", "warning", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in (sec.scanner_signatures or []):
        if e.timestamp:
            add(e.timestamp, "security", "critical", e.detail, e.src_ip, e.dst_ip, e.packet_number)

    # Protocol
    for e in proto.tls_failures:
        if e.timestamp:
            add(e.timestamp, "protocol", "critical", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in proto.dns_errors:
        if e.timestamp:
            add(e.timestamp, "protocol", "warning", e.detail, e.src_ip, e.dst_ip, e.packet_number)
    for e in (proto.icmp_errors or []):
        if e.timestamp:
            add(e.timestamp, "protocol", "warning", e.detail, e.src_ip, e.dst_ip, e.packet_number)

    # ARP
    if arp:
        for c in arp.conflicts:
            add(c.timestamp, "security", "critical",
                f"ARP spoofing: IP {c.ip} seen with MACs {', '.join(c.macs_seen)}",
                pkt_num=c.packet_number)

    # IOC
    if ioc:
        for m in ioc.matches:
            add(start_ts, "security", m.severity, f"IOC match: {m.detail}", dst=m.ip)

    # Beacons
    if beacons:
        for b in beacons.beacons:
            add(start_ts, "beacon", "critical",
                f"C2 beacon: {b.src_ip}→{b.dst_ip}:{b.dst_port} "
                f"({b.connection_count} connections, CV={b.cv})",
                src=b.src_ip, dst=b.dst_ip)

    # RST forensics
    if rst_forensics:
        for r in rst_forensics.classified:
            sev = r.severity
            add(r.rst_timestamp, "rst", sev,
                f"RST: {r.root_cause} — {r.src_ip}:{r.src_port}→{r.dst_ip}:{r.dst_port}",
                src=r.src_ip, dst=r.dst_ip, pkt_num=r.rst_packet_number)

    events.sort(key=lambda e: e.timestamp)
    return TimelineMetrics(events=events, start_time=start_ts)
