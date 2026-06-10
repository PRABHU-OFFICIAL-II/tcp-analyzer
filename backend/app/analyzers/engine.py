import uuid
from scapy.all import PcapReader
from ..models.report import AnalysisReport, SummaryDiagnosis
from .performance import analyze_performance
from .security import analyze_security
from .protocol import analyze_protocol
from .flow import analyze_flow
from .fingerprint import analyze_fingerprint
from .tls_deep import analyze_tls_deep
from .arp import analyze_arp
from .ioc import analyze_ioc
from .geo import analyze_geo
from .beacon import analyze_beacon
from .rst_forensics import analyze_rst_forensics
from .timeline import build_timeline
from .http_objects import analyze_http_objects
from .dns_map import analyze_dns_map
from .. import db, thresholds


def _load_packets(filepath: str) -> list:
    """Stream-read PCAP respecting the configured packet limit."""
    max_pkts = thresholds.get("engine", "max_packets") or 500_000
    packets = []
    with PcapReader(filepath) as reader:
        for pkt in reader:
            packets.append(pkt)
            if len(packets) >= max_pkts:
                break
    return packets


def run_analysis(filepath: str, filename: str, save: bool = True) -> AnalysisReport:
    packets = _load_packets(filepath)

    if len(packets) == 0:
        raise ValueError("PCAP file contains no packets.")

    timestamps = [float(p.time) for p in packets]
    start_ts = min(timestamps)
    end_ts   = max(timestamps)
    duration = end_ts - start_ts

    unique_ips: set = set()
    for pkt in packets:
        if pkt.haslayer("IP"):
            unique_ips.add(pkt["IP"].src)
            unique_ips.add(pkt["IP"].dst)

    perf          = analyze_performance(packets)
    sec           = analyze_security(packets)
    proto         = analyze_protocol(packets)
    flow          = analyze_flow(packets)
    fingerprint   = analyze_fingerprint(packets)
    tls_deep      = analyze_tls_deep(packets)
    arp           = analyze_arp(packets)
    ioc           = analyze_ioc(packets)
    geo           = analyze_geo(packets)
    beacons       = analyze_beacon(packets)
    rst_forensics = analyze_rst_forensics(packets)
    http_objects  = analyze_http_objects(packets)
    dns_map       = analyze_dns_map(packets)
    timeline      = build_timeline(perf, sec, proto, arp, ioc, beacons, rst_forensics, start_ts)

    diagnoses = _build_diagnoses(perf, sec, proto, arp, ioc, beacons, tls_deep, rst_forensics)

    report = AnalysisReport(
        analysis_id=uuid.uuid4().hex,
        filename=filename,
        total_packets=len(packets),
        capture_duration_sec=round(duration, 3),
        start_time=start_ts,
        unique_ips=sorted(unique_ips),
        diagnoses=diagnoses,
        performance=perf,
        security=sec,
        protocol=proto,
        flow=flow,
        fingerprint=fingerprint,
        tls_deep=tls_deep,
        arp=arp,
        ioc=ioc,
        geo=geo,
        beacons=beacons,
        rst_forensics=rst_forensics,
        timeline=timeline,
        http_objects=http_objects,
        dns_map=dns_map,
    )

    if save:
        db.save_report(report.model_dump())

    return report


def _build_diagnoses(perf, sec, proto, arp, ioc, beacons, tls_deep, rst_forensics):
    diagnoses = []

    if perf.zero_window_count > 0:
        diagnoses.append(SummaryDiagnosis(
            headline="Server-side resource exhaustion detected (TCP Zero Window)",
            severity="warning",
            details=[
                f"{perf.zero_window_count} Zero Window events found.",
                "The receiving host's buffer is full — indicates CPU or memory pressure.",
            ]
        ))

    if perf.retransmission_rate_pct > thresholds.get("performance", "retransmission_rate_warning"):
        diagnoses.append(SummaryDiagnosis(
            headline=f"High packet loss detected ({perf.retransmission_rate_pct}% retransmission rate)",
            severity="critical",
            details=[
                f"{perf.retransmission_count} retransmitted packets.",
                "Check network cables, switch ports, and NIC drivers.",
            ]
        ))
    elif perf.retransmission_count > 0:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Minor retransmissions ({perf.retransmission_rate_pct}% rate)",
            severity="info",
            details=[f"{perf.retransmission_count} retransmitted packets — within normal range."]
        ))

    if perf.max_handshake_ms and perf.max_handshake_ms > thresholds.get("performance", "high_handshake_ms"):
        diagnoses.append(SummaryDiagnosis(
            headline=f"High network latency (max handshake: {perf.max_handshake_ms} ms)",
            severity="warning",
            details=[f"Avg: {perf.avg_handshake_ms} ms, P95: {perf.p95_handshake_ms} ms, Max: {perf.max_handshake_ms} ms."]
        ))

    if perf.max_delta_ms and perf.max_delta_ms > thresholds.get("performance", "high_delta_ms"):
        diagnoses.append(SummaryDiagnosis(
            headline=f"Slow application response time (max: {perf.max_delta_ms} ms)",
            severity="warning",
            details=[f"Avg: {perf.avg_delta_ms} ms, P95: {perf.p95_delta_ms} ms, Max: {perf.max_delta_ms} ms."]
        ))

    if sec.cleartext_credentials:
        diagnoses.append(SummaryDiagnosis(
            headline=f"CRITICAL: Credentials in cleartext ({len(sec.cleartext_credentials)} instance(s))",
            severity="critical",
            details=["Enforce TLS/HTTPS. Disable plaintext protocols (HTTP, FTP, Telnet)."]
        ))

    if sec.port_scan_sources:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Port scanning from {len(sec.port_scan_sources)} source(s)",
            severity="critical",
            details=[f"Source(s): {', '.join(e.src_ip for e in sec.port_scan_sources)}"]
        ))

    if sec.scanner_signatures:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Scanner tool signatures detected ({len(sec.scanner_signatures)} instance(s))",
            severity="critical",
            details=[e.detail for e in sec.scanner_signatures[:5]]
        ))

    if sec.exfiltration_indicators:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Potential data exfiltration ({len(sec.exfiltration_indicators)} indicator(s))",
            severity="critical",
            details=[e.detail for e in sec.exfiltration_indicators]
        ))

    if sec.protocol_port_mismatches:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Protocol/port mismatches ({len(sec.protocol_port_mismatches)} instance(s))",
            severity="warning",
            details=[e.detail for e in sec.protocol_port_mismatches]
        ))

    if arp.conflicts:
        diagnoses.append(SummaryDiagnosis(
            headline=f"ARP spoofing detected ({len(arp.conflicts)} IP conflict(s))",
            severity="critical",
            details=[f"IP {c.ip} seen with MACs: {', '.join(c.macs_seen)}" for c in arp.conflicts]
        ))

    if ioc.matches:
        diagnoses.append(SummaryDiagnosis(
            headline=f"IOC matches: {len(ioc.matches)} malicious IP(s) detected",
            severity="critical",
            details=[m.detail for m in ioc.matches]
        ))

    if beacons.beacons:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Beaconing / C2 activity detected ({len(beacons.beacons)} flow(s))",
            severity="critical",
            details=[
                f"{b.src_ip} → {b.dst_ip}:{b.dst_port} — {b.connection_count} connections, "
                f"avg interval {b.avg_interval_sec}s, CV={b.cv}"
                for b in beacons.beacons[:5]
            ]
        ))

    if tls_deep.deprecated_version_count > 0:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Deprecated TLS versions in use ({tls_deep.deprecated_version_count} connection(s))",
            severity="warning",
            details=["TLS 1.0/1.1 and SSL 3.0 are deprecated. Upgrade to TLS 1.2 or 1.3."]
        ))

    if tls_deep.weak_cipher_count > 0:
        diagnoses.append(SummaryDiagnosis(
            headline=f"Weak TLS cipher suites offered ({tls_deep.weak_cipher_count} instance(s))",
            severity="warning",
            details=["Review and disable weak/export-grade ciphers in your TLS configuration."]
        ))

    if proto.tls_failures:
        diagnoses.append(SummaryDiagnosis(
            headline=f"TLS handshake failures ({len(proto.tls_failures)} connection(s))",
            severity="critical",
            details=["Check certificate validity, TLS version, and cipher suite compatibility."]
        ))

    if proto.http_error_rate_pct > 10:
        diagnoses.append(SummaryDiagnosis(
            headline=f"High HTTP error rate: {proto.http_error_rate_pct}%",
            severity="warning",
            details=[f"HTTP status breakdown: {proto.http_status_counts}"]
        ))

    if proto.reset_rate_pct > 5:
        diagnoses.append(SummaryDiagnosis(
            headline=f"High connection reset rate: {proto.reset_rate_pct}%",
            severity="warning",
            details=[f"{len(proto.connection_resets)} RST packets."]
        ))

    if proto.dns_errors:
        diagnoses.append(SummaryDiagnosis(
            headline=f"DNS issues ({len(proto.dns_errors)} event(s))",
            severity="warning",
            details=[
                f"{sum(1 for e in proto.dns_errors if 'NXDOMAIN' in e.detail)} NXDOMAIN, "
                f"{sum(1 for e in proto.dns_errors if 'Slow' in e.detail)} slow resolutions, "
                f"{sum(1 for e in proto.dns_errors if 'SERVFAIL' in e.detail)} SERVFAIL."
            ]
        ))

    if proto.icmp_errors:
        diagnoses.append(SummaryDiagnosis(
            headline=f"ICMP error messages ({len(proto.icmp_errors)} event(s))",
            severity="warning",
            details=[e.detail for e in proto.icmp_errors[:5]]
        ))

    if rst_forensics and rst_forensics.total_resets > 0:
        critical_codes = {"MIDDLEBOX_INJECTION", "TLS_REJECTION", "RESOURCE_EXHAUSTION", "APP_CRASH"}
        sev = "critical" if any(c in rst_forensics.by_cause for c in critical_codes) else "warning"
        cause_summary = ", ".join(
            f"{count}× {code.replace('_', ' ').title()}"
            for code, count in sorted(rst_forensics.by_cause.items(), key=lambda x: -x[1])
        )
        diagnoses.append(SummaryDiagnosis(
            headline=f"TCP Reset forensics: {rst_forensics.total_resets} stream(s) terminated with RST",
            severity=sev,
            details=[
                f"Root causes: {cause_summary}.",
                "See the RST Forensics tab for a full evidence chain per reset.",
            ]
        ))

    if not diagnoses:
        diagnoses.append(SummaryDiagnosis(
            headline="No significant anomalies detected",
            severity="clean",
            details=["Traffic appears normal across all analysis dimensions."]
        ))

    return diagnoses
