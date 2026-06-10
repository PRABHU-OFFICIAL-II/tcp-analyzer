"""
RST Forensics Analyzer
======================
For every RST packet in the capture, this analyzer:
  1. Reconstructs the stream history (all packets on the same 4-tuple)
  2. Backracks through that history and classifies the root cause
  3. Builds a human-readable evidence chain showing exactly what led to the RST

Root cause classification tree (evaluated in order):
  PORT_CLOSED          SYN -> RST with no SYN-ACK
  FIREWALL_REJECTION   SYN -> SYN-ACK -> RST (partial handshake)
  TLS_REJECTION        ClientHello present in stream -> RST
  RESOURCE_EXHAUSTION  Zero Window event in stream -> RST
  APP_CRASH            HTTP 5xx response in stream -> RST
  NAT_TIMEOUT          Handshake complete, long idle gap (>30s) -> RST
  APP_REFUSED          Handshake complete, no data payload -> RST
  MIDDLEBOX_INJECTION  RST sender is a third IP (not client or server)
  MID_SESSION          Handshake + data exchange -> abrupt RST
"""

import re
from collections import defaultdict
from ..models.extended_report import (
    RSTForensicsMetrics, RSTAnalysis, RSTEvidenceStep,
)

NAT_IDLE_THRESHOLD_SEC = 30.0
HTTP_STATUS_RE = re.compile(rb"HTTP/\d\.\d (\d{3})")

# ── Root cause catalogue ───────────────────────────────────────────────────────

CAUSES = {
    "PORT_CLOSED": {
        "label":          "Port closed / service not listening",
        "severity":       "warning",
        "confidence":     "high",
        "explanation":    "A SYN was sent but the remote host immediately replied with RST+ACK, "
                          "meaning nothing is listening on that port.",
        "recommendation": "Verify the target service is running and bound to the expected port. "
                          "Check firewall rules that may be sending TCP RST instead of silently dropping.",
    },
    "FIREWALL_REJECTION": {
        "label":          "Firewall or load balancer policy rejection",
        "severity":       "warning",
        "confidence":     "high",
        "explanation":    "The three-way handshake started (SYN + SYN-ACK) but was interrupted by "
                          "an RST before the ACK completed it. A stateful firewall, WAF, or load "
                          "balancer likely terminated the connection based on policy.",
        "recommendation": "Review firewall/ACL rules on the path between client and server. "
                          "Check load balancer health-check and connection limits.",
    },
    "TLS_REJECTION": {
        "label":          "TLS negotiation rejected",
        "severity":       "critical",
        "confidence":     "high",
        "explanation":    "A TLS ClientHello was sent on this stream and the connection was "
                          "subsequently reset. The server likely rejected the handshake due to "
                          "a certificate error, unsupported cipher suite, or TLS version mismatch.",
        "recommendation": "Check server certificate validity and expiry. Ensure client and server "
                          "share at least one TLS version and cipher suite in common.",
    },
    "RESOURCE_EXHAUSTION": {
        "label":          "Server resource exhaustion (Zero Window → RST)",
        "severity":       "critical",
        "confidence":     "high",
        "explanation":    "The receiving host advertised a Zero Window (buffer full) before the RST. "
                          "The application likely ran out of memory or CPU and the OS killed the socket.",
        "recommendation": "Investigate high memory/CPU usage on the server. Check application logs "
                          "for OOM kills or connection pool exhaustion.",
    },
    "APP_CRASH": {
        "label":          "Application crash or fatal error",
        "severity":       "critical",
        "confidence":     "high",
        "explanation":    "An HTTP 5xx error response was observed on this stream immediately before "
                          "the RST. The server-side application encountered a fatal error and "
                          "terminated the connection abruptly instead of a graceful FIN.",
        "recommendation": "Review application logs for exceptions or crashes at the time of this "
                          "packet. Check for unhandled exceptions in request handlers.",
    },
    "NAT_TIMEOUT": {
        "label":          "NAT / firewall session timeout",
        "severity":       "warning",
        "confidence":     "medium",
        "explanation":    "The handshake completed successfully and data was exchanged, but there "
                          "was a long idle gap before the RST. A NAT device or stateful firewall "
                          "likely expired its session table entry and injected the RST.",
        "recommendation": "Enable TCP keepalives on long-lived connections. Increase NAT/firewall "
                          "session timeout values, or use application-level heartbeats.",
    },
    "APP_REFUSED": {
        "label":          "Application refused connection after accept",
        "severity":       "warning",
        "confidence":     "medium",
        "explanation":    "The TCP handshake completed but no application data was exchanged before "
                          "the RST. The application accepted the socket at the OS level but then "
                          "immediately rejected it (e.g., connection limit, auth pre-check, or "
                          "access control list).",
        "recommendation": "Check application-layer connection limits, IP allowlists, and "
                          "authentication gate logic that runs before data exchange.",
    },
    "MIDDLEBOX_INJECTION": {
        "label":          "Middlebox / IDS TCP reset injection",
        "severity":       "critical",
        "confidence":     "high",
        "explanation":    "The RST was sent by an IP address that is neither the client nor the "
                          "server of this stream. This is a strong indicator of a middlebox "
                          "(IDS/IPS, DPI appliance) injecting a TCP reset to forcibly terminate "
                          "the connection, or a spoofed RST attack.",
        "recommendation": "Identify the device at the injecting IP. If it is an IDS/IPS, review "
                          "its signatures. If the IP is unknown, investigate for TCP reset attacks.",
    },
    "MID_SESSION": {
        "label":          "Mid-session abrupt termination",
        "severity":       "warning",
        "confidence":     "medium",
        "explanation":    "The connection was fully established and data was actively being exchanged "
                          "when it was abruptly reset. This typically indicates a process crash, "
                          "network path failure, or deliberate connection tear-down by the application.",
        "recommendation": "Correlate with application logs at the exact timestamp. Check for "
                          "process restarts, network interface errors, or deliberate disconnection "
                          "logic in the application code.",
    },
    "UNKNOWN": {
        "label":          "RST with insufficient context",
        "severity":       "info",
        "confidence":     "low",
        "explanation":    "An RST was observed but there is not enough stream history in this "
                          "capture to determine the root cause with confidence.",
        "recommendation": "Capture more of the conversation context (increase capture buffer size "
                          "or start capture earlier in the session lifetime).",
    },
}


# ── Flag helpers ───────────────────────────────────────────────────────────────

def _flag_str(flags) -> str:
    names = []
    f = int(flags)
    if f & 0x001: names.append("FIN")
    if f & 0x002: names.append("SYN")
    if f & 0x004: names.append("RST")
    if f & 0x008: names.append("PSH")
    if f & 0x010: names.append("ACK")
    if f & 0x020: names.append("URG")
    return "+".join(names) if names else str(f)


def _has_flag(flags, name: str) -> bool:
    f = int(flags)
    return {
        "SYN": bool(f & 0x002),
        "RST": bool(f & 0x004),
        "ACK": bool(f & 0x010),
        "PSH": bool(f & 0x008),
        "FIN": bool(f & 0x001),
    }.get(name, False)


# ── Main analyzer ──────────────────────────────────────────────────────────────

def analyze_rst_forensics(packets) -> RSTForensicsMetrics:
    # Index all packets by their canonical stream key
    # Canonical key: (min_ip, max_ip, min_port, max_port) so both directions match
    stream_index: dict = defaultdict(list)  # canon_key -> [(pkt_num, pkt)]

    for idx, pkt in enumerate(packets, 1):
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue
        ip  = pkt["IP"]
        tcp = pkt["TCP"]
        ips   = (ip.src, ip.dst)
        ports = (tcp.sport, tcp.dport)
        canon = (min(ips), max(ips), min(ports), max(ports))
        stream_index[canon].append((idx, pkt))

    metrics = RSTForensicsMetrics()
    seen_streams: set = set()   # avoid double-classifying the same stream

    for idx, pkt in enumerate(packets, 1):
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue
        ip  = pkt["IP"]
        tcp = pkt["TCP"]
        if not _has_flag(tcp.flags, "RST"):
            continue

        metrics.total_resets += 1

        ips   = (ip.src, ip.dst)
        ports = (tcp.sport, tcp.dport)
        canon = (min(ips), max(ips), min(ports), max(ports))

        if canon in seen_streams:
            continue
        seen_streams.add(canon)

        stream = stream_index[canon]   # all pkts in this stream, both directions
        analysis = _classify_stream(
            rst_pkt_num=idx,
            rst_pkt=pkt,
            stream=stream,
        )
        metrics.classified.append(analysis)
        code = analysis.root_cause_code
        metrics.by_cause[code] = metrics.by_cause.get(code, 0) + 1

    metrics.classified.sort(key=lambda a: a.rst_timestamp)
    return metrics


# ── Stream classifier ──────────────────────────────────────────────────────────

def _classify_stream(rst_pkt_num, rst_pkt, stream) -> RSTAnalysis:
    ip  = rst_pkt["IP"]
    tcp = rst_pkt["TCP"]
    rst_ts = float(rst_pkt.time)

    client_ip   = None   # IP that sent the first SYN
    server_ip   = None
    client_port = None
    server_port = None

    # ── Walk the stream history, earliest first ────────────────────────────────
    stream_sorted = sorted(stream, key=lambda x: float(x[1].time))

    had_syn          = False
    had_syn_ack      = False
    had_ack          = False   # handshake complete
    had_tls          = False
    had_zero_window  = False
    had_http_error   = False
    http_status_rst  = None
    had_data         = False
    bytes_exchanged  = 0
    last_data_ts     = None
    first_ts         = None
    evidence: list   = []

    for pkt_num, pkt in stream_sorted:
        p_ip  = pkt["IP"]
        p_tcp = pkt["TCP"]
        ts    = float(pkt.time)
        flags = _flag_str(p_tcp.flags)

        if first_ts is None:
            first_ts = ts

        step_detail = ""

        # SYN
        if _has_flag(p_tcp.flags, "SYN") and not _has_flag(p_tcp.flags, "ACK"):
            if not had_syn:
                client_ip   = p_ip.src
                server_ip   = p_ip.dst
                client_port = p_tcp.sport
                server_port = p_tcp.dport
                had_syn = True
                step_detail = f"Connection initiated — SYN from {p_ip.src}:{p_tcp.sport} → {p_ip.dst}:{p_tcp.dport}"

        # SYN-ACK
        elif _has_flag(p_tcp.flags, "SYN") and _has_flag(p_tcp.flags, "ACK"):
            had_syn_ack = True
            step_detail = f"Server acknowledged — SYN-ACK from {p_ip.src}:{p_tcp.sport}"

        # Completing ACK
        elif (_has_flag(p_tcp.flags, "ACK") and not _has_flag(p_tcp.flags, "SYN")
              and not _has_flag(p_tcp.flags, "RST") and not _has_flag(p_tcp.flags, "PSH")
              and had_syn_ack and not had_ack):
            had_ack = True
            step_detail = f"Handshake completed — ACK from {p_ip.src}"

        # Zero Window
        if p_tcp.window == 0 and not _has_flag(p_tcp.flags, "SYN") and not _has_flag(p_tcp.flags, "RST"):
            had_zero_window = True
            step_detail = (step_detail or "") + f" | Zero Window advertised by {p_ip.src} — receive buffer full"

        # Data payload
        if pkt.haslayer("Raw"):
            raw = bytes(pkt["Raw"])
            size = len(raw)
            bytes_exchanged += size
            last_data_ts = ts

            # TLS ClientHello detection
            if (len(raw) >= 6 and raw[0] == 22
                    and (raw[1], raw[2]) in [(3,1),(3,2),(3,3),(3,4)]
                    and raw[5] == 1):
                had_tls = True
                step_detail = (step_detail or "") + f" | TLS ClientHello from {p_ip.src}"

            # HTTP error codes
            for m in HTTP_STATUS_RE.finditer(raw):
                code = m.group(1).decode()
                if code.startswith("5") or code.startswith("4"):
                    had_http_error = True
                    http_status_rst = code
                    step_detail = (step_detail or "") + f" | HTTP {code} response from {p_ip.src}"

            had_data = True

        # RST itself
        if _has_flag(p_tcp.flags, "RST"):
            step_detail = f"CONNECTION RESET by {p_ip.src}:{p_tcp.sport}"

        if step_detail:
            evidence.append(RSTEvidenceStep(
                packet_number=pkt_num,
                timestamp=ts,
                flags=flags,
                src_ip=p_ip.src,
                dst_ip=p_ip.dst,
                src_port=p_tcp.sport,
                dst_port=p_tcp.dport,
                detail=step_detail,
            ))

    # ── Determine RST sender role ──────────────────────────────────────────────
    rst_sender_ip = ip.src
    if client_ip and server_ip:
        if rst_sender_ip == client_ip:
            rst_sender = "client"
        elif rst_sender_ip == server_ip:
            rst_sender = "server"
        else:
            rst_sender = "third_party"
    else:
        rst_sender = "unknown"

    # ── Idle gap before RST ────────────────────────────────────────────────────
    idle_gap = None
    if last_data_ts and rst_ts > last_data_ts:
        idle_gap = round(rst_ts - last_data_ts, 3)

    stream_duration = round(rst_ts - first_ts, 3) if first_ts else None

    # ── Classification rule tree (evaluated in priority order) ────────────────
    code = _classify(
        had_syn=had_syn,
        had_syn_ack=had_syn_ack,
        had_ack=had_ack,
        had_tls=had_tls,
        had_zero_window=had_zero_window,
        had_http_error=had_http_error,
        had_data=had_data,
        idle_gap=idle_gap,
        rst_sender=rst_sender,
    )

    cause = CAUSES[code]

    return RSTAnalysis(
        rst_packet_number=rst_pkt_num,
        rst_timestamp=rst_ts,
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=tcp.sport,
        dst_port=tcp.dport,
        rst_sender=rst_sender,
        root_cause=cause["label"],
        root_cause_code=code,
        confidence=cause["confidence"],
        severity=cause["severity"],
        explanation=cause["explanation"],
        recommendation=cause["recommendation"],
        evidence_chain=evidence,
        stream_duration_sec=stream_duration,
        idle_gap_before_rst_sec=idle_gap,
        bytes_exchanged=bytes_exchanged,
        had_tls=had_tls,
        had_zero_window=had_zero_window,
        had_http_error=had_http_error,
        http_status_before_rst=http_status_rst,
    )


def _classify(had_syn, had_syn_ack, had_ack, had_tls,
              had_zero_window, had_http_error, had_data,
              idle_gap, rst_sender) -> str:
    # Third-party sender is always middlebox injection regardless of anything else
    if rst_sender == "third_party":
        return "MIDDLEBOX_INJECTION"

    # SYN was sent, RST came back before SYN-ACK → port closed
    if had_syn and not had_syn_ack:
        return "PORT_CLOSED"

    # SYN + SYN-ACK but no completing ACK → firewall intercepted mid-handshake
    if had_syn and had_syn_ack and not had_ack:
        return "FIREWALL_REJECTION"

    # Handshake complete — now look at what happened in the stream
    if had_ack:
        if had_tls:
            return "TLS_REJECTION"
        if had_zero_window:
            return "RESOURCE_EXHAUSTION"
        if had_http_error:
            return "APP_CRASH"
        if idle_gap is not None and idle_gap >= NAT_IDLE_THRESHOLD_SEC:
            return "NAT_TIMEOUT"
        if not had_data:
            return "APP_REFUSED"
        return "MID_SESSION"

    return "UNKNOWN"
