from collections import defaultdict
from typing import List, Tuple, Dict
from ..models.report import PerformanceMetrics, AnomalyEntry

# Thresholds
RETRANSMISSION_RATE_WARNING = 2.0   # percent
HIGH_HANDSHAKE_MS = 200             # ms
HIGH_DELTA_MS = 1000                # ms — server response time


def analyze_performance(packets) -> PerformanceMetrics:
    metrics = PerformanceMetrics()

    total_tcp = 0
    retransmit_count = 0
    seen_seq: Dict[Tuple, set] = defaultdict(set)

    # Handshake tracking: key = (src_ip, dst_ip, dst_port)
    syn_times: Dict[Tuple, float] = {}
    syn_ack_times: Dict[Tuple, float] = {}
    handshake_durations: List[float] = []

    # Application delta tracking: last request time per stream
    request_times: Dict[Tuple, float] = {}
    response_deltas: List[float] = []

    # Throughput bucketing (1-second buckets)
    throughput: Dict[int, int] = defaultdict(int)
    start_ts = None
    packet_number = 0

    for pkt in packets:
        packet_number += 1
        if not pkt.haslayer("TCP"):
            continue

        ts = float(pkt.time)
        if start_ts is None:
            start_ts = ts
        bucket = int(ts - start_ts)
        throughput[bucket] += len(pkt)

        ip = pkt["IP"] if pkt.haslayer("IP") else None
        tcp = pkt["TCP"]
        if ip is None:
            continue

        src, dst = ip.src, ip.dst
        sport, dport = tcp.sport, tcp.dport
        flags = tcp.flags
        total_tcp += 1

        # --- Retransmission detection ---
        stream_key = (src, dst, sport, dport)
        seq = tcp.seq
        if seq in seen_seq[stream_key]:
            retransmit_count += 1
            metrics.retransmission_events.append(AnomalyEntry(
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=packet_number,
                timestamp=ts,
                detail=f"Retransmitted seq={seq}",
                severity="warning"
            ))
        else:
            seen_seq[stream_key].add(seq)

        # --- Zero window ---
        if tcp.window == 0 and "S" not in str(flags) and "R" not in str(flags):
            metrics.zero_window_count += 1
            metrics.zero_window_events.append(AnomalyEntry(
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=packet_number,
                timestamp=ts,
                detail=f"TCP Zero Window — receiver buffer full",
                severity="warning"
            ))

        # --- Handshake timing ---
        # SYN (no ACK)
        if flags == 0x002:  # SYN
            key = (src, dst, dport)
            syn_times[key] = ts

        # SYN-ACK
        elif flags == 0x012:  # SYN+ACK
            key = (dst, src, sport)  # reverse perspective
            if key in syn_times:
                syn_ack_times[key] = ts

        # ACK completing handshake
        elif flags == 0x010:  # ACK only
            key = (src, dst, dport)
            if key in syn_ack_times:
                duration_ms = (ts - syn_times[key]) * 1000
                handshake_durations.append(duration_ms)
                if duration_ms > HIGH_HANDSHAKE_MS:
                    metrics.handshake_anomalies.append(AnomalyEntry(
                        src_ip=src, dst_ip=dst,
                        src_port=sport, dst_port=dport,
                        packet_number=packet_number,
                        timestamp=ts,
                        detail=f"Slow handshake: {duration_ms:.1f} ms",
                        severity="warning"
                    ))
                del syn_times[key]
                del syn_ack_times[key]

        # --- Application delta: track request/response pairs ---
        # Heuristic: PSH+ACK with payload going to server port is a request
        if "P" in str(flags) and "A" in str(flags):
            if dport in (80, 443, 8080, 8443, 3000, 5000):
                request_times[(src, dst, sport, dport)] = ts
            elif sport in (80, 443, 8080, 8443, 3000, 5000):
                req_key = (dst, src, dport, sport)
                if req_key in request_times:
                    delta_ms = (ts - request_times[req_key]) * 1000
                    response_deltas.append(delta_ms)
                    del request_times[req_key]

    # Populate summary metrics
    metrics.retransmission_count = retransmit_count
    if total_tcp > 0:
        metrics.retransmission_rate_pct = round(retransmit_count / total_tcp * 100, 2)

    if handshake_durations:
        metrics.avg_handshake_ms = round(sum(handshake_durations) / len(handshake_durations), 2)
        metrics.max_handshake_ms = round(max(handshake_durations), 2)

    if response_deltas:
        metrics.avg_delta_ms = round(sum(response_deltas) / len(response_deltas), 2)
        metrics.max_delta_ms = round(max(response_deltas), 2)

    # Build throughput time series
    if throughput:
        for second in sorted(throughput.keys()):
            metrics.throughput_series.append({"time_sec": second, "bytes": throughput[second]})

    return metrics
