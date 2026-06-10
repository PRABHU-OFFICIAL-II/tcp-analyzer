from collections import defaultdict
from typing import List, Tuple, Dict
from ..models.report import PerformanceMetrics, AnomalyEntry
from .. import thresholds


def analyze_performance(packets) -> PerformanceMetrics:
    HIGH_HANDSHAKE_MS = thresholds.get("performance", "high_handshake_ms")
    HIGH_DELTA_MS     = thresholds.get("performance", "high_delta_ms")

    metrics = PerformanceMetrics()

    total_tcp = 0
    retransmit_count = 0
    seen_seq: Dict[Tuple, set] = defaultdict(set)

    syn_times: Dict[Tuple, float] = {}
    syn_ack_times: Dict[Tuple, float] = {}
    handshake_durations: List[float] = []

    request_times: Dict[Tuple, float] = {}
    response_deltas: List[float] = []

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

        # Retransmission detection
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

        # Zero window
        if tcp.window == 0 and "S" not in str(flags) and "R" not in str(flags):
            metrics.zero_window_count += 1
            metrics.zero_window_events.append(AnomalyEntry(
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=packet_number,
                timestamp=ts,
                detail="TCP Zero Window — receiver buffer full",
                severity="warning"
            ))

        # Handshake timing
        if flags == 0x002:
            key = (src, dst, dport)
            syn_times[key] = ts
        elif flags == 0x012:
            key = (dst, src, sport)
            if key in syn_times:
                syn_ack_times[key] = ts
        elif flags == 0x010:
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

        # Application delta
        if "P" in str(flags) and "A" in str(flags):
            if dport in (80, 443, 8080, 8443, 3000, 5000):
                request_times[(src, dst, sport, dport)] = ts
            elif sport in (80, 443, 8080, 8443, 3000, 5000):
                req_key = (dst, src, dport, sport)
                if req_key in request_times:
                    delta_ms = (ts - request_times[req_key]) * 1000
                    response_deltas.append(delta_ms)
                    if delta_ms > HIGH_DELTA_MS:
                        metrics.slow_response_events.append(AnomalyEntry(
                            src_ip=src, dst_ip=dst,
                            src_port=sport, dst_port=dport,
                            packet_number=packet_number,
                            timestamp=ts,
                            detail=f"Slow server response: {delta_ms:.1f} ms",
                            severity="warning"
                        ))
                    del request_times[req_key]

    metrics.retransmission_count = retransmit_count
    if total_tcp > 0:
        metrics.retransmission_rate_pct = round(retransmit_count / total_tcp * 100, 2)

    if handshake_durations:
        metrics.avg_handshake_ms = round(sum(handshake_durations) / len(handshake_durations), 2)
        metrics.max_handshake_ms = round(max(handshake_durations), 2)
        metrics.p95_handshake_ms = round(sorted(handshake_durations)[int(len(handshake_durations) * 0.95)], 2)

    if response_deltas:
        metrics.avg_delta_ms = round(sum(response_deltas) / len(response_deltas), 2)
        metrics.max_delta_ms = round(max(response_deltas), 2)
        metrics.p95_delta_ms = round(sorted(response_deltas)[int(len(response_deltas) * 0.95)], 2)

    if throughput:
        for second in sorted(throughput.keys()):
            metrics.throughput_series.append({"time_sec": second, "bytes": throughput[second]})

    return metrics
