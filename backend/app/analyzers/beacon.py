import statistics
from collections import defaultdict
from ..models.extended_report import BeaconMetrics, BeaconFlow

MIN_CONNECTIONS = 5
MAX_CV = 0.3        # coefficient of variation threshold — lower = more regular = more suspicious


def analyze_beacon(packets) -> BeaconMetrics:
    # Track SYN timestamps per (src_ip, dst_ip, dst_port)
    syn_times: dict = defaultdict(list)

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue
        tcp = pkt["TCP"]
        if tcp.flags != 0x002:  # pure SYN only
            continue
        ip = pkt["IP"]
        key = (ip.src, ip.dst, tcp.dport)
        syn_times[key].append(float(pkt.time))

    beacons = []
    for (src, dst, dport), times in syn_times.items():
        if len(times) < MIN_CONNECTIONS:
            continue
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times) - 1)]
        if not intervals:
            continue
        avg = statistics.mean(intervals)
        if avg == 0:
            continue
        try:
            std = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        except statistics.StatisticsError:
            continue
        cv = std / avg
        if cv <= MAX_CV:
            beacons.append(BeaconFlow(
                src_ip=src,
                dst_ip=dst,
                dst_port=dport,
                connection_count=len(times),
                avg_interval_sec=round(avg, 3),
                cv=round(cv, 4),
                intervals=[round(i, 3) for i in intervals[:50]],
            ))

    beacons.sort(key=lambda b: b.cv)
    return BeaconMetrics(beacons=beacons)
