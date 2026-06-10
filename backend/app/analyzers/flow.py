from collections import defaultdict
from ..models.extended_report import FlowMetrics, FlowEntry, TalkerEntry


def analyze_flow(packets) -> FlowMetrics:
    # key: (src_ip, dst_ip, sport, dport, proto)
    flow_packets: dict = defaultdict(int)
    flow_bytes: dict = defaultdict(int)
    flow_start: dict = {}
    flow_end: dict = {}

    talker_sent: dict = defaultdict(int)
    talker_recv: dict = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue
        ip = pkt["IP"]
        src, dst = ip.src, ip.dst
        ts = float(pkt.time)
        size = len(pkt)

        talker_sent[src] += size
        talker_recv[dst] += size

        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            key = (src, dst, tcp.sport, tcp.dport, "TCP")
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            key = (src, dst, udp.sport, udp.dport, "UDP")
        else:
            key = (src, dst, 0, 0, "OTHER")

        flow_packets[key] += 1
        flow_bytes[key] += size
        if key not in flow_start:
            flow_start[key] = ts
        flow_end[key] = ts

    flows = []
    for key, pkt_count in flow_packets.items():
        src, dst, sport, dport, proto = key
        duration = round(flow_end[key] - flow_start[key], 4)
        flows.append(FlowEntry(
            src_ip=src, dst_ip=dst,
            src_port=sport, dst_port=dport,
            protocol=proto,
            packets=pkt_count,
            bytes=flow_bytes[key],
            duration_sec=duration,
        ))

    flows.sort(key=lambda f: f.bytes, reverse=True)

    all_ips = set(talker_sent) | set(talker_recv)
    talkers = []
    for ip in all_ips:
        sent = talker_sent.get(ip, 0)
        recv = talker_recv.get(ip, 0)
        talkers.append(TalkerEntry(ip=ip, bytes_sent=sent, bytes_recv=recv, total_bytes=sent + recv))
    talkers.sort(key=lambda t: t.total_bytes, reverse=True)

    # Conversation matrix: aggregate by (src, dst) regardless of port
    conv: dict = defaultdict(int)
    for key, b in flow_bytes.items():
        src, dst = key[0], key[1]
        pair = (src, dst) if src < dst else (dst, src)
        conv[pair] += b
    matrix = [{"src": k[0], "dst": k[1], "bytes": v} for k, v in conv.items()]
    matrix.sort(key=lambda x: x["bytes"], reverse=True)

    return FlowMetrics(
        total_flows=len(flows),
        flows=flows[:200],
        top_talkers=talkers[:20],
        conversation_matrix=matrix[:50],
    )
