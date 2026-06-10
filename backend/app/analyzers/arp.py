from collections import defaultdict
from ..models.extended_report import ARPMetrics, ARPConflict


def analyze_arp(packets) -> ARPMetrics:
    # ip -> set of MACs seen in ARP replies
    ip_to_macs: dict = defaultdict(set)
    ip_first_pkt: dict = {}
    ip_first_ts: dict = {}

    packet_number = 0
    for pkt in packets:
        packet_number += 1
        if not pkt.haslayer("ARP"):
            continue
        arp = pkt["ARP"]
        # op=2 is ARP reply
        if arp.op == 2:
            ip = arp.psrc
            mac = arp.hwsrc.lower()
            ip_to_macs[ip].add(mac)
            if ip not in ip_first_pkt:
                ip_first_pkt[ip] = packet_number
                ip_first_ts[ip] = float(pkt.time)

    conflicts = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            conflicts.append(ARPConflict(
                ip=ip,
                macs_seen=sorted(macs),
                packet_number=ip_first_pkt[ip],
                timestamp=ip_first_ts[ip],
            ))

    return ARPMetrics(conflicts=conflicts)
