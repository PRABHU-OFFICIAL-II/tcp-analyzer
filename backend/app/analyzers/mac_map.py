"""
MAC Map analyzer.

Extracts every MAC address seen in the capture and enriches it with:
  - OUI manufacturer name (via Scapy's built-in manufacturer DB)
  - Device hostname, sourced from (in priority order):
      1. DHCP option 12  – device announces its own name to the DHCP server
      2. NetBIOS (UDP 137) NBNS – Windows workstation names
      3. mDNS (UDP 5353) – Apple / Linux / IoT zeroconf names
      4. DNS PTR reverse lookups present in the capture
"""

from collections import defaultdict
from typing import Dict, Set, Optional


def _get_manufacturer(mac: str) -> str:
    try:
        from scapy.config import conf
        db = conf.manufdb
        for method in ("get_manuf", "_get_manuf", "get_manuf_long"):
            if hasattr(db, method):
                result = getattr(db, method)(mac)
                if result and result.lower() not in (mac.lower(), ""):
                    return str(result)
    except Exception:
        pass
    return "Unknown"


def _bytes_to_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])


def analyze_mac_map(packets):
    from ..models.extended_report import MacEntry, MacMapMetrics

    # mac -> { ips, hostnames: {source->name}, count }
    mac_data: Dict[str, dict] = defaultdict(
        lambda: {"ips": set(), "hostnames": {}, "count": 0}
    )
    ip_to_mac: Dict[str, str] = {}

    for pkt in packets:
        # ── 1. ARP: most reliable MAC→IP binding ──────────────────────────────
        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            mac = arp.hwsrc
            if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                mac = mac.lower()
                mac_data[mac]["count"] += 1
                if arp.psrc and arp.psrc != "0.0.0.0":
                    mac_data[mac]["ips"].add(arp.psrc)
                    ip_to_mac[arp.psrc] = mac
            # ARP reply also carries the target mapping
            mac2 = arp.hwdst
            if mac2 and mac2 not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                mac2 = mac2.lower()
                if arp.pdst and arp.pdst != "0.0.0.0":
                    mac_data[mac2]["ips"].add(arp.pdst)
                    ip_to_mac[arp.pdst] = mac2

        # ── 2. Ethernet + IP: link every IP source to its MAC ──────────────────
        if pkt.haslayer("Ether") and pkt.haslayer("IP"):
            mac = pkt["Ether"].src.lower()
            ip  = pkt["IP"].src
            if (mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
                    and ip and not ip.startswith("0.")):
                mac_data[mac]["ips"].add(ip)
                mac_data[mac]["count"] += 1
                ip_to_mac[ip] = mac

        # ── 3. DHCP option 12 (hostname) ──────────────────────────────────────
        if pkt.haslayer("BOOTP") and pkt.haslayer("DHCP"):
            try:
                raw_mac = bytes(pkt["BOOTP"].chaddr)[:6]
                if any(b != 0 for b in raw_mac):
                    client_mac = _bytes_to_mac(raw_mac)
                    for opt in pkt["DHCP"].options:
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            name = opt[1]
                            if isinstance(name, bytes):
                                name = name.decode("utf-8", errors="ignore")
                            name = name.strip()
                            if name and "hostname" not in mac_data[client_mac]["hostnames"]:
                                mac_data[client_mac]["hostnames"]["DHCP"] = name
            except Exception:
                pass

        # ── 4. mDNS (UDP 5353) – hostname from A/AAAA/PTR answer records ──────
        if (pkt.haslayer("UDP") and pkt.haslayer("DNS")
                and pkt.haslayer("Ether")):
            udp = pkt["UDP"]
            if udp.dport == 5353 or udp.sport == 5353:
                sender_mac = pkt["Ether"].src.lower()
                dns = pkt["DNS"]
                try:
                    rr = dns.an
                    while rr and hasattr(rr, "rrname"):
                        name = rr.rrname
                        if isinstance(name, bytes):
                            name = name.decode("utf-8", errors="ignore")
                        name = name.rstrip(".")

                        if rr.type == 1:  # A record: name→IP
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = ".".join(str(b) for b in rdata)
                            # Strip .local suffix to get the bare hostname
                            host = name.replace(".local", "").split(".")[0]
                            if (host and sender_mac
                                    and "mDNS" not in mac_data[sender_mac]["hostnames"]
                                    and not host.startswith("_")):
                                mac_data[sender_mac]["hostnames"]["mDNS"] = host
                            if rdata and sender_mac:
                                mac_data[sender_mac]["ips"].add(rdata)
                                ip_to_mac[rdata] = sender_mac

                        elif rr.type == 12:  # PTR record
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            rdata = rdata.rstrip(".")
                            host = rdata.replace(".local", "").split(".")[0]
                            if (host and sender_mac
                                    and "mDNS" not in mac_data[sender_mac]["hostnames"]
                                    and not host.startswith("_")):
                                mac_data[sender_mac]["hostnames"]["mDNS"] = host

                        # Advance to next RR in the linked list
                        next_rr = rr.payload
                        if not hasattr(next_rr, "rrname"):
                            break
                        rr = next_rr
                except Exception:
                    pass

        # ── 5. NetBIOS Name Service (UDP 137) ──────────────────────────────────
        if (pkt.haslayer("UDP") and pkt.haslayer("Ether")
                and pkt["UDP"].sport == 137):
            sender_mac = pkt["Ether"].src.lower()
            try:
                from scapy.layers.netbios import NBNSNodeStatusResponse
                if pkt.haslayer(NBNSNodeStatusResponse):
                    nbns = pkt[NBNSNodeStatusResponse]
                    rdata = getattr(nbns, "ADDITIONAL_RDATA", [])
                    for entry in rdata:
                        raw = getattr(entry, "NETBIOS_NAME", b"")
                        if isinstance(raw, bytes):
                            name = raw.decode("utf-8", errors="ignore").strip()
                        else:
                            name = str(raw).strip()
                        if (name and name != "\x00" * len(name)
                                and "NetBIOS" not in mac_data[sender_mac]["hostnames"]):
                            mac_data[sender_mac]["hostnames"]["NetBIOS"] = name
                            break
            except Exception:
                pass

    # ── 6. DNS PTR reverse lookups already in the capture ─────────────────────
    for pkt in packets:
        if not (pkt.haslayer("UDP") and pkt.haslayer("DNS")):
            continue
        dns = pkt["DNS"]
        if dns.qr != 1:  # only responses
            continue
        try:
            rr = dns.an
            while rr and hasattr(rr, "rrname"):
                if rr.type == 12:  # PTR
                    rrname = rr.rrname
                    if isinstance(rrname, bytes):
                        rrname = rrname.decode("utf-8", errors="ignore")
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="ignore")

                    # rrname like "1.168.192.in-addr.arpa" → reverse → IP
                    if "in-addr.arpa" in rrname:
                        parts = rrname.replace(".in-addr.arpa.", "").replace(".in-addr.arpa", "").split(".")
                        ip = ".".join(reversed(parts))
                        if ip in ip_to_mac:
                            mac = ip_to_mac[ip]
                            host = rdata.rstrip(".").split(".")[0]
                            if host and "DNS-PTR" not in mac_data[mac]["hostnames"]:
                                mac_data[mac]["hostnames"]["DNS-PTR"] = host
                next_rr = rr.payload
                if not hasattr(next_rr, "rrname"):
                    break
                rr = next_rr
        except Exception:
            pass

    # ── Build output entries ───────────────────────────────────────────────────
    HOSTNAME_PRIORITY = ["DHCP", "NetBIOS", "mDNS", "DNS-PTR"]

    entries = []
    for mac, data in mac_data.items():
        if not data["ips"] and data["count"] == 0:
            continue

        hostname = None
        hostname_source = None
        for src in HOSTNAME_PRIORITY:
            if src in data["hostnames"]:
                hostname = data["hostnames"][src]
                hostname_source = src
                break

        entries.append(MacEntry(
            mac=mac,
            manufacturer=_get_manufacturer(mac),
            hostname=hostname,
            hostname_source=hostname_source,
            all_hostnames=data["hostnames"],
            ips=sorted(data["ips"]),
            packet_count=data["count"],
        ))

    entries.sort(key=lambda e: e.packet_count, reverse=True)
    resolved = sum(1 for e in entries if e.hostname)

    return MacMapMetrics(
        entries=entries,
        total_devices=len(entries),
        resolved_hostnames=resolved,
    )
