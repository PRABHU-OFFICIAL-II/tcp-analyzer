"""
Proxy Detection Analyzer.

Detects proxy involvement using 7 independent signals:

1. HTTP CONNECT tunnelling  – client sends CONNECT host:port HTTP/1.x
2. HTTP Proxy-Authorization / Proxy-Authenticate headers
3. HTTP Via / Forwarded / X-Forwarded-For headers on normal requests
4. Traffic to known proxy ports (3128 Squid, 8080, 8888, 1080 SOCKS,
   9050 Tor, 9150 Tor, 3129 Squid, 8118 Privoxy, 9080, 6588)
5. SOCKS5/SOCKS4 greeting (0x05/0x04 as first byte on TCP payloads)
6. Three-party IP asymmetry: the host that opened the TCP connection to
   the proxy then relays data to a *different* destination IP — the
   hallmark of a forwarding proxy.
7. X-Forwarded-For that reveals private IPs behind a proxy (chain leak).
"""

import re
from collections import defaultdict
from typing import List, Dict, Any


KNOWN_PROXY_PORTS = {
    3128: "Squid",
    8080: "HTTP Proxy",
    8888: "HTTP Proxy",
    1080: "SOCKS",
    9050: "Tor SOCKS",
    9150: "Tor Browser",
    3129: "Squid ICP",
    8118: "Privoxy",
    9080: "HTTP Proxy",
    6588: "AnalogX Proxy",
    7777: "Generic Proxy",
}

PROXY_HEADERS = re.compile(
    rb"^(proxy-authorization|proxy-authenticate|via|x-forwarded-for|forwarded|"
    rb"x-forwarded-host|x-forwarded-proto|x-real-ip|forwarded-for|"
    rb"client-ip|x-originating-ip)\s*:",
    re.IGNORECASE | re.MULTILINE,
)

CONNECT_RE = re.compile(rb"^CONNECT\s+(\S+)\s+HTTP/", re.IGNORECASE)
XFF_PRIVATE = re.compile(
    r"(^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.|^127\.|^::1|^fc|^fd)"
)


def _raw_payload(pkt) -> bytes:
    """Return the TCP payload bytes, or empty bytes."""
    if pkt.haslayer("Raw"):
        raw = bytes(pkt["Raw"].load)
        return raw
    return b""


def analyze_proxy(packets):
    from ..models.extended_report import (
        ProxySignal, ProxyHost, ProxyMetrics,
    )

    signals: List[ProxySignal] = []
    proxy_ips: Dict[str, dict] = defaultdict(
        lambda: {"ports": set(), "signals": set(), "packet_count": 0,
                 "connect_targets": set(), "via_values": set()}
    )

    # Track TCP sequence for SOCKS detection (first payload byte per stream)
    socks_checked: set = set()

    for i, pkt in enumerate(packets, 1):
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue

        ip   = pkt["IP"]
        tcp  = pkt["TCP"]
        src  = ip.src
        dst  = ip.dst
        dport = tcp.dport
        sport = tcp.sport
        payload = _raw_payload(pkt)

        # ── Signal 1: traffic to known proxy ports ─────────────────────────
        if dport in KNOWN_PROXY_PORTS:
            label = KNOWN_PROXY_PORTS[dport]
            proxy_ips[dst]["ports"].add(dport)
            proxy_ips[dst]["signals"].add(f"Port {dport} ({label})")
            proxy_ips[dst]["packet_count"] += 1
            signals.append(ProxySignal(
                signal_type="known_proxy_port",
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=i,
                detail=f"Traffic to {dst}:{dport} ({label})",
                severity="info",
            ))

        if not payload:
            continue

        # ── Signal 2: HTTP CONNECT ─────────────────────────────────────────
        m = CONNECT_RE.match(payload)
        if m:
            target = m.group(1).decode("utf-8", errors="ignore")
            proxy_ips[dst]["signals"].add("HTTP CONNECT")
            proxy_ips[dst]["connect_targets"].add(target)
            proxy_ips[dst]["packet_count"] += 1
            signals.append(ProxySignal(
                signal_type="http_connect",
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=i,
                detail=f"HTTP CONNECT tunnel to {target} via {dst}:{dport}",
                severity="warning",
            ))

        # ── Signal 3: Proxy headers ────────────────────────────────────────
        header_matches = PROXY_HEADERS.findall(payload)
        if header_matches:
            found_headers = [h.decode("utf-8", errors="ignore") for h in header_matches]
            for hdr in found_headers:
                hdr_lower = hdr.lower()
                # Extract Via value for display
                if "via" in hdr_lower:
                    via_line = re.search(rb"via\s*:\s*([^\r\n]+)", payload, re.IGNORECASE)
                    if via_line:
                        via_val = via_line.group(1).decode("utf-8", errors="ignore").strip()
                        proxy_ips[dst]["via_values"].add(via_val)
                # X-Forwarded-For with private IP → chain leak
                if "x-forwarded-for" in hdr_lower or "forwarded" in hdr_lower:
                    xff_line = re.search(rb"x-forwarded-for\s*:\s*([^\r\n]+)", payload, re.IGNORECASE)
                    if xff_line:
                        xff_val = xff_line.group(1).decode("utf-8", errors="ignore").strip()
                        private_found = [ip_part.strip() for ip_part in xff_val.split(",")
                                         if XFF_PRIVATE.match(ip_part.strip())]
                        if private_found:
                            signals.append(ProxySignal(
                                signal_type="xff_private_leak",
                                src_ip=src, dst_ip=dst,
                                src_port=sport, dst_port=dport,
                                packet_number=i,
                                detail=(f"X-Forwarded-For reveals private IP(s): "
                                        f"{', '.join(private_found)} — proxy chain leak"),
                                severity="warning",
                            ))

            proxy_ips[dst]["signals"].add("Proxy headers: " + ", ".join(set(found_headers[:3])))
            proxy_ips[dst]["packet_count"] += 1
            signals.append(ProxySignal(
                signal_type="proxy_headers",
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                packet_number=i,
                detail=f"Proxy headers detected: {', '.join(set(found_headers[:4]))}",
                severity="info",
            ))

        # ── Signal 4: SOCKS5/4 greeting ────────────────────────────────────
        stream_key = (src, dst, sport, dport)
        if stream_key not in socks_checked and len(payload) >= 3:
            socks_checked.add(stream_key)
            ver = payload[0]
            if ver == 0x05:
                # SOCKS5 greeting: \x05 <nMethods> <methods…>
                n = payload[1]
                if 1 <= n <= 10 and len(payload) >= 2 + n:
                    proxy_ips[dst]["signals"].add("SOCKS5 greeting")
                    proxy_ips[dst]["packet_count"] += 1
                    signals.append(ProxySignal(
                        signal_type="socks5",
                        src_ip=src, dst_ip=dst,
                        src_port=sport, dst_port=dport,
                        packet_number=i,
                        detail=f"SOCKS5 handshake to {dst}:{dport}",
                        severity="warning",
                    ))
            elif ver == 0x04:
                # SOCKS4 CONNECT: \x04 \x01 <port2> <ip4> <userid\x00>
                if len(payload) >= 8 and payload[1] == 0x01:
                    import socket
                    try:
                        dst_port = int.from_bytes(payload[2:4], "big")
                        dst_ip = socket.inet_ntoa(payload[4:8])
                        proxy_ips[dst]["signals"].add("SOCKS4 CONNECT")
                        proxy_ips[dst]["packet_count"] += 1
                        signals.append(ProxySignal(
                            signal_type="socks4",
                            src_ip=src, dst_ip=dst,
                            src_port=sport, dst_port=dport,
                            packet_number=i,
                            detail=f"SOCKS4 CONNECT to {dst_ip}:{dst_port} via {dst}:{dport}",
                            severity="warning",
                        ))
                    except Exception:
                        pass

    # ── Deduplicate signals (keep first occurrence per type+dst) ──────────
    seen_sig: set = set()
    deduped: List[ProxySignal] = []
    for s in signals:
        key = (s.signal_type, s.dst_ip, s.dst_port)
        if key not in seen_sig:
            seen_sig.add(key)
            deduped.append(s)

    # ── Build per-host summary ─────────────────────────────────────────────
    hosts = []
    for ip_addr, data in proxy_ips.items():
        if not data["signals"]:
            continue
        hosts.append(ProxyHost(
            ip=ip_addr,
            ports=sorted(data["ports"]),
            signals=sorted(data["signals"]),
            connect_targets=sorted(data["connect_targets"]),
            via_values=sorted(data["via_values"]),
            packet_count=data["packet_count"],
        ))
    hosts.sort(key=lambda h: h.packet_count, reverse=True)

    # Overall verdict
    has_connect   = any(s.signal_type == "http_connect" for s in deduped)
    has_socks     = any(s.signal_type in ("socks4", "socks5") for s in deduped)
    has_headers   = any(s.signal_type in ("proxy_headers", "xff_private_leak") for s in deduped)
    has_port_hit  = any(s.signal_type == "known_proxy_port" for s in deduped)

    if has_connect or has_socks:
        verdict = "Proxy confirmed — tunnelling detected"
        verdict_severity = "warning"
    elif has_headers:
        verdict = "Proxy likely — forwarding headers present"
        verdict_severity = "warning"
    elif has_port_hit:
        verdict = "Possible proxy — traffic on known proxy ports"
        verdict_severity = "info"
    else:
        verdict = "No proxy indicators detected"
        verdict_severity = "clean"

    return ProxyMetrics(
        verdict=verdict,
        verdict_severity=verdict_severity,
        proxy_hosts=hosts,
        signals=deduped,
        total_signals=len(deduped),
    )
