"""
DNS Map Analyzer
================
Extracts every DNS query/response pair, builds a domain→IP mapping,
tracks NXDOMAIN/SERVFAIL counts, and identifies the most-queried domains.
"""
from collections import defaultdict
from ..models.extended_report import DNSMapMetrics, DNSRecord

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
               15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def analyze_dns_map(packets) -> DNSMapMetrics:
    pending: dict  = {}   # dns query id -> (query_name, qtype, client_ip, server_ip, ts, pkt_num)
    records: list  = []
    query_counts: dict = defaultdict(int)
    nxdomain_count = 0

    pkt_num = 0
    for pkt in packets:
        pkt_num += 1
        if not (pkt.haslayer("DNS") and pkt.haslayer("IP")):
            continue
        dns = pkt["DNS"]
        ip  = pkt["IP"]
        ts  = float(pkt.time)
        src, dst = ip.src, ip.dst
        qid = dns.id

        if dns.qr == 0:  # query
            if dns.qd:
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    qname = "(decode error)"
                qtype_raw = dns.qd.qtype if hasattr(dns.qd, "qtype") else 1
                qtype = QTYPE_NAMES.get(qtype_raw, str(qtype_raw))
                pending[qid] = (qname, qtype, src, dst, ts)
                query_counts[qname] += 1

        elif dns.qr == 1:  # response
            rcode = dns.rcode if hasattr(dns, "rcode") else 0

            if qid in pending:
                qname, qtype, client_ip, server_ip, q_ts = pending.pop(qid)
            else:
                if dns.qd:
                    try:
                        qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    except Exception:
                        qname = "(unknown)"
                    qtype_raw = dns.qd.qtype if hasattr(dns.qd, "qtype") else 1
                    qtype = QTYPE_NAMES.get(qtype_raw, str(qtype_raw))
                else:
                    qname, qtype = "(unknown)", "?"
                client_ip, server_ip, q_ts = dst, src, ts

            latency_ms = round((ts - q_ts) * 1000, 2) if q_ts else None

            # Collect answer RRs
            responses = []
            try:
                ans = dns.an
                while ans:
                    if hasattr(ans, "rdata"):
                        responses.append(str(ans.rdata))
                    elif hasattr(ans, "rrname"):
                        responses.append(str(ans.rrname))
                    ans = ans.payload if hasattr(ans, "payload") else None
                    if not hasattr(ans, "rrname"):
                        break
            except Exception:
                pass

            if rcode == 3:
                nxdomain_count += 1

            records.append(DNSRecord(
                query=qname,
                query_type=qtype,
                responses=responses,
                client_ip=client_ip,
                server_ip=server_ip,
                latency_ms=latency_ms,
                rcode=rcode,
                timestamp=ts,
            ))

    records.sort(key=lambda r: r.timestamp or 0.0)

    unique_domains = sorted({r.query for r in records if r.query and r.query != "(unknown)"})

    top_queried = sorted(
        [{"domain": d, "count": c} for d, c in query_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:30]

    return DNSMapMetrics(
        records=records[:1000],
        unique_domains=unique_domains[:200],
        nxdomain_count=nxdomain_count,
        top_queried=top_queried,
    )
