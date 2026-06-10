"""
HTTP Object Extractor
=====================
Reconstructs HTTP request/response pairs from TCP streams.
Extracts method, host, path, status code, content-type, sizes.
"""
import re
from collections import defaultdict
from ..models.extended_report import HTTPObjectMetrics, HTTPObject

HTTP_REQUEST_RE  = re.compile(rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT) ([^\r\n]+) HTTP/\d\.\d", re.MULTILINE)
HTTP_RESPONSE_RE = re.compile(rb"^HTTP/\d\.\d (\d{3})", re.MULTILINE)
HOST_RE          = re.compile(rb"(?i)^Host:\s*([^\r\n]+)", re.MULTILINE)
CONTENT_TYPE_RE  = re.compile(rb"(?i)^Content-Type:\s*([^\r\n;]+)", re.MULTILINE)
CONTENT_LEN_RE   = re.compile(rb"(?i)^Content-Length:\s*(\d+)", re.MULTILINE)

HTTP_PORTS = {80, 8080, 8000, 3000, 5000, 8888, 8081}


def analyze_http_objects(packets) -> HTTPObjectMetrics:
    # Collect request payloads keyed by (src, dst, sport, dport)
    requests: dict  = {}  # key -> HTTPObject (pending response)
    objects: list   = []

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP") and pkt.haslayer("Raw")):
            continue
        ip  = pkt["IP"]
        tcp = pkt["TCP"]
        raw = bytes(pkt["Raw"])
        ts  = float(pkt.time)
        src, dst   = ip.src, ip.dst
        sport, dport = tcp.sport, tcp.dport

        # Request: from client to HTTP port
        if dport in HTTP_PORTS:
            req_match = HTTP_REQUEST_RE.search(raw)
            if req_match:
                method = req_match.group(1).decode("ascii", errors="replace")
                path   = req_match.group(2).decode("utf-8", errors="replace")
                host_m = HOST_RE.search(raw)
                host   = host_m.group(1).decode("utf-8", errors="replace").strip() if host_m else dst
                cl_m   = CONTENT_LEN_RE.search(raw)
                req_size = int(cl_m.group(1)) if cl_m else len(raw)
                key = (src, dst, sport, dport)
                requests[key] = HTTPObject(
                    src_ip=src, dst_ip=dst,
                    src_port=sport, dst_port=dport,
                    method=method, host=host, path=path,
                    request_size=req_size,
                    timestamp=ts,
                )

        # Response: from HTTP port to client
        elif sport in HTTP_PORTS:
            resp_match = HTTP_RESPONSE_RE.search(raw)
            if resp_match:
                status  = resp_match.group(1).decode("ascii", errors="replace")
                ct_m    = CONTENT_TYPE_RE.search(raw)
                ct      = ct_m.group(1).decode("utf-8", errors="replace").strip() if ct_m else None
                cl_m    = CONTENT_LEN_RE.search(raw)
                resp_size = int(cl_m.group(1)) if cl_m else len(raw)

                # Match to pending request (reverse direction)
                req_key = (dst, src, dport, sport)
                if req_key in requests:
                    obj = requests.pop(req_key)
                    obj.status_code    = status
                    obj.content_type   = ct
                    obj.response_size  = resp_size
                    objects.append(obj)
                else:
                    # Response without a seen request (e.g. capture started mid-stream)
                    objects.append(HTTPObject(
                        src_ip=dst, dst_ip=src,
                        src_port=dport, dst_port=sport,
                        method="?", host=src, path="?",
                        status_code=status,
                        content_type=ct,
                        response_size=resp_size,
                        timestamp=ts,
                    ))

    # Any pending requests with no response
    for obj in requests.values():
        objects.append(obj)

    objects.sort(key=lambda o: o.timestamp or 0.0)

    unique_hosts = sorted({o.host for o in objects if o.host})
    return HTTPObjectMetrics(
        objects=objects[:500],
        total_requests=len(objects),
        unique_hosts=unique_hosts,
    )
