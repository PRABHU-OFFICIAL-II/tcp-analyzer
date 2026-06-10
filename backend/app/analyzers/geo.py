import json
from collections import defaultdict
from urllib.request import urlopen, Request
from urllib.error import URLError
from ..models.extended_report import GeoMetrics, GeoEntry

GEO_API_URL = "http://ip-api.com/batch"
GEO_API_TIMEOUT = 5
_GEO_CACHE: dict = {}


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )


def _batch_lookup(ips: list) -> dict:
    result = {}
    uncached = [ip for ip in ips if ip not in _GEO_CACHE]

    for chunk_start in range(0, len(uncached), 100):
        chunk = uncached[chunk_start:chunk_start + 100]
        try:
            payload = json.dumps(chunk).encode()
            req = Request(
                GEO_API_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=GEO_API_TIMEOUT) as resp:
                data = json.loads(resp.read())
            for entry in data:
                ip = entry.get("query", "")
                _GEO_CACHE[ip] = {
                    "country": entry.get("country", "Unknown"),
                    "country_code": entry.get("countryCode", "??"),
                    "city": entry.get("city", ""),
                    "isp": entry.get("isp", ""),
                }
        except (URLError, Exception):
            for ip in chunk:
                _GEO_CACHE[ip] = {"country": "Lookup failed", "country_code": "??", "city": "", "isp": ""}

    for ip in ips:
        result[ip] = _GEO_CACHE.get(ip, {"country": "Unknown", "country_code": "??", "city": "", "isp": ""})
    return result


def analyze_geo(packets) -> GeoMetrics:
    ip_bytes: dict = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue
        ip_layer = pkt["IP"]
        size = len(pkt)
        for ip in (ip_layer.src, ip_layer.dst):
            if not _is_private(ip):
                ip_bytes[ip] += size

    if not ip_bytes:
        return GeoMetrics()

    geo_data = _batch_lookup(list(ip_bytes.keys()))

    entries = []
    country_bytes: dict = defaultdict(int)

    for ip, b in ip_bytes.items():
        geo = geo_data.get(ip, {})
        country = geo.get("country", "Unknown")
        entries.append(GeoEntry(
            ip=ip,
            country=country,
            country_code=geo.get("country_code", "??"),
            city=geo.get("city", ""),
            isp=geo.get("isp", ""),
            bytes=b,
        ))
        country_bytes[country] += b

    entries.sort(key=lambda e: e.bytes, reverse=True)
    by_country = [{"country": c, "bytes": b} for c, b in
                  sorted(country_bytes.items(), key=lambda x: x[1], reverse=True)]

    return GeoMetrics(entries=entries[:100], by_country=by_country[:20])
