from pydantic import BaseModel
from typing import List, Optional, Dict, Any


# ── Flow analysis ──────────────────────────────────────────────────────────────

class FlowEntry(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int
    bytes: int
    duration_sec: float


class TalkerEntry(BaseModel):
    ip: str
    bytes_sent: int
    bytes_recv: int
    total_bytes: int


class FlowMetrics(BaseModel):
    total_flows: int = 0
    flows: List[FlowEntry] = []
    top_talkers: List[TalkerEntry] = []
    conversation_matrix: List[Dict[str, Any]] = []


# ── OS / App fingerprinting ────────────────────────────────────────────────────

class HostFingerprint(BaseModel):
    ip: str
    os_guess: str
    ttl_observed: int
    detected_apps: List[str] = []


class FingerprintMetrics(BaseModel):
    hosts: List[HostFingerprint] = []


# ── TLS deep inspection ────────────────────────────────────────────────────────

class JA3Entry(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    ja3: str
    ja3s: Optional[str] = None
    tls_version_offered: str
    cipher_suites: List[int] = []
    weak_ciphers: List[str] = []
    deprecated_version: bool = False


class TLSDeepMetrics(BaseModel):
    connections: List[JA3Entry] = []
    weak_cipher_count: int = 0
    deprecated_version_count: int = 0
    unique_ja3: List[str] = []


# ── ARP spoofing ───────────────────────────────────────────────────────────────

class ARPConflict(BaseModel):
    ip: str
    macs_seen: List[str]
    packet_number: int
    timestamp: float


class ARPMetrics(BaseModel):
    conflicts: List[ARPConflict] = []


# ── IOC matching ───────────────────────────────────────────────────────────────

class IOCMatch(BaseModel):
    ip: str
    source: str
    detail: str
    severity: str


class IOCMetrics(BaseModel):
    matches: List[IOCMatch] = []


# ── Geo-IP ────────────────────────────────────────────────────────────────────

class GeoEntry(BaseModel):
    ip: str
    country: str
    country_code: str
    city: str
    isp: str
    bytes: int


class GeoMetrics(BaseModel):
    entries: List[GeoEntry] = []
    by_country: List[Dict[str, Any]] = []


# ── Beaconing ─────────────────────────────────────────────────────────────────

class BeaconFlow(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    connection_count: int
    avg_interval_sec: float
    cv: float
    intervals: List[float] = []


class BeaconMetrics(BaseModel):
    beacons: List[BeaconFlow] = []


# ── Timeline event ────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: float
    time_offset_sec: float
    category: str          # "security", "performance", "protocol", "rst", "beacon"
    severity: str          # "critical", "warning", "info"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    detail: str
    packet_number: Optional[int] = None


class TimelineMetrics(BaseModel):
    events: List[TimelineEvent] = []
    start_time: Optional[float] = None


# ── HTTP object extraction ─────────────────────────────────────────────────────

class HTTPObject(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    method: str
    host: str
    path: str
    status_code: Optional[str] = None
    content_type: Optional[str] = None
    request_size: int = 0
    response_size: int = 0
    timestamp: Optional[float] = None


class HTTPObjectMetrics(BaseModel):
    objects: List[HTTPObject] = []
    total_requests: int = 0
    unique_hosts: List[str] = []


# ── DNS map ───────────────────────────────────────────────────────────────────

class DNSRecord(BaseModel):
    query: str
    query_type: str
    responses: List[str] = []
    client_ip: str
    server_ip: str
    latency_ms: Optional[float] = None
    rcode: int = 0
    timestamp: Optional[float] = None


class DNSMapMetrics(BaseModel):
    records: List[DNSRecord] = []
    unique_domains: List[str] = []
    nxdomain_count: int = 0
    top_queried: List[Dict[str, Any]] = []


# ── Comparison report ─────────────────────────────────────────────────────────

class MetricDiff(BaseModel):
    label: str
    file1_value: Any
    file2_value: Any
    delta: Optional[float] = None
    direction: str = "neutral"


class CompareReport(BaseModel):
    file1_name: str
    file2_name: str
    diffs: List[MetricDiff] = []
    file1_diagnoses: List[Any] = []
    file2_diagnoses: List[Any] = []


# ── RST forensics ─────────────────────────────────────────────────────────────

class RSTEvidenceStep(BaseModel):
    packet_number: int
    timestamp: float
    flags: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    detail: str
    payload_bytes: int = 0


class RSTAnalysis(BaseModel):
    rst_packet_number: int
    rst_timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    rst_sender: str

    root_cause: str
    root_cause_code: str
    confidence: str
    severity: str

    explanation: str
    recommendation: str

    evidence_chain: List[RSTEvidenceStep] = []
    full_trace: List[RSTEvidenceStep] = []

    stream_duration_sec: Optional[float] = None
    idle_gap_before_rst_sec: Optional[float] = None
    bytes_exchanged: int = 0
    had_tls: bool = False
    had_zero_window: bool = False
    had_http_error: bool = False
    http_status_before_rst: Optional[str] = None


class RSTForensicsMetrics(BaseModel):
    total_resets: int = 0
    classified: List[RSTAnalysis] = []
    by_cause: Dict[str, int] = {}


# ── Proxy Detection ───────────────────────────────────────────────────────────

class ProxySignal(BaseModel):
    signal_type: str          # "http_connect", "socks5", "proxy_headers", etc.
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_number: int
    detail: str
    severity: str             # "warning", "info"


class ProxyHost(BaseModel):
    ip: str
    ports: List[int] = []
    signals: List[str] = []
    connect_targets: List[str] = []
    via_values: List[str] = []
    packet_count: int = 0


class ProxyMetrics(BaseModel):
    verdict: str = "No proxy indicators detected"
    verdict_severity: str = "clean"
    proxy_hosts: List[ProxyHost] = []
    signals: List[ProxySignal] = []
    total_signals: int = 0


# ── MAC Map ───────────────────────────────────────────────────────────────────

class MacEntry(BaseModel):
    mac: str
    manufacturer: str = "Unknown"
    hostname: Optional[str] = None
    hostname_source: Optional[str] = None        # "DHCP", "mDNS", "NetBIOS", "DNS-PTR"
    all_hostnames: Dict[str, str] = {}           # source -> name (all found)
    ips: List[str] = []
    packet_count: int = 0


class MacMapMetrics(BaseModel):
    entries: List[MacEntry] = []
    total_devices: int = 0
    resolved_hostnames: int = 0


# ── History summary ────────────────────────────────────────────────────────────

class HistorySummary(BaseModel):
    id: str
    filename: str
    timestamp: float
    total_packets: int
