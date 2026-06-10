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
    conversation_matrix: List[Dict[str, Any]] = []  # [{src, dst, bytes}]


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
    source: str          # "blocklist" or "abuseipdb"
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
    by_country: List[Dict[str, Any]] = []   # [{country, bytes}] sorted desc


# ── Beaconing ─────────────────────────────────────────────────────────────────

class BeaconFlow(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    connection_count: int
    avg_interval_sec: float
    cv: float                      # coefficient of variation — lower = more regular
    intervals: List[float] = []


class BeaconMetrics(BaseModel):
    beacons: List[BeaconFlow] = []


# ── Comparison report ─────────────────────────────────────────────────────────

class MetricDiff(BaseModel):
    label: str
    file1_value: Any
    file2_value: Any
    delta: Optional[float] = None
    direction: str = "neutral"   # "improved", "degraded", "neutral"


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
    detail: str                  # human-readable description of this step


class RSTAnalysis(BaseModel):
    # Identity
    rst_packet_number: int
    rst_timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    rst_sender: str              # "client", "server", or "third_party"

    # Classification
    root_cause: str              # short label, e.g. "Port closed / not listening"
    root_cause_code: str         # machine-readable key
    confidence: str              # "high", "medium", "low"
    severity: str                # "critical", "warning", "info"

    # Explanation
    explanation: str             # 1–2 sentence plain-English cause
    recommendation: str          # what to do about it

    # Evidence chain — ordered list of packets that led to the RST
    evidence_chain: List[RSTEvidenceStep] = []

    # Context metrics
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
    by_cause: Dict[str, int] = {}   # root_cause_code -> count


# ── History summary ────────────────────────────────────────────────────────────

class HistorySummary(BaseModel):
    id: str
    filename: str
    timestamp: float
    total_packets: int
