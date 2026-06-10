from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class AnomalyEntry(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_number: Optional[int] = None
    timestamp: Optional[float] = None
    detail: str
    severity: str  # "critical", "warning", "info"


class PerformanceMetrics(BaseModel):
    avg_handshake_ms: Optional[float] = None
    max_handshake_ms: Optional[float] = None
    retransmission_count: int = 0
    retransmission_rate_pct: float = 0.0
    zero_window_count: int = 0
    avg_delta_ms: Optional[float] = None
    max_delta_ms: Optional[float] = None
    throughput_series: List[Dict[str, Any]] = []
    handshake_anomalies: List[AnomalyEntry] = []
    zero_window_events: List[AnomalyEntry] = []
    retransmission_events: List[AnomalyEntry] = []


class SecurityMetrics(BaseModel):
    port_scan_sources: List[AnomalyEntry] = []
    cleartext_credentials: List[AnomalyEntry] = []
    protocol_port_mismatches: List[AnomalyEntry] = []
    exfiltration_indicators: List[AnomalyEntry] = []


class ProtocolMetrics(BaseModel):
    tls_failures: List[AnomalyEntry] = []
    dns_errors: List[AnomalyEntry] = []
    http_error_rate_pct: float = 0.0
    http_status_counts: Dict[str, int] = {}
    connection_resets: List[AnomalyEntry] = []
    total_connections: int = 0
    reset_rate_pct: float = 0.0


class SummaryDiagnosis(BaseModel):
    headline: str
    severity: str  # "critical", "warning", "info", "clean"
    details: List[str] = []


class AnalysisReport(BaseModel):
    analysis_id: str = ""
    filename: str
    total_packets: int
    capture_duration_sec: float
    start_time: Optional[float] = None
    unique_ips: List[str] = []
    diagnoses: List[SummaryDiagnosis] = []
    performance: PerformanceMetrics
    security: SecurityMetrics
    protocol: ProtocolMetrics
    # Extended metrics — all Optional so older saved reports remain loadable
    flow: Optional[Any] = None
    fingerprint: Optional[Any] = None
    tls_deep: Optional[Any] = None
    arp: Optional[Any] = None
    ioc: Optional[Any] = None
    geo: Optional[Any] = None
    beacons: Optional[Any] = None
    rst_forensics: Optional[Any] = None
