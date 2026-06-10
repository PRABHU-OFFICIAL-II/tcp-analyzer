import os
import tempfile
from fastapi import APIRouter, UploadFile, File, HTTPException
from ..analyzers.engine import run_analysis
from ..models.extended_report import CompareReport, MetricDiff

router = APIRouter()


def _scalar(report, *path):
    obj = report
    for key in path:
        obj = getattr(obj, key, None)
        if obj is None:
            return None
    return obj


def _diff(label, v1, v2, lower_is_better=True) -> MetricDiff:
    delta = None
    direction = "neutral"
    if v1 is not None and v2 is not None:
        try:
            delta = round(float(v2) - float(v1), 4)
            if delta == 0:
                direction = "neutral"
            elif lower_is_better:
                direction = "improved" if delta < 0 else "degraded"
            else:
                direction = "improved" if delta > 0 else "degraded"
        except (TypeError, ValueError):
            pass
    return MetricDiff(label=label, file1_value=v1, file2_value=v2, delta=delta, direction=direction)


@router.post("/compare", response_model=CompareReport)
async def compare_pcaps(
    file1: UploadFile = File(...),
    file2: UploadFile = File(...),
):
    reports = []
    files = [file1, file2]
    tmp_paths = []

    try:
        for f in files:
            if not f.filename.endswith((".pcap", ".pcapng", ".cap")):
                raise HTTPException(status_code=400, detail=f"{f.filename} is not a valid PCAP file.")
            contents = await f.read()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(contents)
                tmp_paths.append(tmp.name)

        for i, path in enumerate(tmp_paths):
            try:
                r = run_analysis(path, files[i].filename, save=False)
                reports.append(r)
            except Exception as e:
                raise HTTPException(status_code=422, detail=f"Analysis of {files[i].filename} failed: {e}")
    finally:
        for p in tmp_paths:
            try:
                os.unlink(p)
            except Exception:
                pass

    r1, r2 = reports

    diffs = [
        _diff("Total Packets",          r1.total_packets,                           r2.total_packets,                           lower_is_better=False),
        _diff("Capture Duration (s)",   r1.capture_duration_sec,                    r2.capture_duration_sec,                    lower_is_better=False),
        _diff("Retransmission Rate (%)", r1.performance.retransmission_rate_pct,    r2.performance.retransmission_rate_pct),
        _diff("Retransmission Count",   r1.performance.retransmission_count,        r2.performance.retransmission_count),
        _diff("Avg Handshake (ms)",     r1.performance.avg_handshake_ms,            r2.performance.avg_handshake_ms),
        _diff("Max Handshake (ms)",     r1.performance.max_handshake_ms,            r2.performance.max_handshake_ms),
        _diff("Zero Window Count",      r1.performance.zero_window_count,           r2.performance.zero_window_count),
        _diff("Avg App Delta (ms)",     r1.performance.avg_delta_ms,                r2.performance.avg_delta_ms),
        _diff("HTTP Error Rate (%)",    r1.protocol.http_error_rate_pct,            r2.protocol.http_error_rate_pct),
        _diff("Reset Rate (%)",         r1.protocol.reset_rate_pct,                 r2.protocol.reset_rate_pct),
        _diff("TLS Failures",           len(r1.protocol.tls_failures),              len(r2.protocol.tls_failures)),
        _diff("DNS Errors",             len(r1.protocol.dns_errors),                len(r2.protocol.dns_errors)),
        _diff("Security Findings",      _count_security(r1),                        _count_security(r2)),
        _diff("Beaconing Flows",        len(r1.beacons.beacons) if r1.beacons else 0, len(r2.beacons.beacons) if r2.beacons else 0),
        _diff("IOC Matches",            len(r1.ioc.matches) if r1.ioc else 0,       len(r2.ioc.matches) if r2.ioc else 0),
        _diff("Unique Flows",           r1.flow.total_flows if r1.flow else 0,      r2.flow.total_flows if r2.flow else 0, lower_is_better=False),
    ]

    return CompareReport(
        file1_name=file1.filename,
        file2_name=file2.filename,
        diffs=diffs,
        file1_diagnoses=[d.model_dump() for d in r1.diagnoses],
        file2_diagnoses=[d.model_dump() for d in r2.diagnoses],
    )


def _count_security(report) -> int:
    s = report.security
    return (len(s.port_scan_sources) + len(s.cleartext_credentials) +
            len(s.protocol_port_mismatches) + len(s.exfiltration_indicators))
