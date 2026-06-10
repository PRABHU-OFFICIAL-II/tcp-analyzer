import json
from pathlib import Path

_PATH = Path(__file__).parent.parent / "data" / "thresholds.json"

_defaults = {
    "performance": {
        "retransmission_rate_warning": 2.0,
        "high_handshake_ms": 200,
        "high_delta_ms": 1000,
    },
    "security": {
        "port_scan_threshold": 20,
        "exfil_bytes_threshold": 5_000_000,
        "large_dns_payload": 512,
    },
    "protocol": {"high_dns_latency_ms": 500},
    "beacon": {"min_connections": 5, "max_cv": 0.3},
    "rst_forensics": {"nat_idle_threshold_sec": 30.0},
    "engine": {"max_packets": 500_000},
}


def _load() -> dict:
    try:
        data = json.loads(_PATH.read_text())
        merged = {}
        for section, vals in _defaults.items():
            merged[section] = {**vals, **data.get(section, {})}
        return merged
    except Exception:
        return _defaults


_cfg: dict = _load()


def get(section: str, key: str):
    return _cfg.get(section, _defaults.get(section, {})).get(
        key, _defaults.get(section, {}).get(key)
    )


def reload():
    global _cfg
    _cfg = _load()


def all_thresholds() -> dict:
    return _cfg
