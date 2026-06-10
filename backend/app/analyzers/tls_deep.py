import hashlib
import struct
from ..models.extended_report import TLSDeepMetrics, JA3Entry

# Cipher suites considered weak or export-grade
WEAK_CIPHERS = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",   # not weak, but CBC
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    0x0064: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
    0xFF85: "LEGACY_GOST",
}

TLS_VERSION_NAMES = {
    (3, 0): "SSL 3.0",
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}

DEPRECATED_VERSIONS = {(3, 0), (3, 1), (3, 2)}  # SSL3, TLS 1.0, TLS 1.1

# GREASE values to ignore in JA3
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
          0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def _parse_client_hello(raw: bytes):
    """Return (version_tuple, cipher_list, ext_types, curves, point_formats) or None."""
    try:
        # TLS record header: content_type(1) + version(2) + length(2)
        if len(raw) < 5 or raw[0] != 22:
            return None
        rec_version = (raw[1], raw[2])
        if rec_version not in TLS_VERSION_NAMES and rec_version != (3, 1):
            return None

        # Handshake header: type(1) + length(3)
        if raw[5] != 1:  # not ClientHello
            return None

        offset = 9  # skip to ClientHello body
        if offset + 2 > len(raw):
            return None
        client_version = (raw[offset], raw[offset + 1])
        offset += 2 + 32  # skip version + random

        # Session ID
        if offset >= len(raw):
            return None
        sid_len = raw[offset]
        offset += 1 + sid_len

        # Cipher suites
        if offset + 2 > len(raw):
            return None
        cs_len = struct.unpack("!H", raw[offset:offset+2])[0]
        offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if offset + 2 > len(raw):
                break
            c = struct.unpack("!H", raw[offset:offset+2])[0]
            if c not in GREASE:
                ciphers.append(c)
            offset += 2

        # Compression methods
        if offset >= len(raw):
            return None
        comp_len = raw[offset]
        offset += 1 + comp_len

        # Extensions
        ext_types, curves, point_formats = [], [], []
        if offset + 2 <= len(raw):
            exts_total = struct.unpack("!H", raw[offset:offset+2])[0]
            offset += 2
            end = offset + exts_total
            while offset + 4 <= end and offset + 4 <= len(raw):
                ext_type = struct.unpack("!H", raw[offset:offset+2])[0]
                ext_len = struct.unpack("!H", raw[offset+2:offset+4])[0]
                offset += 4
                if ext_type not in GREASE:
                    ext_types.append(ext_type)
                if ext_type == 10 and offset + ext_len <= len(raw):  # supported_groups
                    gl = struct.unpack("!H", raw[offset:offset+2])[0]
                    for j in range(2, 2 + gl, 2):
                        if offset + j + 2 <= len(raw):
                            g = struct.unpack("!H", raw[offset+j:offset+j+2])[0]
                            if g not in GREASE:
                                curves.append(g)
                if ext_type == 11 and offset + ext_len <= len(raw):  # ec_point_formats
                    pfl = raw[offset]
                    for j in range(1, 1 + pfl):
                        if offset + j < len(raw):
                            point_formats.append(raw[offset + j])
                offset += ext_len

        return client_version, ciphers, ext_types, curves, point_formats
    except Exception:
        return None


def _ja3_string(version, ciphers, ext_types, curves, point_formats) -> str:
    v = version[0] * 256 + version[1]
    return "-".join([
        str(v),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_types),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in point_formats),
    ])


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def analyze_tls_deep(packets) -> TLSDeepMetrics:
    metrics = TLSDeepMetrics()
    seen_flows: set = set()

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP") and pkt.haslayer("Raw")):
            continue
        ip = pkt["IP"]
        tcp = pkt["TCP"]
        raw = bytes(pkt["Raw"])

        parsed = _parse_client_hello(raw)
        if parsed is None:
            continue

        flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        if flow_key in seen_flows:
            continue
        seen_flows.add(flow_key)

        version, ciphers, ext_types, curves, point_formats = parsed
        version_str = TLS_VERSION_NAMES.get(version, f"Unknown ({version[0]}.{version[1]})")
        deprecated = version in DEPRECATED_VERSIONS

        weak = [WEAK_CIPHERS[c] for c in ciphers if c in WEAK_CIPHERS]

        ja3_str = _ja3_string(version, ciphers, ext_types, curves, point_formats)
        ja3_hash = _md5(ja3_str)

        metrics.connections.append(JA3Entry(
            src_ip=ip.src,
            dst_ip=ip.dst,
            dst_port=tcp.dport,
            ja3=ja3_hash,
            tls_version_offered=version_str,
            cipher_suites=ciphers,
            weak_ciphers=weak,
            deprecated_version=deprecated,
        ))

    metrics.weak_cipher_count = sum(len(c.weak_ciphers) for c in metrics.connections)
    metrics.deprecated_version_count = sum(1 for c in metrics.connections if c.deprecated_version)
    metrics.unique_ja3 = list({c.ja3 for c in metrics.connections})

    return metrics
