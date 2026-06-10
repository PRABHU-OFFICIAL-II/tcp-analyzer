const s = {
  badge: (color) => ({
    display: "inline-block", padding: "1px 7px", borderRadius: "4px",
    fontSize: "0.7rem", fontWeight: 700, marginRight: "4px",
    background: color + "22", color, border: `1px solid ${color}`,
  }),
};

export default function TLSDeepPanel({ connections = [], weakCipherCount = 0, deprecatedCount = 0, uniqueJa3 = [] }) {
  if (!connections.length) return <p style={{ color: "#4b5563", fontStyle: "italic", fontSize: "0.875rem" }}>No TLS ClientHello packets found</p>;
  return (
    <div>
      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        <div style={{ background: "#1e2130", border: "1px solid #2d3148", borderRadius: "10px", padding: "0.75rem 1.25rem" }}>
          <div style={{ color: "#64748b", fontSize: "0.75rem", textTransform: "uppercase", marginBottom: "0.25rem" }}>TLS Connections</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "#60a5fa" }}>{connections.length}</div>
        </div>
        <div style={{ background: "#1e2130", border: "1px solid #2d3148", borderRadius: "10px", padding: "0.75rem 1.25rem" }}>
          <div style={{ color: "#64748b", fontSize: "0.75rem", textTransform: "uppercase", marginBottom: "0.25rem" }}>Weak Ciphers</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: weakCipherCount > 0 ? "#f59e0b" : "#22c55e" }}>{weakCipherCount}</div>
        </div>
        <div style={{ background: "#1e2130", border: "1px solid #2d3148", borderRadius: "10px", padding: "0.75rem 1.25rem" }}>
          <div style={{ color: "#64748b", fontSize: "0.75rem", textTransform: "uppercase", marginBottom: "0.25rem" }}>Deprecated Versions</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: deprecatedCount > 0 ? "#ef4444" : "#22c55e" }}>{deprecatedCount}</div>
        </div>
        <div style={{ background: "#1e2130", border: "1px solid #2d3148", borderRadius: "10px", padding: "0.75rem 1.25rem" }}>
          <div style={{ color: "#64748b", fontSize: "0.75rem", textTransform: "uppercase", marginBottom: "0.25rem" }}>Unique JA3</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "#a78bfa" }}>{uniqueJa3.length}</div>
        </div>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #2d3148" }}>
              {["Src IP", "Dst IP:Port", "TLS Version", "JA3 Hash", "Flags"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.6rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {connections.map((c, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{c.src_ip}</td>
                <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{c.dst_ip}:{c.dst_port}</td>
                <td style={{ padding: "0.45rem 0.6rem" }}>
                  <span style={{ color: c.deprecated_version ? "#ef4444" : "#4ade80", fontWeight: 600 }}>{c.tls_version_offered}</span>
                </td>
                <td style={{ padding: "0.45rem 0.6rem", color: "#94a3b8", fontFamily: "monospace", fontSize: "0.7rem" }}>{c.ja3}</td>
                <td style={{ padding: "0.45rem 0.6rem" }}>
                  {c.deprecated_version && <span style={s.badge("#ef4444")}>DEPRECATED</span>}
                  {c.weak_ciphers?.length > 0 && <span style={s.badge("#f59e0b")}>WEAK CIPHER</span>}
                  {!c.deprecated_version && !c.weak_ciphers?.length && <span style={{ color: "#22c55e", fontSize: "0.75rem" }}>OK</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
