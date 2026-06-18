export default function TLSDeepPanel({ connections = [], weakCipherCount = 0, deprecatedCount = 0, uniqueJa3 = [] }) {
  if (!connections.length) return (
    <p style={{ color: "#94a3b8", fontStyle: "italic", fontSize: "0.875rem" }}>No TLS ClientHello packets found</p>
  );

  const statCards = [
    { label: "TLS Connections", value: connections.length, color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
    { label: "Weak Ciphers", value: weakCipherCount, color: weakCipherCount > 0 ? "#d97706" : "#16a34a", bg: weakCipherCount > 0 ? "#fffbeb" : "#f0fdf4", border: weakCipherCount > 0 ? "#fde68a" : "#bbf7d0" },
    { label: "Deprecated Versions", value: deprecatedCount, color: deprecatedCount > 0 ? "#dc2626" : "#16a34a", bg: deprecatedCount > 0 ? "#fef2f2" : "#f0fdf4", border: deprecatedCount > 0 ? "#fecaca" : "#bbf7d0" },
    { label: "Unique JA3", value: uniqueJa3.length, color: "#7c3aed", bg: "#f5f3ff", border: "#ddd6fe" },
  ];

  return (
    <div>
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        {statCards.map(c => (
          <div key={c.label} style={{
            background: c.bg, border: `1px solid ${c.border}`,
            borderRadius: "10px", padding: "0.75rem 1.25rem",
            minWidth: "120px",
          }}>
            <div style={{ color: "#64748b", fontSize: "0.72rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.25rem" }}>{c.label}</div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, color: c.color }}>{c.value}</div>
          </div>
        ))}
      </div>

      <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead>
            <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
              {["Src IP", "Dst IP:Port", "TLS Version", "JA3 Hash", "Flags"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {connections.map((c, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{c.src_ip}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{c.dst_ip}:{c.dst_port}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <span style={{
                    background: c.deprecated_version ? "#fef2f2" : "#f0fdf4",
                    color: c.deprecated_version ? "#dc2626" : "#16a34a",
                    border: `1px solid ${c.deprecated_version ? "#fecaca" : "#bbf7d0"}`,
                    fontWeight: 600, fontSize: "0.75rem",
                    padding: "2px 7px", borderRadius: "4px",
                  }}>{c.tls_version_offered}</span>
                </td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#64748b", fontFamily: "monospace", fontSize: "0.7rem" }}>{c.ja3}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  {c.deprecated_version && (
                    <span style={{ display: "inline-block", marginRight: 3, padding: "1px 6px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700, background: "#fef2f2", color: "#dc2626", border: "1px solid #fecaca" }}>DEPRECATED</span>
                  )}
                  {c.weak_ciphers?.length > 0 && (
                    <span style={{ display: "inline-block", marginRight: 3, padding: "1px 6px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700, background: "#fffbeb", color: "#d97706", border: "1px solid #fde68a" }}>WEAK CIPHER</span>
                  )}
                  {!c.deprecated_version && !c.weak_ciphers?.length && (
                    <span style={{ display: "inline-block", padding: "1px 6px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700, background: "#f0fdf4", color: "#16a34a", border: "1px solid #bbf7d0" }}>OK</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
