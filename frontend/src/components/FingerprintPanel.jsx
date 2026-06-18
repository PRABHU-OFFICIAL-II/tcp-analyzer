const OS_STYLE = {
  "Windows":                         { bg: "#eff6ff", color: "#2563eb", border: "#bfdbfe" },
  "Linux / macOS":                   { bg: "#f0fdf4", color: "#16a34a", border: "#bbf7d0" },
  "Network Device (Cisco/Juniper)":  { bg: "#fffbeb", color: "#d97706", border: "#fde68a" },
  "Older Windows (9x/NT)":           { bg: "#fef2f2", color: "#dc2626", border: "#fecaca" },
};

export default function FingerprintPanel({ hosts = [] }) {
  if (!hosts.length) return (
    <p style={{ color: "#94a3b8", fontStyle: "italic", fontSize: "0.875rem" }}>No host fingerprint data available</p>
  );

  return (
    <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
        <thead>
          <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
            {["IP Address", "OS Guess", "TTL", "Detected Applications"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {hosts.map((h, i) => {
            const style = Object.entries(OS_STYLE).find(([k]) => h.os_guess.startsWith(k))?.[1]
              || { bg: "#f8fafc", color: "#475569", border: "#e2e8f0" };
            return (
              <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{h.ip}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <span style={{
                    background: style.bg, color: style.color,
                    border: `1px solid ${style.border}`,
                    fontSize: "0.75rem", fontWeight: 600,
                    padding: "2px 8px", borderRadius: "5px",
                  }}>{h.os_guess}</span>
                </td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#64748b", fontFamily: "monospace" }}>{h.ttl_observed}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#475569" }}>
                  {h.detected_apps.length
                    ? h.detected_apps.map((app, j) => (
                        <span key={j} style={{
                          display: "inline-block", marginRight: "4px", marginBottom: "2px",
                          background: "#f1f5f9", color: "#334155",
                          fontSize: "0.72rem", fontWeight: 500,
                          padding: "1px 6px", borderRadius: "4px",
                          border: "1px solid #e2e8f0",
                        }}>{app}</span>
                      ))
                    : <span style={{ color: "#94a3b8" }}>—</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
