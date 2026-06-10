const OS_COLOR = {
  "Windows": "#60a5fa",
  "Linux / macOS": "#4ade80",
  "Network Device (Cisco/Juniper)": "#f59e0b",
  "Older Windows (9x/NT)": "#f87171",
};

export default function FingerprintPanel({ hosts = [] }) {
  if (!hosts.length) return <p style={{ color: "#4b5563", fontStyle: "italic", fontSize: "0.875rem" }}>No host data</p>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #2d3148" }}>
            {["IP Address", "OS Guess", "TTL", "Detected Applications"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {hosts.map((h, i) => {
            const color = Object.entries(OS_COLOR).find(([k]) => h.os_guess.startsWith(k))?.[1] || "#94a3b8";
            return (
              <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                <td style={{ padding: "0.5rem 0.75rem", color: "#cbd5e1", fontFamily: "monospace" }}>{h.ip}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <span style={{ color, fontWeight: 600 }}>{h.os_guess}</span>
                </td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{h.ttl_observed}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>
                  {h.detected_apps.length ? h.detected_apps.join(", ") : <span style={{ color: "#475569" }}>—</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
