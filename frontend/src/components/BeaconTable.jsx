export default function BeaconTable({ beacons = [] }) {
  if (!beacons.length) return (
    <p style={{ color: "#16a34a", fontStyle: "italic", fontSize: "0.875rem", fontWeight: 500 }}>
      No beaconing activity detected
    </p>
  );

  return (
    <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
        <thead>
          <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
            {["Src IP", "Dst IP", "Port", "Connections", "Avg Interval", "CV (regularity)", "Risk"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {beacons.map((b, i) => {
            const risk = b.cv < 0.05 ? "CRITICAL" : b.cv < 0.15 ? "HIGH" : "MEDIUM";
            const riskStyle = b.cv < 0.05
              ? { bg: "#fef2f2", color: "#dc2626", border: "#fecaca" }
              : b.cv < 0.15
              ? { bg: "#fffbeb", color: "#d97706", border: "#fde68a" }
              : { bg: "#fefce8", color: "#ca8a04", border: "#fef08a" };
            return (
              <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{b.src_ip}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{b.dst_ip}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#475569", fontFamily: "monospace" }}>{b.dst_port}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontWeight: 600 }}>{b.connection_count}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#475569" }}>{b.avg_interval_sec}s</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#475569" }}>{b.cv}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <span style={{
                    background: riskStyle.bg, color: riskStyle.color,
                    border: `1px solid ${riskStyle.border}`,
                    fontWeight: 700, fontSize: "0.7rem",
                    padding: "2px 7px", borderRadius: "4px",
                  }}>{risk}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
