export default function BeaconTable({ beacons = [] }) {
  if (!beacons.length) return <p style={{ color: "#4b5563", fontStyle: "italic", fontSize: "0.875rem" }}>No beaconing activity detected</p>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #2d3148" }}>
            {["Src IP", "Dst IP", "Port", "Connections", "Avg Interval", "CV (regularity)", "Risk"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {beacons.map((b, i) => {
            const risk = b.cv < 0.05 ? "CRITICAL" : b.cv < 0.15 ? "HIGH" : "MEDIUM";
            const riskColor = b.cv < 0.05 ? "#ef4444" : b.cv < 0.15 ? "#f59e0b" : "#facc15";
            return (
              <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                <td style={{ padding: "0.5rem 0.75rem", color: "#cbd5e1", fontFamily: "monospace" }}>{b.src_ip}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#cbd5e1", fontFamily: "monospace" }}>{b.dst_ip}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{b.dst_port}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#e2e8f0", fontWeight: 600 }}>{b.connection_count}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{b.avg_interval_sec}s</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{b.cv}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>
                  <span style={{ color: riskColor, fontWeight: 700, fontSize: "0.75rem" }}>{risk}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
