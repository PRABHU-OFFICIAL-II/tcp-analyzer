const SEVERITY_COLOR = {
  critical: "#ef4444",
  warning: "#f59e0b",
  info: "#3b82f6",
};

export default function AnomalyTable({ title, entries, emptyMessage = "None detected" }) {
  return (
    <div style={{ marginBottom: "2rem" }}>
      <h3 style={{ color: "#94a3b8", fontSize: "0.85rem", fontWeight: 600,
        textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "0.75rem" }}>
        {title}
      </h3>
      {entries.length === 0 ? (
        <p style={{ color: "#4b5563", fontSize: "0.875rem", fontStyle: "italic" }}>{emptyMessage}</p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2d3148" }}>
                {["#", "Src IP", "Dst IP", "Port", "Severity", "Detail"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem",
                    color: "#64748b", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#475569" }}>{e.packet_number ?? "—"}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#cbd5e1", fontFamily: "monospace" }}>{e.src_ip}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#cbd5e1", fontFamily: "monospace" }}>{e.dst_ip}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8", fontFamily: "monospace" }}>
                    {e.src_port != null ? `${e.src_port}→${e.dst_port}` : "—"}
                  </td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>
                    <span style={{ color: SEVERITY_COLOR[e.severity] || "#94a3b8",
                      fontWeight: 700, fontSize: "0.75rem", textTransform: "uppercase" }}>
                      {e.severity}
                    </span>
                  </td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8", maxWidth: "400px" }}>{e.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
