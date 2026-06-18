const SEVERITY_COLOR = {
  critical: "#dc2626",
  warning:  "#d97706",
  info:     "#2563eb",
};

const SEVERITY_BG = {
  critical: "#fef2f2",
  warning:  "#fffbeb",
  info:     "#eff6ff",
};

export default function AnomalyTable({ title, entries, emptyMessage = "None detected" }) {
  return (
    <div style={{ marginBottom: "2rem" }}>
      <h3 style={{
        color: "#475569", fontSize: "0.78rem", fontWeight: 700,
        textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "0.75rem",
      }}>
        {title}
        {entries.length > 0 && (
          <span style={{ marginLeft: "0.5rem", background: "#f1f5f9", color: "#64748b",
            fontSize: "0.72rem", padding: "1px 7px", borderRadius: "10px", fontWeight: 600 }}>
            {entries.length}
          </span>
        )}
      </h3>
      {entries.length === 0 ? (
        <p style={{ color: "#94a3b8", fontSize: "0.85rem", fontStyle: "italic" }}>{emptyMessage}</p>
      ) : (
        <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0",
          boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                {["#", "Src IP", "Dst IP", "Port", "Severity", "Detail"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem",
                    color: "#64748b", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} style={{
                  borderBottom: "1px solid #f1f5f9",
                  background: i % 2 === 0 ? "#fff" : "#fafbfc",
                }}>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8", fontFamily: "monospace" }}>{e.packet_number ?? "—"}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{e.src_ip}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{e.dst_ip}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#64748b", fontFamily: "monospace" }}>
                    {e.src_port != null ? `${e.src_port}→${e.dst_port}` : "—"}
                  </td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>
                    <span style={{
                      background: SEVERITY_BG[e.severity] || "#f8fafc",
                      color: SEVERITY_COLOR[e.severity] || "#64748b",
                      fontWeight: 700, fontSize: "0.68rem", textTransform: "uppercase",
                      padding: "2px 7px", borderRadius: "4px",
                    }}>
                      {e.severity}
                    </span>
                  </td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#475569", maxWidth: "400px" }}>{e.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
