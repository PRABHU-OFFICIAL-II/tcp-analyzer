import { useState } from "react";

function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

const PROTO_STYLE = {
  TCP:   { bg: "#eff6ff", color: "#2563eb", border: "#bfdbfe" },
  UDP:   { bg: "#f5f3ff", color: "#7c3aed", border: "#ddd6fe" },
  OTHER: { bg: "#f8fafc", color: "#475569", border: "#e2e8f0" },
};

const TH = { textAlign: "left", padding: "0.55rem 0.75rem", color: "#64748b", fontWeight: 600, fontSize: "0.78rem" };
const TD_MONO = { padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500, fontSize: "0.8rem" };
const TD      = { padding: "0.5rem 0.75rem", color: "#475569", fontSize: "0.8rem" };
const ROW_ODD  = { borderBottom: "1px solid #f1f5f9", background: "#fff" };
const ROW_EVEN = { borderBottom: "1px solid #f1f5f9", background: "#fafbfc" };

export default function FlowTable({ flows = [], topTalkers = [], matrix = [] }) {
  const [tab, setTab] = useState("flows");

  const tabStyle = (active) => ({
    padding: "0.45rem 1rem", cursor: "pointer",
    background: active ? "#eff6ff" : "transparent",
    border: "none", borderRadius: "7px",
    color: active ? "#2563eb" : "#64748b",
    fontWeight: active ? 600 : 400, fontSize: "0.82rem",
    transition: "all 0.15s",
  });

  return (
    <div>
      <div style={{
        display: "flex", gap: "0.25rem", marginBottom: "1.25rem",
        background: "#f8fafc", borderRadius: "10px", padding: "0.3rem",
        border: "1px solid #e2e8f0",
      }}>
        {[["flows", "Flows"], ["talkers", "Top Talkers"], ["matrix", "Conversation Matrix"]].map(([id, label]) => (
          <button key={id} style={tabStyle(tab === id)} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {tab === "flows" && (
        <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                {["Src IP", "Dst IP", "Src Port", "Dst Port", "Proto", "Packets", "Bytes", "Duration"].map(h => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 && (
                <tr><td colSpan={8} style={{ padding: "1.5rem", textAlign: "center", color: "#94a3b8", fontStyle: "italic" }}>No flows recorded</td></tr>
              )}
              {flows.map((f, i) => {
                const ps = PROTO_STYLE[f.protocol] || PROTO_STYLE.OTHER;
                return (
                  <tr key={i} style={i % 2 === 0 ? ROW_ODD : ROW_EVEN}>
                    <td style={TD_MONO}>{f.src_ip}</td>
                    <td style={TD_MONO}>{f.dst_ip}</td>
                    <td style={{ ...TD, fontFamily: "monospace" }}>{f.src_port}</td>
                    <td style={{ ...TD, fontFamily: "monospace" }}>{f.dst_port}</td>
                    <td style={{ padding: "0.5rem 0.75rem" }}>
                      <span style={{
                        background: ps.bg, color: ps.color,
                        border: `1px solid ${ps.border}`,
                        fontSize: "0.72rem", fontWeight: 700,
                        padding: "2px 7px", borderRadius: "4px",
                      }}>{f.protocol}</span>
                    </td>
                    <td style={TD}>{f.packets}</td>
                    <td style={{ ...TD, fontWeight: 600, color: "#1e293b" }}>{fmtBytes(f.bytes)}</td>
                    <td style={TD}>{f.duration_sec}s</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {tab === "talkers" && (
        <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                {["IP Address", "Sent", "Received", "Total"].map(h => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {topTalkers.length === 0 && (
                <tr><td colSpan={4} style={{ padding: "1.5rem", textAlign: "center", color: "#94a3b8", fontStyle: "italic" }}>No data</td></tr>
              )}
              {topTalkers.map((t, i) => (
                <tr key={i} style={i % 2 === 0 ? ROW_ODD : ROW_EVEN}>
                  <td style={TD_MONO}>{t.ip}</td>
                  <td style={{ ...TD, color: "#dc2626", fontWeight: 600 }}>{fmtBytes(t.bytes_sent)}</td>
                  <td style={{ ...TD, color: "#16a34a", fontWeight: 600 }}>{fmtBytes(t.bytes_recv)}</td>
                  <td style={{ ...TD, color: "#1e293b", fontWeight: 700 }}>{fmtBytes(t.total_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "matrix" && (
        <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                {["Host A", "Host B", "Total Bytes"].map(h => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matrix.length === 0 && (
                <tr><td colSpan={3} style={{ padding: "1.5rem", textAlign: "center", color: "#94a3b8", fontStyle: "italic" }}>No data</td></tr>
              )}
              {matrix.map((m, i) => (
                <tr key={i} style={i % 2 === 0 ? ROW_ODD : ROW_EVEN}>
                  <td style={TD_MONO}>{m.src}</td>
                  <td style={TD_MONO}>{m.dst}</td>
                  <td style={{ ...TD, fontWeight: 700, color: "#1e293b" }}>{fmtBytes(m.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
