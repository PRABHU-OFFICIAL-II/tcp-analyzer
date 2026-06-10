import { useState } from "react";

function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

const PROTO_COLOR = { TCP: "#60a5fa", UDP: "#a78bfa", OTHER: "#94a3b8" };

export default function FlowTable({ flows = [], topTalkers = [], matrix = [] }) {
  const [tab, setTab] = useState("flows");

  const tabStyle = (active) => ({
    padding: "0.4rem 0.9rem", cursor: "pointer",
    background: "none", border: "none",
    color: active ? "#60a5fa" : "#64748b",
    borderBottom: active ? "2px solid #60a5fa" : "2px solid transparent",
    fontWeight: active ? 600 : 400, fontSize: "0.82rem",
  });

  return (
    <div>
      <div style={{ display: "flex", gap: "0.25rem", borderBottom: "1px solid #2d3148", marginBottom: "1rem" }}>
        {[["flows", "Flows"], ["talkers", "Top Talkers"], ["matrix", "Conversation Matrix"]].map(([id, label]) => (
          <button key={id} style={tabStyle(tab === id)} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {tab === "flows" && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2d3148" }}>
                {["Src IP", "Dst IP", "Src Port", "Dst Port", "Proto", "Packets", "Bytes", "Duration"].map(h => (
                  <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.6rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {flows.map((f, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{f.src_ip}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{f.dst_ip}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#94a3b8" }}>{f.src_port}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#94a3b8" }}>{f.dst_port}</td>
                  <td style={{ padding: "0.45rem 0.6rem" }}>
                    <span style={{ color: PROTO_COLOR[f.protocol] || "#94a3b8", fontWeight: 600 }}>{f.protocol}</span>
                  </td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#94a3b8" }}>{f.packets}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#e2e8f0", fontWeight: 500 }}>{fmtBytes(f.bytes)}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#64748b" }}>{f.duration_sec}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "talkers" && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2d3148" }}>
                {["IP Address", "Sent", "Received", "Total"].map(h => (
                  <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.6rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {topTalkers.map((t, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{t.ip}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#f87171" }}>{fmtBytes(t.bytes_sent)}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#4ade80" }}>{fmtBytes(t.bytes_recv)}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#e2e8f0", fontWeight: 600 }}>{fmtBytes(t.total_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "matrix" && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #2d3148" }}>
                {["Host A", "Host B", "Total Bytes"].map(h => (
                  <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.6rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {matrix.map((m, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{m.src}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1", fontFamily: "monospace" }}>{m.dst}</td>
                  <td style={{ padding: "0.45rem 0.6rem", color: "#e2e8f0", fontWeight: 600 }}>{fmtBytes(m.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
