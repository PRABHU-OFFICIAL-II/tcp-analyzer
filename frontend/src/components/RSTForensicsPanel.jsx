import { useState } from "react";
import { ChevronDown, ChevronRight, List, AlignLeft } from "lucide-react";

const CAUSE_STYLE = {
  PORT_CLOSED:          { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  FIREWALL_REJECTION:   { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  TLS_REJECTION:        { color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  RESOURCE_EXHAUSTION:  { color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  APP_CRASH:            { color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  NAT_TIMEOUT:          { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  APP_REFUSED:          { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  MIDDLEBOX_INJECTION:  { color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  MID_SESSION:          { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  UNKNOWN:              { color: "#475569", bg: "#f8fafc", border: "#e2e8f0" },
};

const SEV_STYLE = {
  critical: { bg: "#fef2f2", border: "#fecaca", color: "#dc2626", cardBg: "#fff" },
  warning:  { bg: "#fffbeb", border: "#fde68a", color: "#d97706", cardBg: "#fff" },
  info:     { bg: "#eff6ff", border: "#bfdbfe", color: "#2563eb", cardBg: "#fff" },
};

const CONF_STYLE = {
  high:   { color: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
  medium: { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  low:    { color: "#64748b", bg: "#f8fafc", border: "#e2e8f0" },
};

function fmtTs(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 });
}

function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

function TraceTable({ steps, title, emptyMsg }) {
  const isFull = title === "Full Trace";
  return (
    <div style={{ marginTop: "1rem", fontSize: "0.78rem" }}>
      <div style={{ color: "#475569", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.75rem", fontSize: "0.72rem" }}>
        {title}
      </div>
      {!steps?.length ? (
        <p style={{ color: "#94a3b8", fontStyle: "italic" }}>{emptyMsg}</p>
      ) : isFull ? (
        <div style={{ overflowX: "auto", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.75rem" }}>
            <thead>
              <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                {["Pkt #", "Time", "Flags", "Source", "Destination", "Bytes", "Detail"].map(h => (
                  <th key={h} style={{ padding: "0.4rem 0.6rem", textAlign: "left", color: "#64748b", fontWeight: 600, whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {steps.map((step, i) => {
                const isRST = step.flags.includes("RST");
                const isSYN = step.flags === "SYN";
                const rowBg = isRST ? "#fff5f5" : isSYN ? "#f0fff4" : (i % 2 === 0 ? "#fff" : "#fafbfc");
                const flagColor = isRST ? "#dc2626" : isSYN ? "#16a34a" : "#4f46e5";
                const textColor = isRST ? "#dc2626" : "#475569";
                return (
                  <tr key={i} style={{ background: rowBg, borderBottom: "1px solid #f1f5f9" }}>
                    <td style={{ padding: "0.35rem 0.6rem", color: "#64748b", fontFamily: "monospace" }}>#{step.packet_number}</td>
                    <td style={{ padding: "0.35rem 0.6rem", color: "#64748b", whiteSpace: "nowrap" }}>{fmtTs(step.timestamp)}</td>
                    <td style={{ padding: "0.35rem 0.6rem", fontFamily: "monospace", fontWeight: 700, color: flagColor, whiteSpace: "nowrap" }}>{step.flags}</td>
                    <td style={{ padding: "0.35rem 0.6rem", fontFamily: "monospace", color: "#1e293b", fontWeight: 500, whiteSpace: "nowrap" }}>{step.src_ip}:{step.src_port}</td>
                    <td style={{ padding: "0.35rem 0.6rem", fontFamily: "monospace", color: "#1e293b", fontWeight: 500, whiteSpace: "nowrap" }}>{step.dst_ip}:{step.dst_port}</td>
                    <td style={{ padding: "0.35rem 0.6rem", color: "#64748b", textAlign: "right" }}>{step.payload_bytes > 0 ? fmtBytes(step.payload_bytes) : "—"}</td>
                    <td style={{ padding: "0.35rem 0.6rem", color: textColor, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{step.detail}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ paddingLeft: "1rem", borderLeft: "2px solid #e2e8f0" }}>
          {steps.map((step, i) => {
            const isRST = step.flags.includes("RST");
            return (
              <div key={i} style={{ display: "flex", gap: "0.75rem", marginBottom: "0.5rem", alignItems: "flex-start" }}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0 }}>
                  <div style={{
                    width: 10, height: 10, borderRadius: "50%",
                    background: isRST ? "#dc2626" : "#e2e8f0",
                    border: `2px solid ${isRST ? "#dc2626" : "#cbd5e1"}`,
                    marginTop: 2,
                  }} />
                  {i < steps.length - 1 && <div style={{ width: 2, height: 20, background: "#e2e8f0" }} />}
                </div>
                <div>
                  <span style={{ color: "#94a3b8", fontFamily: "monospace", marginRight: "0.5rem", fontSize: "0.75rem" }}>#{step.packet_number}</span>
                  <span style={{ color: "#94a3b8", marginRight: "0.5rem", fontSize: "0.75rem" }}>{fmtTs(step.timestamp)}</span>
                  <span style={{ color: isRST ? "#dc2626" : "#4f46e5", fontFamily: "monospace", fontWeight: 700, marginRight: "0.5rem" }}>[{step.flags}]</span>
                  <span style={{ color: isRST ? "#dc2626" : "#334155" }}>{step.detail}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RSTCard({ rst }) {
  const [expanded, setExpanded] = useState(false);
  const [traceView, setTraceView] = useState("summary");
  const causeSt = CAUSE_STYLE[rst.root_cause_code] || CAUSE_STYLE.UNKNOWN;
  const sevSt = SEV_STYLE[rst.severity] || SEV_STYLE.info;
  const confSt = CONF_STYLE[rst.confidence] || CONF_STYLE.low;

  return (
    <div style={{
      border: `1px solid ${causeSt.border}`,
      borderLeft: `4px solid ${causeSt.color}`,
      borderRadius: "12px", marginBottom: "1rem",
      background: "#fff",
      boxShadow: "0 1px 4px rgba(0,0,0,0.05)",
      overflow: "hidden",
    }}>
      {/* Header */}
      <div style={{ padding: "0.9rem 1.25rem", cursor: "pointer", display: "flex", alignItems: "flex-start", gap: "0.75rem" }}
        onClick={() => setExpanded(e => !e)}>
        <div style={{ flexShrink: 0, marginTop: 3 }}>
          {expanded ? <ChevronDown size={16} color="#94a3b8" /> : <ChevronRight size={16} color="#94a3b8" />}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap", marginBottom: "0.4rem" }}>
            <span style={{ background: sevSt.bg, border: `1px solid ${sevSt.border}`, color: sevSt.color, fontSize: "0.68rem", fontWeight: 700, padding: "2px 7px", borderRadius: "4px", textTransform: "uppercase" }}>
              {rst.severity}
            </span>
            <span style={{ background: causeSt.bg, border: `1px solid ${causeSt.border}`, color: causeSt.color, fontWeight: 700, fontSize: "0.85rem", padding: "2px 8px", borderRadius: "5px" }}>
              {rst.root_cause}
            </span>
            <span style={{ background: confSt.bg, border: `1px solid ${confSt.border}`, color: confSt.color, fontSize: "0.68rem", fontWeight: 600, padding: "2px 7px", borderRadius: "4px", marginLeft: "auto" }}>
              {rst.confidence.toUpperCase()} CONFIDENCE
            </span>
          </div>
          <div style={{ display: "flex", gap: "1.25rem", flexWrap: "wrap", fontSize: "0.78rem", color: "#64748b" }}>
            <span>
              <span style={{ color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{rst.src_ip}:{rst.src_port}</span>
              <span style={{ margin: "0 0.3rem", color: "#94a3b8" }}>→</span>
              <span style={{ color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{rst.dst_ip}:{rst.dst_port}</span>
            </span>
            <span>Pkt #{rst.rst_packet_number}</span>
            <span>{fmtTs(rst.rst_timestamp)}</span>
            <span>RST by: <span style={{ color: rst.rst_sender === "third_party" ? "#dc2626" : "#475569", fontWeight: rst.rst_sender === "third_party" ? 700 : 400 }}>{rst.rst_sender}</span></span>
            {rst.bytes_exchanged > 0 && <span>{fmtBytes(rst.bytes_exchanged)} exchanged</span>}
            {rst.idle_gap_before_rst_sec != null && (
              <span style={{ color: rst.idle_gap_before_rst_sec > 30 ? "#d97706" : "#64748b" }}>
                {rst.idle_gap_before_rst_sec}s idle before RST
              </span>
            )}
          </div>
          <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.4rem", flexWrap: "wrap" }}>
            {rst.had_tls && <span style={{ background: "#eff6ff", border: "1px solid #bfdbfe", color: "#2563eb", fontSize: "0.68rem", padding: "1px 6px", borderRadius: "4px", fontWeight: 600 }}>TLS</span>}
            {rst.had_zero_window && <span style={{ background: "#fffbeb", border: "1px solid #fde68a", color: "#d97706", fontSize: "0.68rem", padding: "1px 6px", borderRadius: "4px", fontWeight: 600 }}>ZERO WINDOW</span>}
            {rst.had_http_error && <span style={{ background: "#fef2f2", border: "1px solid #fecaca", color: "#dc2626", fontSize: "0.68rem", padding: "1px 6px", borderRadius: "4px", fontWeight: 600 }}>HTTP {rst.http_status_before_rst}</span>}
          </div>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: "0 1.25rem 1.25rem", borderTop: "1px solid #f1f5f9" }}>
          <div style={{ marginTop: "1rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
            <div style={{ background: "#f8fafc", borderRadius: "10px", padding: "0.9rem 1rem", border: "1px solid #e2e8f0" }}>
              <div style={{ color: "#64748b", fontSize: "0.72rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.4rem" }}>Explanation</div>
              <p style={{ color: "#334155", fontSize: "0.83rem", lineHeight: 1.65 }}>{rst.explanation}</p>
            </div>
            <div style={{ background: "#f0fdf4", borderRadius: "10px", padding: "0.9rem 1rem", border: "1px solid #bbf7d0" }}>
              <div style={{ color: "#64748b", fontSize: "0.72rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.4rem" }}>Recommendation</div>
              <p style={{ color: "#15803d", fontSize: "0.83rem", lineHeight: 1.65 }}>{rst.recommendation}</p>
            </div>
          </div>

          {/* Trace toggle */}
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "1.25rem", borderTop: "1px solid #f1f5f9", paddingTop: "1rem" }}>
            <button onClick={() => setTraceView("summary")} style={{
              display: "flex", alignItems: "center", gap: "0.35rem",
              padding: "0.35rem 0.85rem", borderRadius: "7px",
              border: `1px solid ${traceView === "summary" ? "#bfdbfe" : "#e2e8f0"}`,
              cursor: "pointer", fontSize: "0.78rem", fontWeight: 600,
              background: traceView === "summary" ? "#eff6ff" : "#f8fafc",
              color: traceView === "summary" ? "#2563eb" : "#64748b",
              transition: "all 0.15s",
            }}>
              <AlignLeft size={13} /> Summary
            </button>
            <button onClick={() => setTraceView("full")} style={{
              display: "flex", alignItems: "center", gap: "0.35rem",
              padding: "0.35rem 0.85rem", borderRadius: "7px",
              border: `1px solid ${traceView === "full" ? "#bfdbfe" : "#e2e8f0"}`,
              cursor: "pointer", fontSize: "0.78rem", fontWeight: 600,
              background: traceView === "full" ? "#eff6ff" : "#f8fafc",
              color: traceView === "full" ? "#2563eb" : "#64748b",
              transition: "all 0.15s",
            }}>
              <List size={13} /> Full Trace
              {rst.full_trace?.length > 0 && (
                <span style={{ background: "#e2e8f0", color: "#475569", fontSize: "0.68rem", padding: "0 5px", borderRadius: "4px" }}>
                  {rst.full_trace.length}
                </span>
              )}
            </button>
          </div>

          {traceView === "summary"
            ? <TraceTable steps={rst.evidence_chain} title="Evidence Chain" emptyMsg="No significant events recorded." />
            : <TraceTable steps={rst.full_trace} title="Full Trace" emptyMsg="No full trace available." />}
        </div>
      )}
    </div>
  );
}

export default function RSTForensicsPanel({ metrics }) {
  const [filterCode, setFilterCode] = useState("ALL");

  if (!metrics || metrics.total_resets === 0) {
    return <p style={{ color: "#94a3b8", fontStyle: "italic", fontSize: "0.875rem" }}>No RST packets found in this capture.</p>;
  }

  const causes = Object.entries(metrics.by_cause).sort((a, b) => b[1] - a[1]);
  const filtered = filterCode === "ALL"
    ? metrics.classified
    : metrics.classified.filter(r => r.root_cause_code === filterCode);

  return (
    <div>
      {/* Summary tiles */}
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        <div style={{ background: metrics.total_resets > 0 ? "#fef2f2" : "#f0fdf4", border: `1px solid ${metrics.total_resets > 0 ? "#fecaca" : "#bbf7d0"}`, borderRadius: "10px", padding: "0.75rem 1.25rem", minWidth: 110 }}>
          <div style={{ color: "#64748b", fontSize: "0.72rem", textTransform: "uppercase", fontWeight: 600, marginBottom: "0.25rem" }}>Total RSTs</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700, color: metrics.total_resets > 0 ? "#dc2626" : "#16a34a" }}>{metrics.total_resets}</div>
        </div>
        {causes.map(([code, count]) => {
          const st = CAUSE_STYLE[code] || CAUSE_STYLE.UNKNOWN;
          const isActive = filterCode === code;
          return (
            <div key={code} onClick={() => setFilterCode(f => f === code ? "ALL" : code)} style={{
              background: isActive ? st.bg : "#fff",
              border: `1px solid ${isActive ? st.border : "#e2e8f0"}`,
              borderRadius: "10px", padding: "0.75rem 1.25rem",
              cursor: "pointer", transition: "all 0.15s",
              boxShadow: isActive ? `0 0 0 2px ${st.color}30` : "none",
            }}>
              <div style={{ color: "#64748b", fontSize: "0.68rem", textTransform: "uppercase", fontWeight: 600, marginBottom: "0.25rem" }}>{code.replace(/_/g, " ")}</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 700, color: st.color }}>{count}</div>
            </div>
          );
        })}
      </div>

      {filterCode !== "ALL" && (
        <div style={{ marginBottom: "1rem", fontSize: "0.8rem", color: "#64748b", display: "flex", alignItems: "center", gap: "0.5rem" }}>
          Filtering:
          <span style={{ background: (CAUSE_STYLE[filterCode] || CAUSE_STYLE.UNKNOWN).bg, color: (CAUSE_STYLE[filterCode] || CAUSE_STYLE.UNKNOWN).color, border: `1px solid ${(CAUSE_STYLE[filterCode] || CAUSE_STYLE.UNKNOWN).border}`, fontWeight: 600, fontSize: "0.78rem", padding: "2px 8px", borderRadius: "5px" }}>
            {filterCode.replace(/_/g, " ")}
          </span>
          <button onClick={() => setFilterCode("ALL")} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: "0.78rem", textDecoration: "underline" }}>
            Clear
          </button>
        </div>
      )}

      {filtered.map((rst, i) => <RSTCard key={i} rst={rst} />)}
    </div>
  );
}
