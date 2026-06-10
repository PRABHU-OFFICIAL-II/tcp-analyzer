import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

const CAUSE_COLOR = {
  PORT_CLOSED:          "#f59e0b",
  FIREWALL_REJECTION:   "#f59e0b",
  TLS_REJECTION:        "#ef4444",
  RESOURCE_EXHAUSTION:  "#ef4444",
  APP_CRASH:            "#ef4444",
  NAT_TIMEOUT:          "#f59e0b",
  APP_REFUSED:          "#f59e0b",
  MIDDLEBOX_INJECTION:  "#ef4444",
  MID_SESSION:          "#f59e0b",
  UNKNOWN:              "#64748b",
};

const SEV_BADGE = {
  critical: { bg: "#3b1515", border: "#ef4444", text: "#ef4444" },
  warning:  { bg: "#2d2415", border: "#f59e0b", text: "#f59e0b" },
  info:     { bg: "#15202d", border: "#3b82f6", text: "#3b82f6" },
};

const CONF_COLOR = { high: "#22c55e", medium: "#f59e0b", low: "#64748b" };

function fmtTs(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 });
}

function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

function EvidenceChain({ chain }) {
  return (
    <div style={{ marginTop: "1rem", paddingLeft: "1rem",
      borderLeft: "2px solid #2d3148", fontSize: "0.78rem" }}>
      <div style={{ color: "#64748b", fontWeight: 600, textTransform: "uppercase",
        letterSpacing: "0.06em", marginBottom: "0.5rem", fontSize: "0.72rem" }}>
        Evidence Chain
      </div>
      {chain.map((step, i) => {
        const isRST = step.flags.includes("RST");
        return (
          <div key={i} style={{ display: "flex", gap: "0.75rem", marginBottom: "0.5rem",
            alignItems: "flex-start" }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0 }}>
              <div style={{ width: 10, height: 10, borderRadius: "50%",
                background: isRST ? "#ef4444" : "#3b4268",
                border: `2px solid ${isRST ? "#ef4444" : "#475569"}`,
                marginTop: 2 }} />
              {i < chain.length - 1 && (
                <div style={{ width: 2, height: 20, background: "#2d3148" }} />
              )}
            </div>
            <div>
              <span style={{ color: "#475569", fontFamily: "monospace", marginRight: "0.5rem" }}>
                #{step.packet_number}
              </span>
              <span style={{ color: "#64748b", marginRight: "0.5rem" }}>
                {fmtTs(step.timestamp)}
              </span>
              <span style={{ color: isRST ? "#ef4444" : "#818cf8",
                fontFamily: "monospace", fontWeight: 600, marginRight: "0.5rem" }}>
                [{step.flags}]
              </span>
              <span style={{ color: isRST ? "#fca5a5" : "#94a3b8" }}>
                {step.detail}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function RSTCard({ rst }) {
  const [expanded, setExpanded] = useState(false);
  const color = CAUSE_COLOR[rst.root_cause_code] || "#64748b";
  const sev = SEV_BADGE[rst.severity] || SEV_BADGE.info;

  return (
    <div style={{ border: `1px solid ${color}33`, borderLeft: `4px solid ${color}`,
      borderRadius: "10px", marginBottom: "1rem",
      background: sev.bg, overflow: "hidden" }}>

      {/* Header row — always visible */}
      <div style={{ padding: "0.9rem 1.25rem", cursor: "pointer",
        display: "flex", alignItems: "flex-start", gap: "1rem" }}
        onClick={() => setExpanded(e => !e)}>

        <div style={{ flexShrink: 0, marginTop: 3 }}>
          {expanded
            ? <ChevronDown size={16} color="#64748b" />
            : <ChevronRight size={16} color="#64748b" />}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem",
            flexWrap: "wrap", marginBottom: "0.35rem" }}>
            <span style={{ background: sev.bg, border: `1px solid ${sev.border}`,
              color: sev.text, fontSize: "0.68rem", fontWeight: 700,
              padding: "1px 7px", borderRadius: "4px", textTransform: "uppercase" }}>
              {rst.severity}
            </span>
            <span style={{ color, fontWeight: 700, fontSize: "0.88rem" }}>
              {rst.root_cause}
            </span>
            <span style={{ color: CONF_COLOR[rst.confidence], fontSize: "0.72rem",
              fontWeight: 600, marginLeft: "auto" }}>
              {rst.confidence.toUpperCase()} CONFIDENCE
            </span>
          </div>

          <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap", fontSize: "0.78rem", color: "#64748b" }}>
            <span>
              <span style={{ color: "#94a3b8", fontFamily: "monospace" }}>
                {rst.src_ip}:{rst.src_port}
              </span>
              <span style={{ margin: "0 0.3rem" }}>→</span>
              <span style={{ color: "#94a3b8", fontFamily: "monospace" }}>
                {rst.dst_ip}:{rst.dst_port}
              </span>
            </span>
            <span>Pkt #{rst.rst_packet_number}</span>
            <span>{fmtTs(rst.rst_timestamp)}</span>
            <span>RST by: <span style={{ color: rst.rst_sender === "third_party" ? "#ef4444" : "#94a3b8",
              fontWeight: rst.rst_sender === "third_party" ? 700 : 400 }}>{rst.rst_sender}</span></span>
            {rst.bytes_exchanged > 0 && <span>{fmtBytes(rst.bytes_exchanged)} exchanged</span>}
            {rst.idle_gap_before_rst_sec != null && (
              <span style={{ color: rst.idle_gap_before_rst_sec > 30 ? "#f59e0b" : "#64748b" }}>
                {rst.idle_gap_before_rst_sec}s idle before RST
              </span>
            )}
          </div>

          {/* Context badges */}
          <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.4rem", flexWrap: "wrap" }}>
            {rst.had_tls && <span style={{ background: "#1e2a3a", border: "1px solid #3b82f6",
              color: "#60a5fa", fontSize: "0.68rem", padding: "1px 6px", borderRadius: "4px" }}>TLS</span>}
            {rst.had_zero_window && <span style={{ background: "#2d2415", border: "1px solid #f59e0b",
              color: "#f59e0b", fontSize: "0.68rem", padding: "1px 6px", borderRadius: "4px" }}>ZERO WINDOW</span>}
            {rst.had_http_error && <span style={{ background: "#2d1515", border: "1px solid #ef4444",
              color: "#ef4444", fontSize: "0.68rem", padding: "1px 6px", borderRadius: "4px" }}>
              HTTP {rst.http_status_before_rst}</span>}
          </div>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: "0 1.25rem 1.25rem 1.25rem", borderTop: "1px solid #2d3148" }}>
          <div style={{ marginTop: "1rem", display: "grid",
            gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
            <div>
              <div style={{ color: "#64748b", fontSize: "0.72rem", fontWeight: 600,
                textTransform: "uppercase", marginBottom: "0.35rem" }}>Explanation</div>
              <p style={{ color: "#cbd5e1", fontSize: "0.83rem", lineHeight: 1.6 }}>
                {rst.explanation}
              </p>
            </div>
            <div>
              <div style={{ color: "#64748b", fontSize: "0.72rem", fontWeight: 600,
                textTransform: "uppercase", marginBottom: "0.35rem" }}>Recommendation</div>
              <p style={{ color: "#4ade80", fontSize: "0.83rem", lineHeight: 1.6 }}>
                {rst.recommendation}
              </p>
            </div>
          </div>

          {rst.evidence_chain?.length > 0 && (
            <EvidenceChain chain={rst.evidence_chain} />
          )}
        </div>
      )}
    </div>
  );
}

export default function RSTForensicsPanel({ metrics }) {
  const [filterCode, setFilterCode] = useState("ALL");

  if (!metrics || metrics.total_resets === 0) {
    return (
      <p style={{ color: "#4b5563", fontStyle: "italic", fontSize: "0.875rem" }}>
        No RST packets found in this capture.
      </p>
    );
  }

  const causes = Object.entries(metrics.by_cause).sort((a, b) => b[1] - a[1]);
  const filtered = filterCode === "ALL"
    ? metrics.classified
    : metrics.classified.filter(r => r.root_cause_code === filterCode);

  return (
    <div>
      {/* Summary bar */}
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
        <div style={{ background: "#1e2130", border: "1px solid #2d3148",
          borderRadius: "10px", padding: "0.75rem 1.25rem", minWidth: 120 }}>
          <div style={{ color: "#64748b", fontSize: "0.72rem", textTransform: "uppercase",
            fontWeight: 600, marginBottom: "0.25rem" }}>Total RSTs</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700,
            color: metrics.total_resets > 0 ? "#ef4444" : "#22c55e" }}>
            {metrics.total_resets}
          </div>
        </div>
        {causes.map(([code, count]) => (
          <div key={code}
            onClick={() => setFilterCode(f => f === code ? "ALL" : code)}
            style={{ background: filterCode === code ? "#1e2a3a" : "#1e2130",
              border: `1px solid ${filterCode === code ? (CAUSE_COLOR[code] || "#3b4268") : "#2d3148"}`,
              borderRadius: "10px", padding: "0.75rem 1.25rem",
              cursor: "pointer", transition: "border-color 0.15s" }}>
            <div style={{ color: "#64748b", fontSize: "0.68rem", textTransform: "uppercase",
              fontWeight: 600, marginBottom: "0.25rem" }}>{code.replace(/_/g, " ")}</div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700,
              color: CAUSE_COLOR[code] || "#94a3b8" }}>{count}</div>
          </div>
        ))}
      </div>

      {/* Filter label */}
      {filterCode !== "ALL" && (
        <div style={{ marginBottom: "1rem", fontSize: "0.8rem", color: "#64748b" }}>
          Showing: <span style={{ color: CAUSE_COLOR[filterCode], fontWeight: 600 }}>
            {filterCode.replace(/_/g, " ")}
          </span>
          <button onClick={() => setFilterCode("ALL")}
            style={{ marginLeft: "0.75rem", background: "none", border: "none",
              color: "#475569", cursor: "pointer", fontSize: "0.78rem" }}>
            Clear filter
          </button>
        </div>
      )}

      {/* RST cards */}
      {filtered.map((rst, i) => <RSTCard key={i} rst={rst} />)}
    </div>
  );
}
