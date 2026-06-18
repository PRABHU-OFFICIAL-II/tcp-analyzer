import { useState } from "react";

const CATEGORY_STYLE = {
  security:    { color: "#dc2626", bg: "#fef2f2", border: "#fecaca", line: "#dc2626" },
  performance: { color: "#d97706", bg: "#fffbeb", border: "#fde68a", line: "#d97706" },
  protocol:    { color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe", line: "#2563eb" },
  rst:         { color: "#ea580c", bg: "#fff7ed", border: "#fed7aa", line: "#ea580c" },
  beacon:      { color: "#7c3aed", bg: "#f5f3ff", border: "#ddd6fe", line: "#7c3aed" },
};

const SEVERITY_STYLE = {
  critical: { color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  warning:  { color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  info:     { color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
};

const ALL_CATEGORIES = ["security", "performance", "protocol", "rst", "beacon"];

function fmtOffset(sec) {
  if (sec < 60) return `T+${sec.toFixed(3)}s`;
  const m = Math.floor(sec / 60);
  const s = (sec % 60).toFixed(1);
  return `T+${m}m ${s}s`;
}

function chipStyle(active, color) {
  return {
    padding: "0.3rem 0.75rem", borderRadius: "20px", cursor: "pointer",
    fontSize: "0.78rem", fontWeight: active ? 700 : 500,
    border: `1px solid ${active ? color : "#e2e8f0"}`,
    background: active ? color + "18" : "#f8fafc",
    color: active ? color : "#64748b",
    transition: "all 0.15s",
  };
}

export default function TimelinePanel({ timeline }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");

  if (!timeline?.events?.length) {
    return <p style={{ color: "#94a3b8", fontStyle: "italic" }}>No timeline events.</p>;
  }

  const categoryCounts = {};
  for (const e of timeline.events) {
    categoryCounts[e.category] = (categoryCounts[e.category] || 0) + 1;
  }

  const events = timeline.events.filter(e => {
    if (filter !== "all" && e.category !== filter) return false;
    if (search && !e.detail.toLowerCase().includes(search.toLowerCase()) &&
        !(e.src_ip || "").includes(search) && !(e.dst_ip || "").includes(search)) return false;
    return true;
  });

  return (
    <div>
      {/* Filter bar */}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1.25rem", alignItems: "center" }}>
        <button onClick={() => setFilter("all")} style={chipStyle(filter === "all", "#64748b")}>
          All ({timeline.events.length})
        </button>
        {ALL_CATEGORIES.filter(c => categoryCounts[c]).map(c => {
          const st = CATEGORY_STYLE[c] || { color: "#64748b" };
          return (
            <button key={c} onClick={() => setFilter(c)} style={chipStyle(filter === c, st.color)}>
              {c} ({categoryCounts[c]})
            </button>
          );
        })}
        <input
          placeholder="Search events…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            marginLeft: "auto", padding: "0.4rem 0.75rem",
            background: "#f8fafc", border: "1px solid #e2e8f0",
            borderRadius: "8px", color: "#1e293b",
            fontSize: "0.8rem", width: 200, outline: "none",
          }}
        />
      </div>

      {events.length === 0 && (
        <p style={{ color: "#94a3b8", fontStyle: "italic" }}>No events match this filter.</p>
      )}

      {/* Event stream */}
      <div style={{ position: "relative", paddingLeft: "1.5rem" }}>
        <div style={{ position: "absolute", left: "7px", top: 0, bottom: 0, width: 2, background: "#e2e8f0" }} />

        {events.map((e, i) => {
          const catSt = CATEGORY_STYLE[e.category] || { color: "#64748b", bg: "#f8fafc", border: "#e2e8f0" };
          const sevSt = SEVERITY_STYLE[e.severity] || SEVERITY_STYLE.info;
          return (
            <div key={i} style={{ position: "relative", marginBottom: "0.75rem", paddingLeft: "1rem" }}>
              {/* Timeline dot */}
              <div style={{
                position: "absolute", left: "-1.5rem", top: "0.4rem",
                width: 12, height: 12, borderRadius: "50%",
                background: catSt.color, border: `3px solid #fff`,
                boxShadow: `0 0 0 2px ${catSt.color}40`,
                zIndex: 1,
              }} />

              <div style={{
                background: "#fff",
                border: `1px solid ${catSt.border}`,
                borderLeft: `3px solid ${catSt.color}`,
                borderRadius: "10px",
                padding: "0.7rem 1rem",
                boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
              }}>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap", marginBottom: "0.3rem" }}>
                  <span style={{ fontFamily: "monospace", color: "#64748b", fontSize: "0.72rem", fontWeight: 600 }}>
                    {fmtOffset(e.time_offset_sec)}
                  </span>
                  <span style={{
                    background: catSt.bg, color: catSt.color, border: `1px solid ${catSt.border}`,
                    fontSize: "0.68rem", fontWeight: 700,
                    padding: "1px 7px", borderRadius: "4px", textTransform: "uppercase",
                  }}>{e.category}</span>
                  <span style={{
                    background: sevSt.bg, color: sevSt.color, border: `1px solid ${sevSt.border}`,
                    fontSize: "0.68rem", fontWeight: 700,
                    padding: "1px 7px", borderRadius: "4px", textTransform: "uppercase",
                  }}>{e.severity}</span>
                  {e.packet_number && (
                    <span style={{ color: "#94a3b8", fontSize: "0.72rem", marginLeft: "auto" }}>
                      pkt #{e.packet_number}
                    </span>
                  )}
                </div>

                <div style={{ color: "#1e293b", fontSize: "0.83rem", fontWeight: 500 }}>{e.detail}</div>

                {(e.src_ip || e.dst_ip) && (
                  <div style={{ color: "#64748b", fontSize: "0.72rem", fontFamily: "monospace", marginTop: "0.25rem" }}>
                    {e.src_ip && <span style={{ color: "#2563eb", fontWeight: 500 }}>{e.src_ip}</span>}
                    {e.src_ip && e.dst_ip && <span style={{ margin: "0 0.3rem", color: "#94a3b8" }}>→</span>}
                    {e.dst_ip && <span style={{ color: "#7c3aed", fontWeight: 500 }}>{e.dst_ip}</span>}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
