import { useState } from "react";

const CATEGORY_COLOR = {
  security:    "#ef4444",
  performance: "#f59e0b",
  protocol:    "#3b82f6",
  rst:         "#f97316",
  beacon:      "#a855f7",
};

const SEVERITY_COLOR = {
  critical: "#ef4444",
  warning:  "#f59e0b",
  info:     "#3b82f6",
};

const ALL_CATEGORIES = ["security", "performance", "protocol", "rst", "beacon"];

function fmtOffset(sec) {
  if (sec < 60) return `T+${sec.toFixed(3)}s`;
  const m = Math.floor(sec / 60);
  const s = (sec % 60).toFixed(1);
  return `T+${m}m ${s}s`;
}

export default function TimelinePanel({ timeline }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");

  if (!timeline || !timeline.events || timeline.events.length === 0) {
    return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No timeline events.</p>;
  }

  const events = timeline.events.filter(e => {
    if (filter !== "all" && e.category !== filter) return false;
    if (search && !e.detail.toLowerCase().includes(search.toLowerCase()) &&
        !(e.src_ip || "").includes(search) && !(e.dst_ip || "").includes(search)) return false;
    return true;
  });

  const categoryCounts = {};
  for (const e of timeline.events) {
    categoryCounts[e.category] = (categoryCounts[e.category] || 0) + 1;
  }

  return (
    <div>
      {/* Filter bar */}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem", alignItems: "center" }}>
        <button
          onClick={() => setFilter("all")}
          style={{ ...chipStyle(filter === "all", "#64748b") }}>
          All ({timeline.events.length})
        </button>
        {ALL_CATEGORIES.filter(c => categoryCounts[c]).map(c => (
          <button key={c}
            onClick={() => setFilter(c)}
            style={chipStyle(filter === c, CATEGORY_COLOR[c])}>
            {c} ({categoryCounts[c]})
          </button>
        ))}
        <input
          placeholder="Search events…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ marginLeft: "auto", padding: "0.35rem 0.75rem",
            background: "#0f1117", border: "1px solid #3b4268",
            borderRadius: "6px", color: "#e2e8f0", fontSize: "0.8rem", width: 200 }}
        />
      </div>

      {events.length === 0 && (
        <p style={{ color: "#4b5563", fontStyle: "italic" }}>No events match this filter.</p>
      )}

      {/* Event stream */}
      <div style={{ position: "relative", paddingLeft: "1.5rem" }}>
        <div style={{ position: "absolute", left: "7px", top: 0, bottom: 0,
          width: 2, background: "#2d3148" }} />

        {events.map((e, i) => {
          const catColor = CATEGORY_COLOR[e.category] || "#64748b";
          const sevColor = SEVERITY_COLOR[e.severity] || "#94a3b8";
          return (
            <div key={i} style={{ position: "relative", marginBottom: "0.75rem",
              paddingLeft: "1rem" }}>
              {/* Timeline dot */}
              <div style={{
                position: "absolute", left: "-1.5rem", top: "0.35rem",
                width: 12, height: 12, borderRadius: "50%",
                background: catColor, border: `2px solid ${catColor}40`,
                zIndex: 1,
              }} />

              <div style={{ background: "#1e2130", border: `1px solid ${catColor}30`,
                borderLeft: `3px solid ${catColor}`, borderRadius: "8px",
                padding: "0.6rem 0.9rem" }}>

                <div style={{ display: "flex", gap: "0.75rem", alignItems: "center",
                  flexWrap: "wrap", marginBottom: "0.2rem" }}>
                  <span style={{ fontFamily: "monospace", color: "#475569", fontSize: "0.72rem" }}>
                    {fmtOffset(e.time_offset_sec)}
                  </span>
                  <span style={{ background: catColor + "20", color: catColor,
                    fontSize: "0.68rem", fontWeight: 700, padding: "1px 6px",
                    borderRadius: "4px", textTransform: "uppercase" }}>
                    {e.category}
                  </span>
                  <span style={{ color: sevColor, fontSize: "0.68rem",
                    fontWeight: 700, textTransform: "uppercase" }}>
                    {e.severity}
                  </span>
                  {e.packet_number && (
                    <span style={{ color: "#475569", fontSize: "0.72rem", marginLeft: "auto" }}>
                      pkt #{e.packet_number}
                    </span>
                  )}
                </div>

                <div style={{ color: "#cbd5e1", fontSize: "0.82rem" }}>{e.detail}</div>

                {(e.src_ip || e.dst_ip) && (
                  <div style={{ color: "#475569", fontSize: "0.72rem",
                    fontFamily: "monospace", marginTop: "0.2rem" }}>
                    {e.src_ip && <span>{e.src_ip}</span>}
                    {e.src_ip && e.dst_ip && <span style={{ margin: "0 0.3rem" }}>→</span>}
                    {e.dst_ip && <span>{e.dst_ip}</span>}
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

function chipStyle(active, color) {
  return {
    padding: "0.3rem 0.75rem", borderRadius: "20px", cursor: "pointer",
    fontSize: "0.78rem", fontWeight: active ? 700 : 400,
    border: `1px solid ${active ? color : "#3b4268"}`,
    background: active ? color + "20" : "transparent",
    color: active ? color : "#64748b",
    transition: "all 0.15s",
  };
}
