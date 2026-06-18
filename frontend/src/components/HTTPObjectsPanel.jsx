import { useState } from "react";

const STATUS_BG = (code) => {
  if (!code) return { bg: "#f8fafc", color: "#64748b", border: "#e2e8f0" };
  if (code.startsWith("2")) return { bg: "#f0fdf4", color: "#16a34a", border: "#bbf7d0" };
  if (code.startsWith("3")) return { bg: "#eff6ff", color: "#2563eb", border: "#bfdbfe" };
  if (code.startsWith("4")) return { bg: "#fffbeb", color: "#d97706", border: "#fde68a" };
  if (code.startsWith("5")) return { bg: "#fef2f2", color: "#dc2626", border: "#fecaca" };
  return { bg: "#f8fafc", color: "#64748b", border: "#e2e8f0" };
};

const METHOD_STYLE = {
  GET:     { bg: "#eff6ff",  color: "#2563eb",  border: "#bfdbfe" },
  POST:    { bg: "#f5f3ff",  color: "#7c3aed",  border: "#ddd6fe" },
  PUT:     { bg: "#fffbeb",  color: "#d97706",  border: "#fde68a" },
  DELETE:  { bg: "#fef2f2",  color: "#dc2626",  border: "#fecaca" },
  PATCH:   { bg: "#fff7ed",  color: "#ea580c",  border: "#fed7aa" },
  HEAD:    { bg: "#f8fafc",  color: "#475569",  border: "#e2e8f0" },
  OPTIONS: { bg: "#f8fafc",  color: "#475569",  border: "#e2e8f0" },
};

function fmtBytes(b) {
  b = parseInt(b || 0);
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
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

export default function HTTPObjectsPanel({ httpObjects }) {
  const [search, setSearch] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");

  if (!httpObjects?.objects?.length) {
    return <p style={{ color: "#94a3b8", fontStyle: "italic" }}>No HTTP traffic detected.</p>;
  }

  const STATUS_GROUPS = ["all", "2xx", "3xx", "4xx", "5xx", "no-response"];
  const statusCounts = {};
  for (const o of httpObjects.objects) {
    const code = o.status_code || "";
    const group = code ? code[0] + "xx" : "no-response";
    statusCounts[group] = (statusCounts[group] || 0) + 1;
  }

  const objects = httpObjects.objects.filter(o => {
    if (search) {
      const q = search.toLowerCase();
      if (!o.host.toLowerCase().includes(q) &&
          !o.path.toLowerCase().includes(q) &&
          !o.method.toLowerCase().includes(q)) return false;
    }
    if (filterStatus !== "all") {
      const code = o.status_code || "";
      if (filterStatus === "no-response") return !code;
      if (!code.startsWith(filterStatus[0])) return false;
    }
    return true;
  });

  const filterColor = (g) => {
    if (g === "2xx") return "#16a34a";
    if (g === "3xx") return "#2563eb";
    if (g === "4xx") return "#d97706";
    if (g === "5xx") return "#dc2626";
    return "#64748b";
  };

  return (
    <div>
      {/* Stats */}
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1rem" }}>
        {[
          { label: "Total Requests", value: httpObjects.total_requests, color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
          { label: "Unique Hosts", value: httpObjects.unique_hosts?.length ?? 0, color: "#7c3aed", bg: "#f5f3ff", border: "#ddd6fe" },
        ].map(s => (
          <div key={s.label} style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: "10px", padding: "0.6rem 1.1rem" }}>
            <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>{s.label}</div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem", alignItems: "center" }}>
        {STATUS_GROUPS.filter(g => g === "all" || statusCounts[g]).map(g => (
          <button key={g} onClick={() => setFilterStatus(g)} style={chipStyle(filterStatus === g, filterColor(g))}>
            {g === "all" ? `All (${httpObjects.objects.length})` : `${g} (${statusCounts[g] || 0})`}
          </button>
        ))}
        <input
          placeholder="Filter by host or path…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            marginLeft: "auto", padding: "0.4rem 0.75rem",
            background: "#f8fafc", border: "1px solid #e2e8f0",
            borderRadius: "8px", color: "#1e293b",
            fontSize: "0.8rem", width: 220, outline: "none",
          }}
        />
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead>
            <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
              {["Method", "Host", "Path", "Status", "Req Size", "Resp Size"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {objects.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: "1.5rem", color: "#94a3b8", fontStyle: "italic", textAlign: "center" }}>No objects match this filter.</td></tr>
            ) : objects.map((o, i) => {
              const ms = METHOD_STYLE[o.method] || METHOD_STYLE.HEAD;
              const ss = STATUS_BG(o.status_code);
              return (
                <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                  <td style={{ padding: "0.5rem 0.75rem" }}>
                    <span style={{ background: ms.bg, color: ms.color, border: `1px solid ${ms.border}`, fontWeight: 700, fontSize: "0.7rem", padding: "2px 6px", borderRadius: "4px" }}>{o.method}</span>
                  </td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{o.host}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#475569", fontFamily: "monospace", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={o.path}>{o.path}</td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>
                    {o.status_code
                      ? <span style={{ background: ss.bg, color: ss.color, border: `1px solid ${ss.border}`, fontWeight: 700, fontSize: "0.72rem", padding: "2px 6px", borderRadius: "4px" }}>{o.status_code}</span>
                      : <span style={{ color: "#94a3b8" }}>—</span>}
                  </td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#64748b" }}>{fmtBytes(o.request_size)}</td>
                  <td style={{ padding: "0.5rem 0.75rem", color: "#64748b" }}>{fmtBytes(o.response_size)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
