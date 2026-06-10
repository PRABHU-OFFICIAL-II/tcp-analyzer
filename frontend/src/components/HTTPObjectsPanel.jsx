import { useState } from "react";

const STATUS_COLOR = (code) => {
  if (!code) return "#64748b";
  if (code.startsWith("2")) return "#22c55e";
  if (code.startsWith("3")) return "#60a5fa";
  if (code.startsWith("4")) return "#f59e0b";
  if (code.startsWith("5")) return "#ef4444";
  return "#94a3b8";
};

const METHOD_COLOR = {
  GET: "#60a5fa", POST: "#a78bfa", PUT: "#f59e0b",
  DELETE: "#ef4444", PATCH: "#f97316", HEAD: "#64748b",
  OPTIONS: "#64748b", CONNECT: "#64748b",
};

function fmtBytes(b) {
  b = parseInt(b || 0);
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

export default function HTTPObjectsPanel({ httpObjects }) {
  const [search, setSearch] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");

  if (!httpObjects || !httpObjects.objects || httpObjects.objects.length === 0) {
    return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No HTTP traffic detected.</p>;
  }

  const STATUS_GROUPS = ["all", "2xx", "3xx", "4xx", "5xx", "no-response"];

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

  const statusCounts = {};
  for (const o of httpObjects.objects) {
    const code = o.status_code || "";
    const group = code ? code[0] + "xx" : "no-response";
    statusCounts[group] = (statusCounts[group] || 0) + 1;
  }

  return (
    <div>
      {/* Stats row */}
      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", marginBottom: "1rem" }}>
        <div style={statPill}>
          <span style={{ color: "#60a5fa", fontWeight: 700 }}>{httpObjects.total_requests}</span>
          <span style={{ color: "#64748b", fontSize: "0.8rem" }}> requests</span>
        </div>
        <div style={statPill}>
          <span style={{ color: "#a78bfa", fontWeight: 700 }}>{httpObjects.unique_hosts?.length ?? 0}</span>
          <span style={{ color: "#64748b", fontSize: "0.8rem" }}> unique hosts</span>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem", alignItems: "center" }}>
        {STATUS_GROUPS.filter(g => g === "all" || statusCounts[g]).map(g => {
          const color = g === "2xx" ? "#22c55e" : g === "3xx" ? "#60a5fa" :
            g === "4xx" ? "#f59e0b" : g === "5xx" ? "#ef4444" : "#64748b";
          return (
            <button key={g}
              onClick={() => setFilterStatus(g)}
              style={{ padding: "0.3rem 0.75rem", borderRadius: "20px", cursor: "pointer",
                fontSize: "0.78rem", fontWeight: filterStatus === g ? 700 : 400,
                border: `1px solid ${filterStatus === g ? color : "#3b4268"}`,
                background: filterStatus === g ? color + "20" : "transparent",
                color: filterStatus === g ? color : "#64748b" }}>
              {g === "all" ? `All (${httpObjects.objects.length})` : `${g} (${statusCounts[g] || 0})`}
            </button>
          );
        })}
        <input
          placeholder="Filter by host or path…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ marginLeft: "auto", padding: "0.35rem 0.75rem",
            background: "#0f1117", border: "1px solid #3b4268",
            borderRadius: "6px", color: "#e2e8f0", fontSize: "0.8rem", width: 220 }}
        />
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #2d3148" }}>
              {["Method", "Host", "Path", "Status", "Req", "Resp"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.6rem",
                  color: "#64748b", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {objects.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: "1rem", color: "#4b5563", fontStyle: "italic" }}>
                No objects match this filter.
              </td></tr>
            ) : objects.map((o, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                <td style={{ padding: "0.45rem 0.6rem" }}>
                  <span style={{ color: METHOD_COLOR[o.method] || "#94a3b8",
                    fontWeight: 700, fontFamily: "monospace" }}>{o.method}</span>
                </td>
                <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1",
                  fontFamily: "monospace", maxWidth: 180, overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{o.host}</td>
                <td style={{ padding: "0.45rem 0.6rem", color: "#94a3b8",
                  fontFamily: "monospace", maxWidth: 260, overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={o.path}>{o.path}</td>
                <td style={{ padding: "0.45rem 0.6rem",
                  color: STATUS_COLOR(o.status_code), fontWeight: 700 }}>
                  {o.status_code || "—"}
                </td>
                <td style={{ padding: "0.45rem 0.6rem", color: "#64748b" }}>
                  {fmtBytes(o.request_size)}
                </td>
                <td style={{ padding: "0.45rem 0.6rem", color: "#64748b" }}>
                  {fmtBytes(o.response_size)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const statPill = {
  background: "#1e2130", border: "1px solid #2d3148",
  borderRadius: "8px", padding: "0.5rem 1rem",
};
