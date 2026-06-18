import { useState } from "react";

const RCODE_INFO = {
  0: { label: "NOERROR",  color: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
  1: { label: "FORMERR",  color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  2: { label: "SERVFAIL", color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  3: { label: "NXDOMAIN", color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  4: { label: "NOTIMP",   color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  5: { label: "REFUSED",  color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
};

const QTYPE_STYLE = {
  A:     { color: "#2563eb", bg: "#eff6ff",  border: "#bfdbfe" },
  AAAA:  { color: "#4f46e5", bg: "#eef2ff",  border: "#c7d2fe" },
  CNAME: { color: "#7c3aed", bg: "#f5f3ff",  border: "#ddd6fe" },
  MX:    { color: "#d97706", bg: "#fffbeb",  border: "#fde68a" },
  TXT:   { color: "#475569", bg: "#f8fafc",  border: "#e2e8f0" },
  PTR:   { color: "#475569", bg: "#f8fafc",  border: "#e2e8f0" },
  NS:    { color: "#059669", bg: "#ecfdf5",  border: "#a7f3d0" },
  SRV:   { color: "#ea580c", bg: "#fff7ed",  border: "#fed7aa" },
};

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

export default function DNSMapPanel({ dnsMap }) {
  const [tab, setTab] = useState("records");
  const [search, setSearch] = useState("");
  const [filterRcode, setFilterRcode] = useState("all");

  if (!dnsMap?.records?.length) {
    return <p style={{ color: "#94a3b8", fontStyle: "italic" }}>No DNS traffic detected.</p>;
  }

  const tabStyle = (active) => ({
    padding: "0.45rem 1rem", cursor: "pointer",
    background: active ? "#eff6ff" : "transparent",
    border: "none", borderRadius: "7px",
    color: active ? "#2563eb" : "#64748b",
    fontWeight: active ? 600 : 400, fontSize: "0.82rem",
    transition: "all 0.15s",
  });

  const rcodeCounts = {};
  for (const r of dnsMap.records) {
    const k = String(r.rcode);
    rcodeCounts[k] = (rcodeCounts[k] || 0) + 1;
  }

  const records = dnsMap.records.filter(r => {
    if (filterRcode !== "all" && String(r.rcode) !== filterRcode) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!r.query.toLowerCase().includes(q) &&
          !r.responses?.some(ans => ans.toLowerCase().includes(q))) return false;
    }
    return true;
  });

  return (
    <div>
      {/* Stats */}
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.25rem" }}>
        {[
          { label: "Total Queries",  val: dnsMap.records.length,    color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
          { label: "Unique Domains", val: dnsMap.unique_domains?.length ?? 0, color: "#7c3aed", bg: "#f5f3ff", border: "#ddd6fe" },
          { label: "NXDOMAIN",       val: dnsMap.nxdomain_count ?? 0,
            color: (dnsMap.nxdomain_count ?? 0) > 0 ? "#dc2626" : "#16a34a",
            bg: (dnsMap.nxdomain_count ?? 0) > 0 ? "#fef2f2" : "#f0fdf4",
            border: (dnsMap.nxdomain_count ?? 0) > 0 ? "#fecaca" : "#bbf7d0" },
        ].map(s => (
          <div key={s.label} style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: "10px", padding: "0.6rem 1.1rem" }}>
            <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>{s.label}</div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700, color: s.color }}>{s.val}</div>
          </div>
        ))}
      </div>

      {/* Sub-tabs */}
      <div style={{ display: "flex", gap: "0.25rem", marginBottom: "1.25rem", background: "#f8fafc", borderRadius: "10px", padding: "0.3rem", border: "1px solid #e2e8f0" }}>
        {[["records", "Records"], ["top", "Top Queried"], ["domains", "Domain List"]].map(([id, label]) => (
          <button key={id} style={tabStyle(tab === id)} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {tab === "records" && (
        <>
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem", alignItems: "center" }}>
            <button onClick={() => setFilterRcode("all")} style={chipStyle(filterRcode === "all", "#64748b")}>
              All ({dnsMap.records.length})
            </button>
            {Object.entries(rcodeCounts).sort().map(([code, cnt]) => {
              const info = RCODE_INFO[parseInt(code)] || { label: `RCODE ${code}`, color: "#94a3b8", bg: "#f8fafc", border: "#e2e8f0" };
              return (
                <button key={code} onClick={() => setFilterRcode(code)} style={chipStyle(filterRcode === code, info.color)}>
                  {info.label} ({cnt})
                </button>
              );
            })}
            <input
              placeholder="Search domain or answer…"
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

          <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
              <thead>
                <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                  {["Domain", "Type", "Answers", "Client IP", "RCode", "Latency"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {records.length === 0 ? (
                  <tr><td colSpan={6} style={{ padding: "1.5rem", color: "#94a3b8", fontStyle: "italic", textAlign: "center" }}>No records match.</td></tr>
                ) : records.slice(0, 300).map((r, i) => {
                  const rcInfo = RCODE_INFO[r.rcode] || { label: `${r.rcode}`, color: "#64748b", bg: "#f8fafc", border: "#e2e8f0" };
                  const qtStyle = QTYPE_STYLE[r.query_type] || QTYPE_STYLE.TXT;
                  return (
                    <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                      <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.query}>{r.query}</td>
                      <td style={{ padding: "0.5rem 0.75rem" }}>
                        <span style={{ background: qtStyle.bg, color: qtStyle.color, border: `1px solid ${qtStyle.border}`, fontWeight: 700, fontSize: "0.7rem", padding: "2px 6px", borderRadius: "4px" }}>{r.query_type}</span>
                      </td>
                      <td style={{ padding: "0.5rem 0.75rem", color: "#475569", fontFamily: "monospace", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={(r.responses || []).join(", ")}>
                        {(r.responses || []).slice(0, 3).join(", ") || "—"}
                      </td>
                      <td style={{ padding: "0.5rem 0.75rem", color: "#1e293b", fontFamily: "monospace", fontWeight: 500 }}>{r.client_ip}</td>
                      <td style={{ padding: "0.5rem 0.75rem" }}>
                        <span style={{ background: rcInfo.bg, color: rcInfo.color, border: `1px solid ${rcInfo.border}`, fontWeight: 700, fontSize: "0.7rem", padding: "2px 6px", borderRadius: "4px" }}>{rcInfo.label}</span>
                      </td>
                      <td style={{ padding: "0.5rem 0.75rem", color: "#64748b" }}>
                        {r.latency_ms != null ? `${r.latency_ms} ms` : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === "top" && (
        <div style={{ background: "#fff", borderRadius: "10px", border: "1px solid #e2e8f0", padding: "1rem" }}>
          {(dnsMap.top_queried || []).map((item, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "0.6rem" }}>
              <span style={{ color: "#94a3b8", fontSize: "0.75rem", width: 24, textAlign: "right", fontWeight: 600 }}>{i + 1}</span>
              <div style={{ flex: 1, background: "#f1f5f9", borderRadius: "4px", height: 8, overflow: "hidden" }}>
                <div style={{
                  height: "100%", background: "linear-gradient(90deg, #2563eb, #4f46e5)",
                  width: `${Math.min(100, (item.count / (dnsMap.top_queried[0]?.count || 1)) * 100)}%`,
                  borderRadius: "4px", transition: "width 0.3s",
                }} />
              </div>
              <span style={{ color: "#1e293b", fontFamily: "monospace", fontWeight: 500, fontSize: "0.8rem", minWidth: 200 }}>{item.domain}</span>
              <span style={{ background: "#eff6ff", color: "#2563eb", border: "1px solid #bfdbfe", fontWeight: 700, fontSize: "0.8rem", padding: "2px 8px", borderRadius: "6px", minWidth: 40, textAlign: "right" }}>
                {item.count}
              </span>
            </div>
          ))}
        </div>
      )}

      {tab === "domains" && (
        <div style={{ background: "#fff", borderRadius: "10px", border: "1px solid #e2e8f0", padding: "1rem", columns: "3 180px", gap: "1rem" }}>
          {(dnsMap.unique_domains || []).map((d, i) => (
            <div key={i} style={{
              padding: "0.3rem 0.5rem", color: "#334155",
              fontFamily: "monospace", fontSize: "0.78rem",
              borderBottom: "1px solid #f1f5f9",
            }}>{d}</div>
          ))}
        </div>
      )}
    </div>
  );
}
