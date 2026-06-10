import { useState } from "react";

const RCODE_INFO = {
  0: { label: "NOERROR", color: "#22c55e" },
  1: { label: "FORMERR", color: "#f59e0b" },
  2: { label: "SERVFAIL", color: "#ef4444" },
  3: { label: "NXDOMAIN", color: "#ef4444" },
  4: { label: "NOTIMP",  color: "#f59e0b" },
  5: { label: "REFUSED", color: "#ef4444" },
};

const QTYPE_COLOR = {
  A: "#60a5fa", AAAA: "#818cf8", CNAME: "#a78bfa",
  MX: "#f59e0b", TXT: "#94a3b8", PTR: "#64748b",
  NS: "#34d399", SRV: "#fb923c",
};

export default function DNSMapPanel({ dnsMap }) {
  const [tab, setTab] = useState("records");
  const [search, setSearch] = useState("");
  const [filterRcode, setFilterRcode] = useState("all");

  if (!dnsMap || !dnsMap.records || dnsMap.records.length === 0) {
    return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No DNS traffic detected.</p>;
  }

  const tabStyle = (active) => ({
    padding: "0.4rem 0.9rem", cursor: "pointer",
    background: "none", border: "none",
    color: active ? "#60a5fa" : "#64748b",
    borderBottom: active ? "2px solid #60a5fa" : "2px solid transparent",
    fontWeight: active ? 600 : 400, fontSize: "0.82rem",
  });

  const records = dnsMap.records.filter(r => {
    if (filterRcode !== "all" && String(r.rcode) !== filterRcode) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!r.query.toLowerCase().includes(q) &&
          !r.responses?.some(ans => ans.toLowerCase().includes(q))) return false;
    }
    return true;
  });

  const rcodeCounts = {};
  for (const r of dnsMap.records) {
    const k = String(r.rcode);
    rcodeCounts[k] = (rcodeCounts[k] || 0) + 1;
  }

  return (
    <div>
      {/* Summary stats */}
      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", marginBottom: "1rem" }}>
        {[
          { label: "Total Queries",    val: dnsMap.records.length,    color: "#60a5fa" },
          { label: "Unique Domains",   val: dnsMap.unique_domains?.length ?? 0, color: "#a78bfa" },
          { label: "NXDOMAIN",         val: dnsMap.nxdomain_count ?? 0, color: dnsMap.nxdomain_count > 0 ? "#ef4444" : "#22c55e" },
        ].map(s => (
          <div key={s.label} style={{ background: "#1e2130", border: "1px solid #2d3148",
            borderRadius: "8px", padding: "0.5rem 1rem" }}>
            <div style={{ fontSize: "0.72rem", color: "#64748b",
              textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, color: s.color }}>{s.val}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: "0.25rem", borderBottom: "1px solid #2d3148", marginBottom: "1rem" }}>
        {[["records", "Records"], ["top", "Top Queried"], ["domains", "Domain List"]].map(([id, label]) => (
          <button key={id} style={tabStyle(tab === id)} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      {tab === "records" && (
        <>
          {/* Rcode filter */}
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem", alignItems: "center" }}>
            <button onClick={() => setFilterRcode("all")}
              style={chipStyle(filterRcode === "all", "#64748b")}>
              All ({dnsMap.records.length})
            </button>
            {Object.entries(rcodeCounts).sort().map(([code, cnt]) => {
              const info = RCODE_INFO[parseInt(code)] || { label: `RCODE ${code}`, color: "#94a3b8" };
              return (
                <button key={code} onClick={() => setFilterRcode(code)}
                  style={chipStyle(filterRcode === code, info.color)}>
                  {info.label} ({cnt})
                </button>
              );
            })}
            <input
              placeholder="Search domain or answer…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ marginLeft: "auto", padding: "0.35rem 0.75rem",
                background: "#0f1117", border: "1px solid #3b4268",
                borderRadius: "6px", color: "#e2e8f0", fontSize: "0.8rem", width: 220 }}
            />
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #2d3148" }}>
                  {["Domain", "Type", "Answers", "Client", "RCode", "Latency"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.6rem",
                      color: "#64748b", fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {records.length === 0 ? (
                  <tr><td colSpan={6} style={{ padding: "1rem", color: "#4b5563", fontStyle: "italic" }}>
                    No records match.
                  </td></tr>
                ) : records.slice(0, 300).map((r, i) => {
                  const rcInfo = RCODE_INFO[r.rcode] || { label: `${r.rcode}`, color: "#94a3b8" };
                  return (
                    <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                      <td style={{ padding: "0.45rem 0.6rem", color: "#cbd5e1",
                        fontFamily: "monospace", maxWidth: 220,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={r.query}>{r.query}</td>
                      <td style={{ padding: "0.45rem 0.6rem" }}>
                        <span style={{ color: QTYPE_COLOR[r.query_type] || "#94a3b8",
                          fontWeight: 700, fontSize: "0.75rem" }}>{r.query_type}</span>
                      </td>
                      <td style={{ padding: "0.45rem 0.6rem", color: "#94a3b8",
                        fontFamily: "monospace", maxWidth: 200,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={(r.responses || []).join(", ")}>
                        {(r.responses || []).slice(0, 3).join(", ") || "—"}
                      </td>
                      <td style={{ padding: "0.45rem 0.6rem", color: "#64748b",
                        fontFamily: "monospace" }}>{r.client_ip}</td>
                      <td style={{ padding: "0.45rem 0.6rem",
                        color: rcInfo.color, fontWeight: 700, fontSize: "0.75rem" }}>
                        {rcInfo.label}
                      </td>
                      <td style={{ padding: "0.45rem 0.6rem", color: "#64748b" }}>
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
        <div>
          {(dnsMap.top_queried || []).map((item, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center",
              gap: "1rem", marginBottom: "0.5rem" }}>
              <span style={{ color: "#64748b", fontSize: "0.75rem",
                width: 24, textAlign: "right" }}>{i + 1}</span>
              <div style={{ flex: 1, background: "#2d3148", borderRadius: "4px",
                height: 8, overflow: "hidden" }}>
                <div style={{ height: "100%", background: "#3b82f6",
                  width: `${Math.min(100, (item.count / (dnsMap.top_queried[0]?.count || 1)) * 100)}%`,
                  transition: "width 0.3s" }} />
              </div>
              <span style={{ color: "#cbd5e1", fontFamily: "monospace",
                fontSize: "0.8rem", minWidth: 200 }}>{item.domain}</span>
              <span style={{ color: "#60a5fa", fontWeight: 600,
                fontSize: "0.85rem", minWidth: 40, textAlign: "right" }}>
                {item.count}
              </span>
            </div>
          ))}
        </div>
      )}

      {tab === "domains" && (
        <div style={{ columns: "3 180px", gap: "1rem" }}>
          {(dnsMap.unique_domains || []).map((d, i) => (
            <div key={i} style={{ padding: "0.25rem 0.5rem", color: "#94a3b8",
              fontFamily: "monospace", fontSize: "0.78rem",
              borderBottom: "1px solid #1a1d27" }}>{d}</div>
          ))}
        </div>
      )}
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
  };
}
