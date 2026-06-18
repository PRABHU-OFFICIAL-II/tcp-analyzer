import { useState } from "react";
import { Monitor, Wifi, Server, HelpCircle } from "lucide-react";

const SOURCE_STYLE = {
  "DHCP":    { bg: "#f0fdf4", color: "#16a34a", border: "#bbf7d0" },
  "mDNS":    { bg: "#eff6ff", color: "#2563eb", border: "#bfdbfe" },
  "NetBIOS": { bg: "#f5f3ff", color: "#7c3aed", border: "#ddd6fe" },
  "DNS-PTR": { bg: "#fffbeb", color: "#d97706", border: "#fde68a" },
};

const MANUF_ICON = (manuf) => {
  const m = (manuf || "").toLowerCase();
  if (m.includes("apple"))    return <Monitor size={14} color="#475569" />;
  if (m.includes("cisco") || m.includes("juniper") || m.includes("aruba") || m.includes("netgear") || m.includes("ubiquiti"))
    return <Wifi size={14} color="#475569" />;
  if (m.includes("dell") || m.includes("hp") || m.includes("lenovo") || m.includes("vmware") || m.includes("microsoft"))
    return <Server size={14} color="#475569" />;
  return <HelpCircle size={14} color="#94a3b8" />;
};

export default function MacMapPanel({ macMap }) {
  const [search, setSearch] = useState("");
  const [filterResolved, setFilterResolved] = useState(false);

  if (!macMap?.entries?.length) {
    return <p style={{ color: "#94a3b8", fontStyle: "italic" }}>No MAC address data found in this capture.</p>;
  }

  const entries = macMap.entries.filter(e => {
    if (filterResolved && !e.hostname) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      e.mac.toLowerCase().includes(q) ||
      (e.hostname || "").toLowerCase().includes(q) ||
      e.manufacturer.toLowerCase().includes(q) ||
      e.ips.some(ip => ip.includes(q))
    );
  });

  return (
    <div>
      {/* Stats */}
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.25rem" }}>
        {[
          { label: "Devices Seen", value: macMap.total_devices, color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
          { label: "Hostnames Resolved", value: macMap.resolved_hostnames, color: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
          {
            label: "Unresolved",
            value: macMap.total_devices - macMap.resolved_hostnames,
            color: "#64748b", bg: "#f8fafc", border: "#e2e8f0",
          },
        ].map(s => (
          <div key={s.label} style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: "10px", padding: "0.65rem 1.1rem" }}>
            <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>{s.label}</div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Hostname source legend */}
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem", alignItems: "center" }}>
        <span style={{ fontSize: "0.75rem", color: "#94a3b8", fontWeight: 600 }}>Hostname source:</span>
        {Object.entries(SOURCE_STYLE).map(([src, st]) => (
          <span key={src} style={{ background: st.bg, color: st.color, border: `1px solid ${st.border}`, fontSize: "0.7rem", fontWeight: 700, padding: "1px 8px", borderRadius: "4px" }}>{src}</span>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem", alignItems: "center" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", cursor: "pointer", fontSize: "0.82rem", color: "#475569", fontWeight: 500 }}>
          <input
            type="checkbox"
            checked={filterResolved}
            onChange={e => setFilterResolved(e.target.checked)}
            style={{ accentColor: "#2563eb" }}
          />
          Show only resolved hostnames
        </label>
        <input
          placeholder="Search MAC, hostname, manufacturer, IP…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            marginLeft: "auto", padding: "0.4rem 0.75rem",
            background: "#f8fafc", border: "1px solid #e2e8f0",
            borderRadius: "8px", color: "#1e293b",
            fontSize: "0.8rem", width: 280, outline: "none",
          }}
        />
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
          <thead>
            <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
              {["MAC Address", "Manufacturer", "Hostname", "Source", "IP Address(es)", "Pkts"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.85rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: "1.5rem", textAlign: "center", color: "#94a3b8", fontStyle: "italic" }}>No entries match.</td></tr>
            ) : entries.map((e, i) => {
              const srcSt = e.hostname_source ? (SOURCE_STYLE[e.hostname_source] || SOURCE_STYLE["DNS-PTR"]) : null;
              return (
                <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                  <td style={{ padding: "0.55rem 0.85rem", fontFamily: "monospace", color: "#334155", fontWeight: 600 }}>{e.mac}</td>
                  <td style={{ padding: "0.55rem 0.85rem" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                      {MANUF_ICON(e.manufacturer)}
                      <span style={{ color: e.manufacturer === "Unknown" ? "#94a3b8" : "#334155", fontStyle: e.manufacturer === "Unknown" ? "italic" : "normal" }}>
                        {e.manufacturer}
                      </span>
                    </div>
                  </td>
                  <td style={{ padding: "0.55rem 0.85rem" }}>
                    {e.hostname
                      ? <span style={{ color: "#1e293b", fontWeight: 600 }}>{e.hostname}</span>
                      : <span style={{ color: "#cbd5e1", fontStyle: "italic" }}>—</span>}
                    {/* Show extra hostnames if multiple sources found */}
                    {e.all_hostnames && Object.keys(e.all_hostnames).length > 1 && (
                      <div style={{ marginTop: 2 }}>
                        {Object.entries(e.all_hostnames)
                          .filter(([src]) => src !== e.hostname_source)
                          .map(([src, name]) => {
                            const st = SOURCE_STYLE[src] || SOURCE_STYLE["DNS-PTR"];
                            return (
                              <span key={src} title={`${src}: ${name}`} style={{ fontSize: "0.68rem", color: st.color, marginRight: 4 }}>
                                {name}
                              </span>
                            );
                          })}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: "0.55rem 0.85rem" }}>
                    {srcSt
                      ? <span style={{ background: srcSt.bg, color: srcSt.color, border: `1px solid ${srcSt.border}`, fontSize: "0.7rem", fontWeight: 700, padding: "2px 7px", borderRadius: "4px" }}>{e.hostname_source}</span>
                      : <span style={{ color: "#e2e8f0" }}>—</span>}
                  </td>
                  <td style={{ padding: "0.55rem 0.85rem", fontFamily: "monospace", fontSize: "0.78rem" }}>
                    {e.ips.length === 0
                      ? <span style={{ color: "#94a3b8" }}>—</span>
                      : e.ips.map((ip, j) => (
                          <span key={j} style={{ display: "inline-block", marginRight: 4, marginBottom: 2, background: "#f1f5f9", color: "#334155", padding: "1px 6px", borderRadius: "4px", border: "1px solid #e2e8f0" }}>{ip}</span>
                        ))}
                  </td>
                  <td style={{ padding: "0.55rem 0.85rem", color: "#94a3b8", textAlign: "right" }}>{e.packet_count.toLocaleString()}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
