import { ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Info } from "lucide-react";

const SIGNAL_STYLE = {
  http_connect:      { label: "HTTP CONNECT",    color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
  socks5:            { label: "SOCKS5",           color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  socks4:            { label: "SOCKS4",           color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  proxy_headers:     { label: "Proxy Headers",   color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe" },
  xff_private_leak:  { label: "XFF Chain Leak",  color: "#7c3aed", bg: "#f5f3ff", border: "#ddd6fe" },
  known_proxy_port:  { label: "Proxy Port",      color: "#475569", bg: "#f8fafc", border: "#e2e8f0" },
};

const VERDICT_STYLE = {
  warning: { icon: <ShieldX size={20} color="#dc2626" />, bg: "#fef2f2", border: "#fecaca", color: "#dc2626" },
  info:    { icon: <AlertTriangle size={20} color="#d97706" />, bg: "#fffbeb", border: "#fde68a", color: "#d97706" },
  clean:   { icon: <ShieldCheck size={20} color="#16a34a" />, bg: "#f0fdf4", border: "#bbf7d0", color: "#16a34a" },
};

const SEV_ICON = { warning: <ShieldAlert size={13} />, info: <Info size={13} /> };

export default function ProxyPanel({ proxy }) {
  if (!proxy) return <p style={{ color: "#94a3b8", fontStyle: "italic" }}>No proxy analysis available.</p>;

  const vst = VERDICT_STYLE[proxy.verdict_severity] || VERDICT_STYLE.clean;

  // Group signals by type for the summary
  const byType = {};
  for (const s of proxy.signals || []) {
    byType[s.signal_type] = (byType[s.signal_type] || 0) + 1;
  }

  return (
    <div>
      {/* Verdict banner */}
      <div style={{
        background: vst.bg, border: `1px solid ${vst.border}`,
        borderRadius: "14px", padding: "1.1rem 1.5rem",
        display: "flex", alignItems: "center", gap: "1rem",
        marginBottom: "1.75rem",
        boxShadow: "0 2px 8px rgba(0,0,0,0.05)",
      }}>
        {vst.icon}
        <div>
          <div style={{ fontSize: "1rem", fontWeight: 700, color: vst.color }}>{proxy.verdict}</div>
          <div style={{ fontSize: "0.82rem", color: "#64748b", marginTop: "0.2rem" }}>
            {proxy.total_signals} unique signal{proxy.total_signals !== 1 ? "s" : ""} detected
            {proxy.proxy_hosts?.length > 0 && ` · ${proxy.proxy_hosts.length} potential proxy host${proxy.proxy_hosts.length !== 1 ? "s" : ""}`}
          </div>
        </div>
      </div>

      {proxy.verdict_severity === "clean" ? null : (
        <>
          {/* Signal type breakdown */}
          {Object.keys(byType).length > 0 && (
            <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
              {Object.entries(byType).map(([type, count]) => {
                const st = SIGNAL_STYLE[type] || SIGNAL_STYLE.known_proxy_port;
                return (
                  <div key={type} style={{ background: st.bg, border: `1px solid ${st.border}`, borderRadius: "10px", padding: "0.55rem 1rem" }}>
                    <div style={{ fontSize: "0.68rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600, marginBottom: "0.2rem" }}>{st.label}</div>
                    <div style={{ fontSize: "1.3rem", fontWeight: 700, color: st.color }}>{count}</div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Proxy hosts */}
          {proxy.proxy_hosts?.length > 0 && (
            <>
              <h3 style={{ fontSize: "0.82rem", fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "0.75rem" }}>
                Detected Proxy Hosts
              </h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginBottom: "1.75rem" }}>
                {proxy.proxy_hosts.map((host, i) => (
                  <div key={i} style={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "12px", padding: "1rem 1.25rem", boxShadow: "0 1px 4px rgba(0,0,0,0.05)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
                      <span style={{ fontFamily: "monospace", fontWeight: 700, color: "#1e293b", fontSize: "0.9rem" }}>{host.ip}</span>
                      {host.ports.map(p => (
                        <span key={p} style={{ background: "#f1f5f9", color: "#475569", border: "1px solid #e2e8f0", fontSize: "0.72rem", fontWeight: 600, padding: "1px 7px", borderRadius: "4px" }}>:{p}</span>
                      ))}
                      <span style={{ marginLeft: "auto", color: "#94a3b8", fontSize: "0.75rem" }}>{host.packet_count.toLocaleString()} pkts</span>
                    </div>
                    <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap", marginBottom: host.connect_targets.length || host.via_values.length ? "0.5rem" : 0 }}>
                      {host.signals.map((sig, j) => (
                        <span key={j} style={{ background: "#f8fafc", color: "#475569", border: "1px solid #e2e8f0", fontSize: "0.72rem", padding: "2px 8px", borderRadius: "4px" }}>{sig}</span>
                      ))}
                    </div>
                    {host.connect_targets.length > 0 && (
                      <div style={{ fontSize: "0.78rem", color: "#475569", marginTop: "0.35rem" }}>
                        <span style={{ color: "#94a3b8", fontWeight: 600 }}>CONNECT targets: </span>
                        {host.connect_targets.slice(0, 8).map((t, j) => (
                          <span key={j} style={{ fontFamily: "monospace", marginRight: 6, color: "#334155" }}>{t}</span>
                        ))}
                        {host.connect_targets.length > 8 && <span style={{ color: "#94a3b8" }}>+{host.connect_targets.length - 8} more</span>}
                      </div>
                    )}
                    {host.via_values.length > 0 && (
                      <div style={{ fontSize: "0.78rem", color: "#475569", marginTop: "0.3rem" }}>
                        <span style={{ color: "#94a3b8", fontWeight: 600 }}>Via: </span>
                        {host.via_values.slice(0, 3).map((v, j) => (
                          <span key={j} style={{ fontFamily: "monospace", color: "#334155", marginRight: 6 }}>{v}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Individual signals table */}
          {proxy.signals?.length > 0 && (
            <>
              <h3 style={{ fontSize: "0.82rem", fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: "0.75rem" }}>
                All Signals
                <span style={{ marginLeft: "0.5rem", background: "#f1f5f9", color: "#64748b", fontSize: "0.72rem", padding: "1px 7px", borderRadius: "10px" }}>{proxy.signals.length}</span>
              </h3>
              <div style={{ overflowX: "auto", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.79rem" }}>
                  <thead>
                    <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                      {["Type", "Source IP", "Proxy IP", "Port", "Pkt #", "Detail"].map(h => (
                        <th key={h} style={{ textAlign: "left", padding: "0.55rem 0.85rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {proxy.signals.map((s, i) => {
                      const st = SIGNAL_STYLE[s.signal_type] || SIGNAL_STYLE.known_proxy_port;
                      const sevIcon = s.severity === "warning"
                        ? <ShieldAlert size={12} color="#d97706" />
                        : <Info size={12} color="#2563eb" />;
                      return (
                        <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", background: i % 2 === 0 ? "#fff" : "#fafbfc" }}>
                          <td style={{ padding: "0.5rem 0.85rem" }}>
                            <span style={{ background: st.bg, color: st.color, border: `1px solid ${st.border}`, fontSize: "0.7rem", fontWeight: 700, padding: "2px 7px", borderRadius: "4px" }}>{st.label}</span>
                          </td>
                          <td style={{ padding: "0.5rem 0.85rem", fontFamily: "monospace", color: "#1e293b", fontWeight: 500 }}>{s.src_ip}</td>
                          <td style={{ padding: "0.5rem 0.85rem", fontFamily: "monospace", color: "#1e293b", fontWeight: 500 }}>{s.dst_ip}</td>
                          <td style={{ padding: "0.5rem 0.85rem", fontFamily: "monospace", color: "#64748b" }}>{s.dst_port}</td>
                          <td style={{ padding: "0.5rem 0.85rem", color: "#94a3b8" }}>#{s.packet_number}</td>
                          <td style={{ padding: "0.5rem 0.85rem", color: "#475569", maxWidth: 360 }}>{s.detail}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
