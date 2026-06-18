import { useEffect, useState } from "react";
import { ArrowLeft, Save, RotateCcw, Settings, Zap, ShieldCheck, Activity, Radio, BarChart2, Cpu } from "lucide-react";

const SECTION_ICONS = {
  performance: Zap,
  security: ShieldCheck,
  protocol: Activity,
  beacon: Radio,
  rst_forensics: BarChart2,
  engine: Cpu,
};

const SECTION_COLORS = {
  performance: { bg: "#fffbeb", border: "#fde68a", icon: "#d97706" },
  security:    { bg: "#f0fdf4", border: "#bbf7d0", icon: "#16a34a" },
  protocol:    { bg: "#eff6ff", border: "#bfdbfe", icon: "#2563eb" },
  beacon:      { bg: "#fef2f2", border: "#fecaca", icon: "#dc2626" },
  rst_forensics: { bg: "#f5f3ff", border: "#ddd6fe", icon: "#7c3aed" },
  engine:      { bg: "#f8fafc", border: "#e2e8f0", icon: "#475569" },
};

const FIELDS = [
  {
    section: "performance", label: "Performance",
    fields: [
      { key: "retransmission_rate_warning", label: "Retransmission Rate Warning (%)", desc: "Flag as critical when retransmission rate exceeds this percentage." },
      { key: "high_handshake_ms", label: "Slow Handshake Threshold (ms)", desc: "Flag handshakes slower than this as anomalies." },
      { key: "high_delta_ms", label: "Slow App Response Threshold (ms)", desc: "Flag server response times exceeding this." },
    ],
  },
  {
    section: "security", label: "Security",
    fields: [
      { key: "port_scan_threshold", label: "Port Scan Threshold (unique ports)", desc: "Number of distinct ports a source must hit before flagging as a scan." },
      { key: "exfil_bytes_threshold", label: "Exfiltration Threshold (bytes)", desc: "Total outbound bytes to a single external IP to flag as exfiltration." },
      { key: "large_dns_payload", label: "DNS Tunneling Payload Size (bytes)", desc: "DNS packet size above which tunneling is suspected." },
    ],
  },
  {
    section: "protocol", label: "Protocol",
    fields: [
      { key: "high_dns_latency_ms", label: "Slow DNS Threshold (ms)", desc: "DNS resolution latency above this is flagged as an anomaly." },
    ],
  },
  {
    section: "beacon", label: "Beaconing",
    fields: [
      { key: "min_connections", label: "Minimum Connections", desc: "Minimum number of SYN packets to a single destination before analysing for beaconing." },
      { key: "max_cv", label: "Maximum CV (coefficient of variation)", desc: "Flows with CV below this threshold are flagged as beaconing. Lower = more regular = more suspicious." },
    ],
  },
  {
    section: "rst_forensics", label: "RST Forensics",
    fields: [
      { key: "nat_idle_threshold_sec", label: "NAT Timeout Idle Gap (seconds)", desc: "Idle gap before RST above which NAT/firewall session timeout is suspected." },
    ],
  },
  {
    section: "engine", label: "Engine",
    fields: [
      { key: "max_packets", label: "Max Packets to Analyze", desc: "Maximum number of packets loaded from a PCAP. Larger values use more memory." },
    ],
  },
];

export default function SettingsPage({ onBack }) {
  const [values, setValues] = useState({});
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    fetch("/api/settings/thresholds")
      .then(r => r.json())
      .then(data => { setValues(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  function handleChange(section, key, val) {
    setValues(prev => ({
      ...prev,
      [section]: { ...prev[section], [key]: val },
    }));
  }

  async function handleSave() {
    try {
      const res = await fetch("/api/settings/thresholds", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      if (!res.ok) throw new Error("Save failed");
      const updated = await res.json();
      setValues(updated);
      setToast({ ok: true, msg: "Thresholds saved. They apply to the next analysis." });
    } catch {
      setToast({ ok: false, msg: "Failed to save thresholds." });
    }
    setTimeout(() => setToast(null), 4000);
  }

  async function handleReset() {
    try {
      const res = await fetch("/api/settings/thresholds/reset", { method: "POST" });
      const updated = await res.json();
      setValues(updated);
      setToast({ ok: true, msg: "Thresholds reset to defaults." });
    } catch {
      setToast({ ok: false, msg: "Failed to reset." });
    }
    setTimeout(() => setToast(null), 4000);
  }

  return (
    <div style={{ minHeight: "100vh", background: "#f0f4f8" }}>
      <style>{`
        .set-back:hover { background: #f1f5f9 !important; }
        .set-input:focus { border-color: #2563eb !important; box-shadow: 0 0 0 3px rgba(37,99,235,0.12) !important; }
        .set-save:hover { opacity: 0.9; }
        .set-reset:hover { background: #f1f5f9 !important; }
      `}</style>

      {/* Header */}
      <div style={{
        background: "#fff", borderBottom: "1px solid #e2e8f0",
        padding: "0 2rem", height: 60,
        display: "flex", alignItems: "center", gap: "1rem",
        boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
      }}>
        <button className="set-back" onClick={onBack} style={{
          background: "transparent", border: "1px solid #e2e8f0", color: "#475569",
          borderRadius: "8px", padding: "0.4rem 0.9rem", cursor: "pointer",
          display: "flex", alignItems: "center", gap: "0.4rem",
          fontSize: "0.83rem", fontWeight: 500, transition: "background 0.15s",
        }}>
          <ArrowLeft size={14} /> Back
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Settings size={18} color="#2563eb" />
          <h1 style={{ fontSize: "1.15rem", fontWeight: 800, color: "#0f172a" }}>Detection Thresholds</h1>
        </div>
      </div>

      <div style={{ padding: "2rem", maxWidth: "700px", margin: "0 auto" }}>
        <p style={{ color: "#64748b", fontSize: "0.875rem", marginBottom: "2rem", lineHeight: 1.6 }}>
          Tune every detection threshold to match your network environment.
          Changes apply to the <strong style={{ color: "#1e293b" }}>next</strong> analysis run.
        </p>

        {loading ? (
          <div style={{ textAlign: "center", color: "#94a3b8", padding: "3rem" }}>Loading settings…</div>
        ) : (
          FIELDS.map(({ section, label, fields }) => {
            const colors = SECTION_COLORS[section] || { bg: "#f8fafc", border: "#e2e8f0", icon: "#475569" };
            const Icon = SECTION_ICONS[section] || Settings;
            return (
              <div key={section} style={{
                background: "#fff", border: "1px solid #e2e8f0",
                borderRadius: "14px", padding: "1.5rem",
                marginBottom: "1.25rem",
                boxShadow: "0 1px 4px rgba(0,0,0,0.05)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "1.25rem" }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: "8px",
                    background: colors.bg, border: `1px solid ${colors.border}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <Icon size={15} color={colors.icon} />
                  </div>
                  <span style={{
                    fontSize: "0.82rem", fontWeight: 700, color: "#475569",
                    textTransform: "uppercase", letterSpacing: "0.07em",
                  }}>{label}</span>
                </div>
                {fields.map(f => (
                  <div key={f.key} style={{ marginBottom: "1rem" }}>
                    <label style={{
                      display: "block", fontSize: "0.85rem",
                      color: "#1e293b", fontWeight: 600, marginBottom: "0.2rem",
                    }}>{f.label}</label>
                    <p style={{ fontSize: "0.75rem", color: "#94a3b8", marginBottom: "0.4rem" }}>{f.desc}</p>
                    <input
                      className="set-input"
                      type="number"
                      step="any"
                      style={{
                        width: "100%", padding: "0.5rem 0.75rem",
                        background: "#f8fafc", border: "1px solid #e2e8f0",
                        borderRadius: "8px", color: "#1e293b",
                        fontSize: "0.88rem", outline: "none",
                        transition: "border-color 0.15s, box-shadow 0.15s",
                        boxSizing: "border-box",
                      }}
                      value={values[section]?.[f.key] ?? ""}
                      onChange={e => handleChange(section, f.key, parseFloat(e.target.value) || 0)}
                    />
                  </div>
                ))}
              </div>
            );
          })
        )}

        <div style={{ display: "flex", gap: "0.75rem", marginTop: "1rem" }}>
          <button className="set-save" onClick={handleSave} style={{
            padding: "0.65rem 1.75rem",
            background: "linear-gradient(135deg, #2563eb, #4f46e5)",
            color: "#fff", border: "none", borderRadius: "10px",
            fontSize: "0.9rem", fontWeight: 700, cursor: "pointer",
            display: "flex", alignItems: "center", gap: "0.4rem",
            boxShadow: "0 3px 10px rgba(37,99,235,0.25)", transition: "opacity 0.2s",
          }}>
            <Save size={15} /> Save Thresholds
          </button>
          <button className="set-reset" onClick={handleReset} style={{
            padding: "0.65rem 1.25rem",
            background: "transparent", color: "#64748b",
            border: "1px solid #e2e8f0", borderRadius: "10px",
            fontSize: "0.9rem", cursor: "pointer",
            display: "flex", alignItems: "center", gap: "0.4rem",
            transition: "background 0.15s",
          }}>
            <RotateCcw size={14} /> Reset to Defaults
          </button>
        </div>

        {toast && (
          <div style={{
            padding: "0.85rem 1.25rem", borderRadius: "10px", fontSize: "0.875rem",
            background: toast.ok ? "#f0fdf4" : "#fef2f2",
            border: `1px solid ${toast.ok ? "#bbf7d0" : "#fecaca"}`,
            color: toast.ok ? "#16a34a" : "#dc2626",
            marginTop: "1rem",
            display: "flex", alignItems: "center", gap: "0.5rem",
          }}>
            {toast.ok ? "✓" : "⚠"} {toast.msg}
          </div>
        )}
      </div>
    </div>
  );
}
