import { useEffect, useState } from "react";
import { ArrowLeft, Save, RotateCcw } from "lucide-react";

const s = {
  page: { minHeight: "100vh", background: "#0f1117", padding: "2rem", maxWidth: "700px", margin: "0 auto" },
  header: { display: "flex", alignItems: "center", gap: "1rem", marginBottom: "2rem" },
  backBtn: { background: "none", border: "1px solid #3b4268", color: "#94a3b8",
    borderRadius: "8px", padding: "0.5rem 1rem", cursor: "pointer",
    display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.875rem" },
  title: { fontSize: "1.5rem", fontWeight: 700, color: "#f1f5f9" },
  section: { background: "#1e2130", border: "1px solid #2d3148", borderRadius: "12px",
    padding: "1.5rem", marginBottom: "1.5rem" },
  sectionTitle: { fontSize: "0.9rem", fontWeight: 700, color: "#94a3b8",
    textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "1.25rem" },
  field: { marginBottom: "1rem" },
  label: { display: "block", fontSize: "0.82rem", color: "#94a3b8", marginBottom: "0.35rem", fontWeight: 500 },
  desc: { fontSize: "0.75rem", color: "#475569", marginBottom: "0.4rem" },
  input: { width: "100%", padding: "0.5rem 0.75rem", background: "#0f1117",
    border: "1px solid #3b4268", borderRadius: "6px", color: "#e2e8f0",
    fontSize: "0.88rem", outline: "none" },
  actions: { display: "flex", gap: "0.75rem", marginTop: "1.5rem" },
  saveBtn: { padding: "0.6rem 1.5rem", background: "#3b82f6", color: "#fff",
    border: "none", borderRadius: "8px", fontSize: "0.9rem", fontWeight: 600,
    cursor: "pointer", display: "flex", alignItems: "center", gap: "0.4rem" },
  resetBtn: { padding: "0.6rem 1.25rem", background: "none", color: "#94a3b8",
    border: "1px solid #3b4268", borderRadius: "8px", fontSize: "0.9rem",
    cursor: "pointer", display: "flex", alignItems: "center", gap: "0.4rem" },
  toast: (ok) => ({
    padding: "0.75rem 1.25rem", borderRadius: "8px", fontSize: "0.875rem",
    background: ok ? "#152d1e" : "#2d1515",
    border: `1px solid ${ok ? "#22c55e" : "#ef4444"}`,
    color: ok ? "#4ade80" : "#fca5a5",
    marginTop: "1rem",
  }),
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
    } catch (e) {
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
    <div style={s.page}>
      <div style={s.header}>
        <button style={s.backBtn} onClick={onBack}><ArrowLeft size={15} /> Back</button>
        <h1 style={s.title}>Detection Thresholds</h1>
      </div>

      <p style={{ color: "#64748b", fontSize: "0.875rem", marginBottom: "1.5rem" }}>
        Tune every detection threshold to match your network environment.
        Changes apply to the <strong style={{ color: "#94a3b8" }}>next</strong> analysis run.
      </p>

      {loading ? (
        <p style={{ color: "#4b5563" }}>Loading...</p>
      ) : (
        FIELDS.map(({ section, label, fields }) => (
          <div key={section} style={s.section}>
            <div style={s.sectionTitle}>{label}</div>
            {fields.map(f => (
              <div key={f.key} style={s.field}>
                <label style={s.label}>{f.label}</label>
                <div style={s.desc}>{f.desc}</div>
                <input
                  type="number"
                  step="any"
                  style={s.input}
                  value={values[section]?.[f.key] ?? ""}
                  onChange={e => handleChange(section, f.key, parseFloat(e.target.value) || 0)}
                />
              </div>
            ))}
          </div>
        ))
      )}

      <div style={s.actions}>
        <button style={s.saveBtn} onClick={handleSave}><Save size={15} /> Save</button>
        <button style={s.resetBtn} onClick={handleReset}><RotateCcw size={14} /> Reset to Defaults</button>
      </div>

      {toast && <div style={s.toast(toast.ok)}>{toast.msg}</div>}
    </div>
  );
}
