const SEVERITY_STYLES = {
  critical: { border: "#fca5a5", bg: "#fef2f2", left: "#ef4444", badge: "#ef4444", badgeText: "#fff", label: "CRITICAL" },
  warning:  { border: "#fde68a", bg: "#fffbeb", left: "#f59e0b", badge: "#f59e0b", badgeText: "#fff", label: "WARNING"  },
  info:     { border: "#bfdbfe", bg: "#eff6ff", left: "#3b82f6", badge: "#3b82f6", badgeText: "#fff", label: "INFO"     },
  clean:    { border: "#bbf7d0", bg: "#f0fdf4", left: "#22c55e", badge: "#22c55e", badgeText: "#fff", label: "OK"        },
};

export default function DiagnosisCard({ diagnosis }) {
  const st = SEVERITY_STYLES[diagnosis.severity] || SEVERITY_STYLES.info;
  return (
    <div style={{
      border: `1px solid ${st.border}`,
      borderLeft: `4px solid ${st.left}`,
      background: st.bg,
      borderRadius: "10px",
      padding: "1rem 1.25rem",
      marginBottom: "0.75rem",
      boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.4rem" }}>
        <span style={{
          background: st.badge, color: st.badgeText,
          fontSize: "0.68rem", fontWeight: 700,
          padding: "2px 8px", borderRadius: "4px", letterSpacing: "0.06em",
        }}>{st.label}</span>
        <span style={{ fontWeight: 600, color: "#0f172a", fontSize: "0.9rem" }}>{diagnosis.headline}</span>
      </div>
      {diagnosis.details.length > 0 && (
        <ul style={{ paddingLeft: "1.25rem", color: "#475569", fontSize: "0.85rem", lineHeight: 1.7 }}>
          {diagnosis.details.map((d, i) => <li key={i}>{d}</li>)}
        </ul>
      )}
    </div>
  );
}
