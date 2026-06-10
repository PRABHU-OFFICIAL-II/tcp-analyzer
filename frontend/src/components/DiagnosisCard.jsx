const SEVERITY_STYLES = {
  critical: { border: "#ef4444", bg: "#2d1515", badge: "#ef4444", badgeText: "#fff", label: "CRITICAL" },
  warning:  { border: "#f59e0b", bg: "#2d2415", badge: "#f59e0b", badgeText: "#000", label: "WARNING"  },
  info:     { border: "#3b82f6", bg: "#15202d", badge: "#3b82f6", badgeText: "#fff", label: "INFO"     },
  clean:    { border: "#22c55e", bg: "#152d1e", badge: "#22c55e", badgeText: "#000", label: "OK"        },
};

export default function DiagnosisCard({ diagnosis }) {
  const st = SEVERITY_STYLES[diagnosis.severity] || SEVERITY_STYLES.info;
  return (
    <div style={{
      border: `1px solid ${st.border}`,
      borderLeft: `4px solid ${st.border}`,
      background: st.bg,
      borderRadius: "10px",
      padding: "1rem 1.25rem",
      marginBottom: "0.75rem",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
        <span style={{
          background: st.badge, color: st.badgeText,
          fontSize: "0.7rem", fontWeight: 700,
          padding: "2px 8px", borderRadius: "4px", letterSpacing: "0.05em",
        }}>{st.label}</span>
        <span style={{ fontWeight: 600, color: "#f1f5f9" }}>{diagnosis.headline}</span>
      </div>
      {diagnosis.details.length > 0 && (
        <ul style={{ paddingLeft: "1.25rem", color: "#94a3b8", fontSize: "0.875rem" }}>
          {diagnosis.details.map((d, i) => <li key={i} style={{ marginBottom: "0.25rem" }}>{d}</li>)}
        </ul>
      )}
    </div>
  );
}
