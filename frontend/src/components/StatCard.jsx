export default function StatCard({ label, value, unit = "", color = "#2563eb" }) {
  return (
    <div style={{
      background: "#fff",
      border: "1px solid #e2e8f0",
      borderRadius: "12px",
      padding: "1.25rem",
      display: "flex", flexDirection: "column", gap: "0.4rem",
      boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
    }}>
      <span style={{
        fontSize: "0.72rem", color: "#64748b",
        textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 600,
      }}>{label}</span>
      <span style={{ fontSize: "1.75rem", fontWeight: 700, color, lineHeight: 1 }}>
        {value ?? "—"}
        {unit && <span style={{ fontSize: "0.9rem", color: "#94a3b8", marginLeft: "0.25rem" }}>{unit}</span>}
      </span>
    </div>
  );
}
