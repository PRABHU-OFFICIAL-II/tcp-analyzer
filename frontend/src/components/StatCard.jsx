export default function StatCard({ label, value, unit = "", color = "#60a5fa" }) {
  return (
    <div style={{
      background: "#1e2130", border: "1px solid #2d3148",
      borderRadius: "12px", padding: "1.25rem",
      display: "flex", flexDirection: "column", gap: "0.4rem",
    }}>
      <span style={{ fontSize: "0.78rem", color: "#64748b", textTransform: "uppercase",
        letterSpacing: "0.06em", fontWeight: 600 }}>{label}</span>
      <span style={{ fontSize: "1.75rem", fontWeight: 700, color }}>
        {value ?? "—"}
        {unit && <span style={{ fontSize: "0.95rem", color: "#94a3b8", marginLeft: "0.25rem" }}>{unit}</span>}
      </span>
    </div>
  );
}
