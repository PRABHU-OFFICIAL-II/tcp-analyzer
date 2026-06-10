import { Download, FileText, FileJson } from "lucide-react";

const s = {
  bar: {
    display: "flex", gap: "0.75rem", flexWrap: "wrap",
    padding: "1rem 1.25rem",
    background: "#1e2130", border: "1px solid #2d3148",
    borderRadius: "10px", marginBottom: "1.5rem",
    alignItems: "center",
  },
  label: { color: "#64748b", fontSize: "0.8rem", fontWeight: 600,
    textTransform: "uppercase", letterSpacing: "0.06em", marginRight: "0.25rem" },
  btn: (color) => ({
    display: "flex", alignItems: "center", gap: "0.4rem",
    padding: "0.45rem 1rem", borderRadius: "7px",
    border: `1px solid ${color}`, background: "transparent",
    color, fontSize: "0.82rem", fontWeight: 600,
    cursor: "pointer", transition: "background 0.15s",
    textDecoration: "none",
  }),
};

export default function ExportBar({ analysisId }) {
  if (!analysisId) return null;

  const base = `/api/export/${analysisId}`;

  return (
    <div style={s.bar}>
      <span style={s.label}>Export:</span>
      <a href={`${base}/pdf`} download style={s.btn("#f87171")}>
        <FileText size={14} /> PDF
      </a>
      <a href={`${base}/csv`} download style={s.btn("#4ade80")}>
        <Download size={14} /> CSV
      </a>
      <a href={`${base}/json`} download style={s.btn("#60a5fa")}>
        <FileJson size={14} /> JSON
      </a>
    </div>
  );
}
