import { useState } from "react";
import { Download, FileText, FileJson, Globe, Loader } from "lucide-react";

const EXPORTS = [
  { label: "PDF",  icon: FileText, color: "#dc2626", bg: "#fef2f2", border: "#fecaca", suffix: "pdf",  mime: "application/pdf" },
  { label: "CSV",  icon: Download, color: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0", suffix: "csv",  mime: "text/csv" },
  { label: "JSON", icon: FileJson, color: "#2563eb", bg: "#eff6ff", border: "#bfdbfe", suffix: "json", mime: "application/json" },
  { label: "HTML", icon: Globe,    color: "#d97706", bg: "#fffbeb", border: "#fde68a", suffix: "html", mime: "text/html" },
];

export default function ExportBar({ report }) {
  const [busy, setBusy] = useState(null);

  if (!report) return null;

  async function handleExport(suffix, mime, label) {
    setBusy(suffix);
    try {
      const res = await fetch(`/api/export/${suffix}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Export failed" }));
        alert(`Export failed: ${err.detail}`);
        return;
      }
      const blob = await res.blob();
      const aid  = (report.analysis_id || "report").slice(0, 8);
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `report_${aid}.${suffix}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert(`Export error: ${e.message}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div style={{
      display: "flex", gap: "0.6rem", flexWrap: "wrap",
      padding: "0.875rem 1.25rem",
      background: "#fff", border: "1px solid #e2e8f0",
      borderRadius: "12px", marginBottom: "1.5rem",
      alignItems: "center",
      boxShadow: "0 1px 4px rgba(0,0,0,0.05)",
    }}>
      <span style={{
        color: "#64748b", fontSize: "0.75rem", fontWeight: 700,
        textTransform: "uppercase", letterSpacing: "0.07em", marginRight: "0.25rem",
      }}>
        Export:
      </span>
      {EXPORTS.map(({ label, icon: Icon, color, bg, border, suffix, mime }) => {
        const loading = busy === suffix;
        return (
          <button
            key={suffix}
            disabled={!!busy}
            onClick={() => handleExport(suffix, mime, label)}
            style={{
              display: "inline-flex", alignItems: "center", gap: "0.35rem",
              padding: "0.4rem 0.85rem",
              background: bg, border: `1px solid ${border}`,
              borderRadius: "8px", color,
              fontSize: "0.8rem", fontWeight: 600,
              cursor: busy ? "not-allowed" : "pointer",
              opacity: busy && !loading ? 0.5 : 1,
              transition: "opacity 0.15s",
            }}
          >
            {loading
              ? <Loader size={13} style={{ animation: "spin 0.7s linear infinite" }} />
              : <Icon size={13} />}
            {label}
          </button>
        );
      })}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
