import { useState, useRef } from "react";
import { ArrowLeft, GitCompare, TrendingUp, TrendingDown, Minus, Upload } from "lucide-react";

const DIRECTION_ICON = {
  improved: <TrendingDown size={14} color="#16a34a" />,
  degraded:  <TrendingUp size={14} color="#dc2626" />,
  neutral:   <Minus size={14} color="#94a3b8" />,
};
const DIRECTION_COLOR = { improved: "#16a34a", degraded: "#dc2626", neutral: "#94a3b8" };

export default function ComparePage({ onBack }) {
  const [file1, setFile1] = useState(null);
  const [file2, setFile2] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const ref1 = useRef(), ref2 = useRef();

  async function handleCompare() {
    if (!file1 || !file2) return;
    setLoading(true); setError(null); setResult(null);
    const form = new FormData();
    form.append("file1", file1);
    form.append("file2", file2);
    try {
      const res = await fetch("/api/compare", { method: "POST", body: form });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail); }
      setResult(await res.json());
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ minHeight: "100vh", background: "#f0f4f8" }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }
        .cmp-back:hover { background: #f1f5f9 !important; }
        .cmp-dz:hover { border-color: #2563eb !important; background: #f8fafc !important; }
        .cmp-btn:hover { opacity: 0.9; }
      `}</style>

      {/* Header */}
      <div style={{
        background: "#fff", borderBottom: "1px solid #e2e8f0",
        padding: "0 2rem", height: 60,
        display: "flex", alignItems: "center", gap: "1rem",
        boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
      }}>
        <button className="cmp-back" onClick={onBack} style={{
          background: "transparent", border: "1px solid #e2e8f0", color: "#475569",
          borderRadius: "8px", padding: "0.4rem 0.9rem", cursor: "pointer",
          display: "flex", alignItems: "center", gap: "0.4rem",
          fontSize: "0.83rem", fontWeight: 500, transition: "background 0.15s",
        }}>
          <ArrowLeft size={14} /> Back
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <GitCompare size={18} color="#2563eb" />
          <h1 style={{ fontSize: "1.15rem", fontWeight: 800, color: "#0f172a" }}>Compare PCAPs</h1>
        </div>
      </div>

      <div style={{ padding: "2rem", maxWidth: "960px", margin: "0 auto" }}>
        <p style={{ color: "#64748b", fontSize: "0.9rem", marginBottom: "2rem" }}>
          Upload two PCAP files to compare metrics side by side — identify regressions or improvements between captures.
        </p>

        {/* File selectors */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem", marginBottom: "1.5rem" }}>
          {[
            ["Baseline (Before)", file1, setFile1, ref1, "#2563eb", "#eff6ff", "#bfdbfe"],
            ["Candidate (After)", file2, setFile2, ref2, "#7c3aed", "#f5f3ff", "#ddd6fe"],
          ].map(([label, file, setFile, ref, accent, bg, border]) => (
            <div key={label} className="cmp-dz" onClick={() => ref.current.click()} style={{
              border: `2px dashed ${file ? accent : "#cbd5e1"}`,
              borderRadius: "16px", padding: "2rem 1.5rem", textAlign: "center",
              cursor: "pointer", background: file ? bg : "#fff",
              transition: "all 0.2s", boxShadow: "0 2px 8px rgba(0,0,0,0.06)",
            }}>
              <div style={{
                width: 44, height: 44, borderRadius: "12px",
                background: file ? bg : "#f8fafc",
                border: `1px solid ${file ? border : "#e2e8f0"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                margin: "0 auto 0.75rem",
              }}>
                <Upload size={20} color={file ? accent : "#94a3b8"} />
              </div>
              <p style={{ fontWeight: 700, fontSize: "0.85rem", color: accent, marginBottom: "0.25rem" }}>{label}</p>
              <p style={{ fontSize: "0.8rem", color: file ? "#475569" : "#94a3b8", fontWeight: file ? 500 : 400 }}>
                {file ? file.name : "Click to select .pcap file"}
              </p>
              <input ref={ref} type="file" accept=".pcap,.pcapng,.cap" style={{ display: "none" }}
                onChange={e => setFile(e.target.files[0])} />
            </div>
          ))}
        </div>

        {file1 && file2 && (
          <button className="cmp-btn" disabled={loading} onClick={handleCompare} style={{
            padding: "0.75rem 2rem",
            background: "linear-gradient(135deg, #2563eb, #4f46e5)",
            color: "#fff", border: "none", borderRadius: "10px",
            fontSize: "0.9rem", fontWeight: 700, cursor: loading ? "not-allowed" : "pointer",
            display: "inline-flex", alignItems: "center", gap: "0.5rem",
            boxShadow: "0 3px 12px rgba(37,99,235,0.30)", transition: "opacity 0.2s",
          }}>
            {loading
              ? <><div style={{ width: 17, height: 17, border: "2px solid rgba(255,255,255,0.4)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} /> Comparing...</>
              : <><GitCompare size={15} /> Compare</>}
          </button>
        )}

        {error && (
          <div style={{
            marginTop: "1rem", padding: "0.85rem 1.25rem",
            background: "#fef2f2", border: "1px solid #fecaca",
            borderRadius: "10px", color: "#dc2626", fontSize: "0.875rem",
          }}>
            ⚠ {error}
          </div>
        )}

        {result && (
          <div style={{ marginTop: "2rem" }}>
            <h2 style={{ fontSize: "1rem", fontWeight: 700, color: "#1e293b", marginBottom: "1rem" }}>
              <span style={{ color: "#2563eb" }}>{result.file1_name}</span>
              {" "}
              <span style={{ color: "#94a3b8", fontWeight: 400 }}>vs</span>
              {" "}
              <span style={{ color: "#7c3aed" }}>{result.file2_name}</span>
            </h2>
            <div style={{
              background: "#fff", borderRadius: "12px", border: "1px solid #e2e8f0",
              overflow: "hidden", boxShadow: "0 2px 8px rgba(0,0,0,0.06)",
            }}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.83rem" }}>
                  <thead>
                    <tr style={{ background: "#f8fafc", borderBottom: "2px solid #e2e8f0" }}>
                      {["Metric", result.file1_name, result.file2_name, "Delta", ""].map((h, i) => (
                        <th key={i} style={{
                          textAlign: i === 0 ? "left" : i < 4 ? "right" : "center",
                          padding: "0.65rem 0.9rem",
                          color: i === 1 ? "#2563eb" : i === 2 ? "#7c3aed" : "#64748b",
                          fontWeight: 600, fontSize: "0.8rem",
                        }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.diffs.map((d, i) => (
                      <tr key={i} style={{
                        borderBottom: "1px solid #f1f5f9",
                        background: i % 2 === 0 ? "#fff" : "#fafbfc",
                      }}>
                        <td style={{ padding: "0.55rem 0.9rem", color: "#1e293b", fontWeight: 500 }}>{d.label}</td>
                        <td style={{ padding: "0.55rem 0.9rem", textAlign: "right", color: "#475569", fontFamily: "monospace" }}>
                          {d.file1_value ?? "—"}
                        </td>
                        <td style={{ padding: "0.55rem 0.9rem", textAlign: "right", color: "#475569", fontFamily: "monospace" }}>
                          {d.file2_value ?? "—"}
                        </td>
                        <td style={{
                          padding: "0.55rem 0.9rem", textAlign: "right",
                          fontFamily: "monospace", fontWeight: 600,
                          color: DIRECTION_COLOR[d.direction] || "#94a3b8",
                        }}>
                          {d.delta != null ? (d.delta > 0 ? `+${d.delta}` : d.delta) : "—"}
                        </td>
                        <td style={{ padding: "0.55rem 0.9rem", textAlign: "center" }}>
                          {DIRECTION_ICON[d.direction]}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
