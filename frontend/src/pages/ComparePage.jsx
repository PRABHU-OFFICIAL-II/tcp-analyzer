import { useState, useRef } from "react";
import { ArrowLeft, GitCompare, TrendingUp, TrendingDown, Minus } from "lucide-react";

const s = {
  page: { minHeight: "100vh", background: "#0f1117", padding: "2rem" },
  header: { display: "flex", alignItems: "center", gap: "1rem", marginBottom: "2rem" },
  backBtn: { background: "none", border: "1px solid #3b4268", color: "#94a3b8",
    borderRadius: "8px", padding: "0.5rem 1rem", cursor: "pointer",
    display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.875rem" },
  title: { fontSize: "1.5rem", fontWeight: 700, color: "#f1f5f9" },
  grid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "2rem" },
  dropzone: { border: "2px dashed #3b4268", borderRadius: "12px", padding: "2rem",
    textAlign: "center", cursor: "pointer", background: "#1a1d27", transition: "border-color 0.2s" },
  dropText: { color: "#94a3b8", fontSize: "0.9rem" },
  btn: { padding: "0.7rem 2rem", background: "#3b82f6", color: "#fff",
    border: "none", borderRadius: "8px", fontSize: "0.95rem", fontWeight: 600,
    cursor: "pointer", display: "flex", alignItems: "center", gap: "0.5rem" },
  spinner: { width: "18px", height: "18px", border: "2px solid rgba(255,255,255,0.3)",
    borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" },
  error: { marginTop: "1rem", padding: "0.75rem 1.25rem", background: "#3b1a1a",
    border: "1px solid #7f1d1d", borderRadius: "8px", color: "#fca5a5" },
};

const DIRECTION_ICON = {
  improved: <TrendingDown size={14} color="#22c55e" />,
  degraded:  <TrendingUp size={14} color="#ef4444" />,
  neutral:   <Minus size={14} color="#64748b" />,
};
const DIRECTION_COLOR = { improved: "#22c55e", degraded: "#ef4444", neutral: "#94a3b8" };

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
    <div style={s.page}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <div style={s.header}>
        <button style={s.backBtn} onClick={onBack}><ArrowLeft size={15} /> Back</button>
        <h1 style={s.title}>Compare PCAPs</h1>
      </div>

      <div style={s.grid}>
        {[["Baseline (Before)", file1, setFile1, ref1], ["Candidate (After)", file2, setFile2, ref2]].map(([label, file, setFile, ref]) => (
          <div key={label} style={{ ...s.dropzone, borderColor: file ? "#60a5fa" : "#3b4268" }}
            onClick={() => ref.current.click()}>
            <p style={{ color: "#60a5fa", fontWeight: 600, marginBottom: "0.5rem" }}>{label}</p>
            <p style={s.dropText}>{file ? file.name : "Click to select .pcap file"}</p>
            <input ref={ref} type="file" accept=".pcap,.pcapng,.cap" style={{ display: "none" }}
              onChange={e => setFile(e.target.files[0])} />
          </div>
        ))}
      </div>

      {file1 && file2 && (
        <button style={s.btn} disabled={loading} onClick={handleCompare}>
          {loading ? <><div style={s.spinner} /> Comparing...</> : <><GitCompare size={16} /> Compare</>}
        </button>
      )}
      {error && <div style={s.error}>{error}</div>}

      {result && (
        <div style={{ marginTop: "2rem" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#e2e8f0", marginBottom: "1rem" }}>
            {result.file1_name} <span style={{ color: "#64748b" }}>vs</span> {result.file2_name}
          </h2>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #2d3148" }}>
                  <th style={{ textAlign: "left", padding: "0.6rem 0.75rem", color: "#64748b", fontWeight: 600 }}>Metric</th>
                  <th style={{ textAlign: "right", padding: "0.6rem 0.75rem", color: "#60a5fa", fontWeight: 600 }}>{result.file1_name}</th>
                  <th style={{ textAlign: "right", padding: "0.6rem 0.75rem", color: "#a78bfa", fontWeight: 600 }}>{result.file2_name}</th>
                  <th style={{ textAlign: "right", padding: "0.6rem 0.75rem", color: "#64748b", fontWeight: 600 }}>Delta</th>
                  <th style={{ padding: "0.6rem 0.75rem" }}></th>
                </tr>
              </thead>
              <tbody>
                {result.diffs.map((d, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#e2e8f0" }}>{d.label}</td>
                    <td style={{ padding: "0.5rem 0.75rem", textAlign: "right", color: "#94a3b8", fontFamily: "monospace" }}>
                      {d.file1_value ?? "—"}
                    </td>
                    <td style={{ padding: "0.5rem 0.75rem", textAlign: "right", color: "#94a3b8", fontFamily: "monospace" }}>
                      {d.file2_value ?? "—"}
                    </td>
                    <td style={{ padding: "0.5rem 0.75rem", textAlign: "right", fontFamily: "monospace",
                      color: DIRECTION_COLOR[d.direction] || "#94a3b8" }}>
                      {d.delta != null ? (d.delta > 0 ? `+${d.delta}` : d.delta) : "—"}
                    </td>
                    <td style={{ padding: "0.5rem 0.75rem" }}>{DIRECTION_ICON[d.direction]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
