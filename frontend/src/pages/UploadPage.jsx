import { useRef, useState } from "react";
import { Upload, ShieldCheck, Zap, Bug, Clock, GitCompare } from "lucide-react";

const s = {
  page: { minHeight: "100vh", display: "flex", flexDirection: "column",
    alignItems: "center", justifyContent: "center", padding: "2rem",
    background: "linear-gradient(135deg, #0f1117 0%, #1a1d27 100%)" },
  hero: { textAlign: "center", marginBottom: "2.5rem" },
  title: { fontSize: "2.5rem", fontWeight: 700, color: "#fff", marginBottom: "0.5rem" },
  subtitle: { fontSize: "1.1rem", color: "#94a3b8" },
  accent: { color: "#60a5fa" },
  navRow: { display: "flex", gap: "0.75rem", marginBottom: "2rem", flexWrap: "wrap", justifyContent: "center" },
  navBtn: { background: "#1e2130", border: "1px solid #2d3148", color: "#94a3b8",
    borderRadius: "8px", padding: "0.5rem 1rem", cursor: "pointer",
    display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.85rem",
    transition: "border-color 0.15s, color 0.15s" },
  features: { display: "flex", gap: "1.25rem", marginBottom: "2.5rem", flexWrap: "wrap", justifyContent: "center" },
  featureCard: { background: "#1e2130", border: "1px solid #2d3148", borderRadius: "12px",
    padding: "1rem 1.25rem", display: "flex", alignItems: "center", gap: "0.6rem", minWidth: "180px" },
  featureText: { fontSize: "0.85rem", color: "#cbd5e1" },
  dropzone: { border: "2px dashed #3b4268", borderRadius: "16px", padding: "3rem",
    textAlign: "center", cursor: "pointer", background: "#1a1d27",
    width: "100%", maxWidth: "500px", transition: "border-color 0.2s, background 0.2s" },
  dropzoneDrag: { borderColor: "#60a5fa", background: "#1e2a3a" },
  uploadIcon: { marginBottom: "1rem", color: "#60a5fa" },
  dropText: { fontSize: "1rem", color: "#94a3b8", marginBottom: "0.5rem" },
  dropHint: { fontSize: "0.8rem", color: "#64748b" },
  button: { marginTop: "1.5rem", padding: "0.75rem 2rem", background: "#3b82f6", color: "#fff",
    border: "none", borderRadius: "8px", fontSize: "1rem", fontWeight: 600, cursor: "pointer",
    display: "inline-flex", alignItems: "center", gap: "0.5rem", transition: "background 0.2s" },
  spinner: { width: "20px", height: "20px", border: "2px solid rgba(255,255,255,0.3)",
    borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" },
  error: { marginTop: "1rem", padding: "0.75rem 1.25rem", background: "#3b1a1a",
    border: "1px solid #7f1d1d", borderRadius: "8px", color: "#fca5a5",
    maxWidth: "500px", width: "100%" },
};

const features = [
  { icon: <Zap size={18} color="#facc15" />, label: "Performance" },
  { icon: <ShieldCheck size={18} color="#4ade80" />, label: "Security" },
  { icon: <Bug size={18} color="#f87171" />, label: "Protocol" },
];

export default function UploadPage({ onUpload, loading, error, onHistory, onCompare }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  return (
    <div style={s.page}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <div style={s.hero}>
        <h1 style={s.title}>TCP <span style={s.accent}>Analyzer</span></h1>
        <p style={s.subtitle}>Upload a PCAP file or capture live traffic for instant network analysis</p>
      </div>

      <div style={s.navRow}>
        <button style={s.navBtn} onClick={onHistory}><Clock size={14} /> History</button>
        <button style={s.navBtn} onClick={onCompare}><GitCompare size={14} /> Compare PCAPs</button>
      </div>

      <div style={s.features}>
        {features.map(f => (
          <div key={f.label} style={s.featureCard}>{f.icon}<span style={s.featureText}>{f.label}</span></div>
        ))}
      </div>

      <div
        style={{ ...s.dropzone, ...(dragging ? s.dropzoneDrag : {}) }}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); setSelectedFile(e.dataTransfer.files[0]); }}
        onClick={() => inputRef.current?.click()}
      >
        <div style={s.uploadIcon}><Upload size={40} /></div>
        <p style={s.dropText}>{selectedFile ? selectedFile.name : "Drag & drop your PCAP file here"}</p>
        <p style={s.dropHint}>Supports .pcap, .pcapng, .cap</p>
        <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" style={{ display: "none" }}
          onChange={e => setSelectedFile(e.target.files[0])} />
      </div>

      {selectedFile && (
        <button style={s.button} disabled={loading} onClick={() => onUpload(selectedFile)}>
          {loading ? <><div style={s.spinner} /> Analyzing...</> : <><Zap size={18} /> Analyze</>}
        </button>
      )}
      {error && <div style={s.error}>{error}</div>}
    </div>
  );
}
