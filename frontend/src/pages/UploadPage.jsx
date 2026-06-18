import { useRef, useState } from "react";
import { Upload, ShieldCheck, Zap, Activity, GitCompare, Settings, Network, Lock, Radio, BarChart2 } from "lucide-react";

export default function UploadPage({ onUpload, loading, error, onCompare, onSettings }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  return (
    <div style={{
      minHeight: "100vh", background: "#f0f4f8",
      display: "flex", flexDirection: "column",
    }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        .nav-btn:hover { background: #f1f5f9 !important; color: #1e293b !important; }
        .upload-btn:hover { opacity: 0.92; }
        .dropzone:hover { border-color: #2563eb !important; background: #f8fafc !important; }
        .feature-card:hover { box-shadow: 0 4px 16px rgba(37,99,235,0.10) !important; transform: translateY(-2px); }
      `}</style>

      {/* Top nav bar */}
      <nav style={{
        background: "#fff", borderBottom: "1px solid #e2e8f0",
        padding: "0 2rem", height: 60,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <div style={{
            width: 34, height: 34, borderRadius: "9px",
            background: "linear-gradient(135deg, #2563eb, #4f46e5)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 2px 8px rgba(79,70,229,0.30)",
          }}>
            <Activity size={18} color="#fff" />
          </div>
          <span style={{ fontWeight: 800, fontSize: "1.1rem", color: "#0f172a", letterSpacing: "-0.01em" }}>
            TCP <span style={{ color: "#2563eb" }}>Analyzer</span>
          </span>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button className="nav-btn" onClick={onCompare} style={{
            background: "transparent", border: "1px solid #e2e8f0", color: "#475569",
            borderRadius: "8px", padding: "0.4rem 0.9rem", cursor: "pointer",
            display: "flex", alignItems: "center", gap: "0.4rem",
            fontSize: "0.83rem", fontWeight: 500, transition: "all 0.15s",
          }}>
            <GitCompare size={14} /> Compare
          </button>
          <button className="nav-btn" onClick={onSettings} style={{
            background: "transparent", border: "1px solid #e2e8f0", color: "#475569",
            borderRadius: "8px", padding: "0.4rem 0.9rem", cursor: "pointer",
            display: "flex", alignItems: "center", gap: "0.4rem",
            fontSize: "0.83rem", fontWeight: 500, transition: "all 0.15s",
          }}>
            <Settings size={14} /> Settings
          </button>
        </div>
      </nav>

      {/* Hero */}
      <div style={{
        flex: 1, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
        padding: "3rem 2rem",
      }}>
        {/* Badge */}
        <div style={{
          background: "#eff6ff", border: "1px solid #bfdbfe", borderRadius: "20px",
          padding: "0.3rem 1rem", fontSize: "0.78rem", fontWeight: 600,
          color: "#2563eb", letterSpacing: "0.04em", marginBottom: "1.5rem",
          display: "flex", alignItems: "center", gap: "0.4rem",
        }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#2563eb", display: "inline-block" }} />
          13 ANALYSIS MODULES · REAL-TIME INSIGHTS
        </div>

        <h1 style={{
          fontSize: "3rem", fontWeight: 900, color: "#0f172a",
          letterSpacing: "-0.03em", textAlign: "center",
          lineHeight: 1.15, marginBottom: "1rem", maxWidth: 600,
        }}>
          Deep Network<br />
          <span style={{
            background: "linear-gradient(135deg, #2563eb, #4f46e5)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>Packet Analysis</span>
        </h1>
        <p style={{
          color: "#64748b", fontSize: "1.1rem", textAlign: "center",
          maxWidth: 480, lineHeight: 1.7, marginBottom: "2.5rem",
        }}>
          Upload a PCAP capture and get instant security, performance,
          and protocol insights — no Wireshark required.
        </p>

        {/* Feature pills */}
        <div style={{
          display: "flex", gap: "0.75rem", marginBottom: "3rem",
          flexWrap: "wrap", justifyContent: "center",
        }}>
          {[
            { icon: <ShieldCheck size={14} color="#16a34a" />, label: "Security Analysis", bg: "#f0fdf4", border: "#bbf7d0", text: "#15803d" },
            { icon: <Zap size={14} color="#d97706" />, label: "Performance Metrics", bg: "#fffbeb", border: "#fde68a", text: "#b45309" },
            { icon: <Lock size={14} color="#7c3aed" />, label: "TLS Inspection", bg: "#f5f3ff", border: "#ddd6fe", text: "#6d28d9" },
            { icon: <Radio size={14} color="#dc2626" />, label: "Beacon Detection", bg: "#fef2f2", border: "#fecaca", text: "#b91c1c" },
            { icon: <BarChart2 size={14} color="#0369a1" />, label: "Flow Analysis", bg: "#f0f9ff", border: "#bae6fd", text: "#0369a1" },
            { icon: <Network size={14} color="#475569" />, label: "RST Forensics", bg: "#f8fafc", border: "#e2e8f0", text: "#475569" },
          ].map(f => (
            <div key={f.label} className="feature-card" style={{
              background: f.bg, border: `1px solid ${f.border}`, borderRadius: "20px",
              padding: "0.4rem 0.9rem", display: "flex", alignItems: "center", gap: "0.4rem",
              transition: "all 0.2s", cursor: "default",
            }}>
              {f.icon}
              <span style={{ fontSize: "0.8rem", color: f.text, fontWeight: 600 }}>{f.label}</span>
            </div>
          ))}
        </div>

        {/* Drop zone */}
        <div
          className="dropzone"
          style={{
            border: `2px dashed ${dragging ? "#2563eb" : "#cbd5e1"}`,
            borderRadius: "20px", padding: "3rem 2.5rem",
            textAlign: "center", cursor: "pointer",
            background: dragging ? "#eff6ff" : "#fff",
            width: "100%", maxWidth: "520px",
            transition: "all 0.2s",
            boxShadow: "0 4px 24px rgba(0,0,0,0.07)",
          }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); setSelectedFile(e.dataTransfer.files[0]); }}
          onClick={() => inputRef.current?.click()}
        >
          <div style={{
            width: 60, height: 60, borderRadius: "16px",
            background: dragging ? "#dbeafe" : "#eff6ff",
            display: "flex", alignItems: "center", justifyContent: "center",
            margin: "0 auto 1.25rem",
            transition: "background 0.2s",
          }}>
            <Upload size={28} color="#2563eb" />
          </div>
          {selectedFile ? (
            <>
              <p style={{ fontSize: "1rem", fontWeight: 700, color: "#1e293b", marginBottom: "0.3rem" }}>
                {selectedFile.name}
              </p>
              <p style={{ fontSize: "0.82rem", color: "#64748b" }}>
                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB — click to change
              </p>
            </>
          ) : (
            <>
              <p style={{ fontSize: "1rem", fontWeight: 600, color: "#1e293b", marginBottom: "0.4rem" }}>
                Drop your PCAP file here
              </p>
              <p style={{ fontSize: "0.83rem", color: "#94a3b8" }}>
                or click to browse · .pcap · .pcapng · .cap
              </p>
            </>
          )}
          <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" style={{ display: "none" }}
            onChange={e => setSelectedFile(e.target.files[0])} />
        </div>

        {selectedFile && (
          <button
            className="upload-btn"
            style={{
              marginTop: "1.25rem", padding: "0.8rem 2.5rem",
              background: "linear-gradient(135deg, #2563eb, #4f46e5)",
              color: "#fff", border: "none", borderRadius: "12px",
              fontSize: "1rem", fontWeight: 700, cursor: loading ? "not-allowed" : "pointer",
              display: "inline-flex", alignItems: "center", gap: "0.6rem",
              boxShadow: "0 4px 16px rgba(37,99,235,0.35)", transition: "opacity 0.2s",
              opacity: loading ? 0.8 : 1,
            }}
            disabled={loading}
            onClick={() => onUpload(selectedFile)}
          >
            {loading
              ? <><div style={{ width: 18, height: 18, border: "2px solid rgba(255,255,255,0.4)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} /> Analyzing...</>
              : <><Zap size={18} /> Analyze PCAP</>}
          </button>
        )}

        {error && (
          <div style={{
            marginTop: "1rem", padding: "0.85rem 1.25rem",
            background: "#fef2f2", border: "1px solid #fecaca",
            borderRadius: "10px", color: "#dc2626",
            maxWidth: "520px", width: "100%", fontSize: "0.875rem",
            display: "flex", alignItems: "center", gap: "0.5rem",
          }}>
            ⚠ {error}
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{
        textAlign: "center", padding: "1.5rem",
        color: "#cbd5e1", fontSize: "0.78rem",
        borderTop: "1px solid #e2e8f0", background: "#fff",
      }}>
        TCP Analyzer v3.0 · Security &amp; Performance Intelligence
      </div>
    </div>
  );
}
