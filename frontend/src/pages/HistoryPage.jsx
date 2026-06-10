import { useEffect, useState } from "react";
import { Clock, Trash2, ChevronRight, ArrowLeft, Trash } from "lucide-react";

const s = {
  page: { minHeight: "100vh", background: "#0f1117", padding: "2rem" },
  header: { display: "flex", alignItems: "center", gap: "1rem", marginBottom: "2rem", flexWrap: "wrap" },
  backBtn: { background: "none", border: "1px solid #3b4268", color: "#94a3b8",
    borderRadius: "8px", padding: "0.5rem 1rem", cursor: "pointer",
    display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.875rem" },
  title: { fontSize: "1.5rem", fontWeight: 700, color: "#f1f5f9" },
  clearBtn: { marginLeft: "auto", background: "none", border: "1px solid #7f1d1d",
    color: "#ef4444", borderRadius: "8px", padding: "0.5rem 1rem",
    cursor: "pointer", display: "flex", alignItems: "center", gap: "0.4rem",
    fontSize: "0.875rem" },
  empty: { color: "#4b5563", fontStyle: "italic", textAlign: "center", padding: "4rem 0" },
  row: { display: "flex", alignItems: "center", gap: "1rem",
    background: "#1e2130", border: "1px solid #2d3148",
    borderRadius: "10px", padding: "1rem 1.25rem",
    marginBottom: "0.75rem", cursor: "pointer",
    transition: "border-color 0.15s" },
  filename: { fontWeight: 600, color: "#e2e8f0", fontSize: "0.95rem" },
  meta: { color: "#64748b", fontSize: "0.8rem" },
  packets: { color: "#60a5fa", fontWeight: 600, fontSize: "0.875rem", marginLeft: "auto" },
  delBtn: { background: "none", border: "none", color: "#475569",
    cursor: "pointer", padding: "0.25rem", borderRadius: "4px" },
  confirm: { background: "#2d1515", border: "1px solid #7f1d1d", borderRadius: "8px",
    padding: "1rem 1.25rem", marginBottom: "1rem", color: "#fca5a5",
    display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" },
};

export default function HistoryPage({ onLoad, onBack }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hover, setHover] = useState(null);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    fetch("/api/history")
      .then(r => r.json())
      .then(data => setItems(data))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, []);

  async function handleDelete(e, id) {
    e.stopPropagation();
    await fetch(`/api/history/${id}`, { method: "DELETE" });
    setItems(prev => prev.filter(i => i.id !== id));
  }

  async function handleClearAll() {
    await fetch("/api/history", { method: "DELETE" });
    setItems([]);
    setConfirmClear(false);
  }

  async function handleLoad(id) {
    const res = await fetch(`/api/history/${id}`);
    const report = await res.json();
    onLoad(report);
  }

  return (
    <div style={s.page}>
      <div style={s.header}>
        <button style={s.backBtn} onClick={onBack}><ArrowLeft size={15} /> Back</button>
        <h1 style={s.title}>Analysis History</h1>
        {items.length > 0 && (
          <button style={s.clearBtn} onClick={() => setConfirmClear(true)}>
            <Trash size={14} /> Clear All
          </button>
        )}
      </div>

      {confirmClear && (
        <div style={s.confirm}>
          <span>Delete all {items.length} saved analyses?</span>
          <button style={{ background: "#ef4444", color: "#fff", border: "none",
            borderRadius: "6px", padding: "0.4rem 1rem", cursor: "pointer", fontWeight: 600 }}
            onClick={handleClearAll}>Yes, delete all</button>
          <button style={{ background: "none", color: "#94a3b8", border: "1px solid #3b4268",
            borderRadius: "6px", padding: "0.4rem 1rem", cursor: "pointer" }}
            onClick={() => setConfirmClear(false)}>Cancel</button>
        </div>
      )}

      {loading && <p style={s.empty}>Loading...</p>}
      {!loading && items.length === 0 && <p style={s.empty}>No analyses saved yet. Upload a PCAP to get started.</p>}

      {items.map(item => (
        <div
          key={item.id}
          style={{ ...s.row, borderColor: hover === item.id ? "#60a5fa" : "#2d3148" }}
          onClick={() => handleLoad(item.id)}
          onMouseEnter={() => setHover(item.id)}
          onMouseLeave={() => setHover(null)}
        >
          <Clock size={16} color="#64748b" />
          <div>
            <div style={s.filename}>{item.filename}</div>
            <div style={s.meta}>{new Date(item.timestamp * 1000).toLocaleString()}</div>
          </div>
          <span style={s.packets}>{item.total_packets.toLocaleString()} pkts</span>
          <button style={s.delBtn} onClick={(e) => handleDelete(e, item.id)} title="Delete">
            <Trash2 size={15} />
          </button>
          <ChevronRight size={15} color="#475569" />
        </div>
      ))}
    </div>
  );
}
