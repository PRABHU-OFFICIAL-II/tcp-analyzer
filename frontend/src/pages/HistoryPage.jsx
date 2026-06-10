import { useEffect, useState } from "react";
import { Clock, Trash2, ChevronRight, ArrowLeft } from "lucide-react";

const s = {
  page: { minHeight: "100vh", background: "#0f1117", padding: "2rem" },
  header: { display: "flex", alignItems: "center", gap: "1rem", marginBottom: "2rem" },
  backBtn: { background: "none", border: "1px solid #3b4268", color: "#94a3b8",
    borderRadius: "8px", padding: "0.5rem 1rem", cursor: "pointer",
    display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.875rem" },
  title: { fontSize: "1.5rem", fontWeight: 700, color: "#f1f5f9" },
  empty: { color: "#4b5563", fontStyle: "italic", textAlign: "center", padding: "4rem 0" },
  row: { display: "flex", alignItems: "center", gap: "1rem",
    background: "#1e2130", border: "1px solid #2d3148",
    borderRadius: "10px", padding: "1rem 1.25rem",
    marginBottom: "0.75rem", cursor: "pointer",
    transition: "border-color 0.15s" },
  rowHover: { borderColor: "#60a5fa" },
  filename: { fontWeight: 600, color: "#e2e8f0", fontSize: "0.95rem" },
  meta: { color: "#64748b", fontSize: "0.8rem" },
  packets: { color: "#60a5fa", fontWeight: 600, fontSize: "0.875rem", marginLeft: "auto" },
  delBtn: { background: "none", border: "none", color: "#475569",
    cursor: "pointer", padding: "0.25rem", borderRadius: "4px" },
};

export default function HistoryPage({ onLoad, onBack }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hover, setHover] = useState(null);

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
      </div>

      {loading && <p style={s.empty}>Loading...</p>}
      {!loading && items.length === 0 && <p style={s.empty}>No analyses saved yet. Upload a PCAP to get started.</p>}

      {items.map(item => (
        <div
          key={item.id}
          style={{ ...s.row, ...(hover === item.id ? s.rowHover : {}) }}
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
