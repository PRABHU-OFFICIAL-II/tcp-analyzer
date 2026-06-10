import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";

function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + "MB";
  if (b >= 1e3) return (b / 1e3).toFixed(0) + "KB";
  return b + "B";
}

const COLORS = ["#3b82f6","#8b5cf6","#06b6d4","#10b981","#f59e0b","#ef4444","#ec4899","#84cc16","#f97316","#6366f1"];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#1e2130", border: "1px solid #3b4268", borderRadius: "8px", padding: "0.6rem 1rem", fontSize: "0.8rem" }}>
      <p style={{ color: "#e2e8f0", fontWeight: 600 }}>{payload[0].payload.country}</p>
      <p style={{ color: "#60a5fa" }}>{fmtBytes(payload[0].value)}</p>
    </div>
  );
};

export default function GeoBarChart({ data = [] }) {
  if (!data.length) return <p style={{ color: "#4b5563", fontStyle: "italic", fontSize: "0.875rem" }}>No external traffic data</p>;
  return (
    <div style={{ width: "100%", height: 260 }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 10, right: 20, left: 10, bottom: 40 }}>
          <CartesianGrid stroke="#2d3148" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="country" tick={{ fill: "#64748b", fontSize: 11 }} angle={-35} textAnchor="end" axisLine={false} tickLine={false} />
          <YAxis tickFormatter={fmtBytes} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} width={55} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="bytes" radius={[4, 4, 0, 0]}>
            {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
