import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

function formatBytes(bytes) {
  if (bytes >= 1_000_000) return (bytes / 1_000_000).toFixed(2) + " MB";
  if (bytes >= 1_000) return (bytes / 1_000).toFixed(1) + " KB";
  return bytes + " B";
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#1e2130", border: "1px solid #3b4268",
      borderRadius: "8px", padding: "0.6rem 1rem", fontSize: "0.8rem" }}>
      <p style={{ color: "#94a3b8" }}>T+{label}s</p>
      <p style={{ color: "#60a5fa", fontWeight: 600 }}>{formatBytes(payload[0].value)}</p>
    </div>
  );
};

export default function ThroughputChart({ data }) {
  if (!data || data.length === 0) {
    return <p style={{ color: "#4b5563", fontSize: "0.875rem", fontStyle: "italic" }}>No throughput data</p>;
  }
  return (
    <div style={{ width: "100%", height: 220 }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 10, right: 20, left: 10, bottom: 0 }}>
          <defs>
            <linearGradient id="tpGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#2d3148" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="time_sec"
            tickFormatter={(v) => `${v}s`}
            tick={{ fill: "#64748b", fontSize: 11 }}
            axisLine={false} tickLine={false}
          />
          <YAxis
            tickFormatter={formatBytes}
            tick={{ fill: "#64748b", fontSize: 11 }}
            axisLine={false} tickLine={false} width={70}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone" dataKey="bytes"
            stroke="#3b82f6" strokeWidth={2}
            fill="url(#tpGrad)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
