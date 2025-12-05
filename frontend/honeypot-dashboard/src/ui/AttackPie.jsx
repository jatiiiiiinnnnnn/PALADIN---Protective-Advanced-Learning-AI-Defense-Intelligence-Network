import React from "react";
import { PieChart, Pie, Tooltip, Cell, ResponsiveContainer, Legend } from "recharts";

const COLORS = ["#FF4C4C", "#4C9BFF", "#FF8A4C", "#8AFF8A", "#FFDA4C", "#C084FC"];

/**
 * buckets: [{ key: 'DOS', doc_count: 12 }, ...]
 */
export default function AttackPie({ buckets = [] }) {
  if (!buckets.length) {
    return <div className="text-slate-400 p-8">No distribution data available.</div>;
  }

  return (
    <div style={{ width: "100%", height: 300 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie data={buckets} dataKey="doc_count" nameKey="key" cx="50%" cy="50%" outerRadius={90} label>
            {buckets.map((_, idx) => <Cell key={idx} fill={COLORS[idx % COLORS.length]} />)}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
