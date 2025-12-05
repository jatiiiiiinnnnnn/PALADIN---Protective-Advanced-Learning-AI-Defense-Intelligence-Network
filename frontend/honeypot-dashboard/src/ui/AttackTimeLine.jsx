import React from "react";
import {
  LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer
} from "recharts";

/**
 * data: [{ time: '12:01', DOS: 3, SSH_BRUTE: 1, NORMAL: 0 }, ...]
 * series: ['DOS', 'SSH_BRUTE', 'NORMAL']
 */
const COLORS = ["#FF4C4C", "#FF8A4C", "#4C9BFF", "#8AFF8A", "#FFDA4C", "#C084FC"];

export default function AttackTimeline({ data = [], series = [] }) {
  if (!data.length) {
    return <div className="text-slate-400 p-8">No timeline data available.</div>;
  }

  return (
    <div style={{ width: "100%", height: 300 }}>
      <ResponsiveContainer>
        <LineChart data={data}>
          <CartesianGrid stroke="#2b2b2b" />
          <XAxis dataKey="time" stroke="#9ca3af" />
          <YAxis stroke="#9ca3af" />
          <Tooltip />
          <Legend />
          {series.map((s, i) => (
            <Line key={s} type="monotone" dataKey={s} stroke={COLORS[i % COLORS.length]} strokeWidth={2} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
