import React from "react";

/**
 * LogsTable shows basic columns and risk "bar"
 * Expected log shape (per your contract):
 * {
 *   "@timestamp": "2025-11-26T18:42:49.203Z",
 *   src_ip: "192.168.1.1",
 *   service: "HTTP",
 *   ai_attack_type: "DOS",
 *   ai_final_status: "🚨 ATTACK",
 *   mitre: { risk_score: 2.76, ... },
 *   lstm: { statistics: { recent_sequence: [...] }, recommendations: [...] }
 * }
 */
export default function LogsTable({ logs = [], onRowClick = () => {} }) {
  if (!logs.length) return <div className="text-slate-400 p-6">No logs available.</div>;

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left border-separate border-spacing-y-2">
        <thead>
          <tr className="text-sm text-slate-300">
            <th className="py-2 px-3">Time</th>
            <th className="py-2 px-3">Source IP</th>
            <th className="py-2 px-3">Service</th>
            <th className="py-2 px-3">Attack Type</th>
            <th className="py-2 px-3">Risk Score</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, idx) => {
            const time = new Date(log["@timestamp"]).toLocaleTimeString();
            const risk = Number(log?.mitre?.risk_score || 0);
            const isAttack = log?.ai_final_status && log.ai_final_status !== "NORMAL";

            return (
              <tr key={idx} onClick={() => onRowClick(log)} className="cursor-pointer hover:bg-slate-800">
                <td className="py-3 px-3 text-sm">{time}</td>
                <td className="py-3 px-3 text-sm">{log.src_ip}</td>
                <td className="py-3 px-3 text-sm">{log.service}</td>
                <td className={`py-3 px-3 font-semibold ${isAttack ? "text-red-400" : "text-green-400"}`}>
                  {log.ai_attack_type}
                </td>
                <td className="py-3 px-3">
                  <div className="w-48">
                    <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                      <div style={{ width: `${Math.min(100, risk * 10)}%` }} className="h-2 bg-yellow-400" />
                    </div>
                    <div className="text-xs text-slate-400 mt-1">{risk.toFixed(2)}</div>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
