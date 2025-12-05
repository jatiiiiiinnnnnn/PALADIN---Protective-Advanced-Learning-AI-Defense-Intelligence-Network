import React from "react";
import classNames from "classnames";

/**
 * Small reusable stat card
 */
function StatCard({ title, value, sub, accent }) {
  return (
    <div className={classNames("p-4 rounded-lg", "bg-gradient-to-br", accent)}>
      <p className="text-sm text-slate-200">{title}</p>
      <div className="flex items-baseline gap-3 mt-2">
        <div className="text-3xl font-bold text-white">{value}</div>
        {sub && <div className="text-sm text-slate-200">{sub}</div>}
      </div>
    </div>
  );
}

/**
 * StatsGrid - shows four stat cards and a refresh button
 */
export default function StatsGrid({ totalThreats, maxRisk, activeAttackers, systemStatus, onRefresh, loading }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard title="Total Threats" value={totalThreats} accent="from-red-600 to-red-500" />
      <StatCard title="Max Risk Score" value={Number(maxRisk).toFixed(2)} accent="from-yellow-500 to-yellow-400" />
      <StatCard title="Active Attackers" value={activeAttackers} accent="from-blue-600 to-blue-500" />
      <div className="p-4 rounded-lg bg-slate-800 flex flex-col justify-between">
        <div>
          <p className="text-sm text-slate-300">System Status</p>
          <div className="text-2xl font-bold mt-2">{systemStatus}</div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded text-sm"
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <div className="text-xs text-slate-400">Updated: {new Date().toLocaleTimeString()}</div>
        </div>
      </div>
    </div>
  );
}
