import React, { useEffect, useState } from "react";
import {
  getRecentLogs,
  getAttackDistribution,
  getAttackTimeline
} from "../services/elastic";

import StatsGrid from "../ui/StatsGrid";
import AttackTimeline from "../ui/AttackTimeLine.jsx";
import AttackPie from "../ui/AttackPie";
import LogsTable from "../ui/LogsTable";
import LogModal from "../ui/LogModal";

/**
 * Dashboard page - coordinates fetching + rendering
 * Fetches:
 * - Recent logs (table + stats)
 * - Distribution for pie chart
 * - Timeline for line chart
 */
export default function Dashboard() {
  const [logs, setLogs] = useState([]);
  const [pieBuckets, setPieBuckets] = useState([]);
  const [timelineBuckets, setTimelineBuckets] = useState([]);
  const [selectedLog, setSelectedLog] = useState(null);
  const [loading, setLoading] = useState(true);

  async function loadAll() {
    setLoading(true);
    try {
      const [recent, pie, timeline] = await Promise.all([
        getRecentLogs(),
        getAttackDistribution(),
        getAttackTimeline()
      ]);
      setLogs(recent);
      setPieBuckets(pie);
      setTimelineBuckets(timeline);
    } catch (err) {
      console.error("Failed to load ES data:", err);
      setLogs([]); setPieBuckets([]); setTimelineBuckets([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll(); }, []);

  // Derived stats (defensive)
  const totalThreats = logs.filter(l => l?.ai_final_status && l.ai_final_status !== "NORMAL").length;
  const activeAttackers = new Set(logs.map(l => l?.src_ip).filter(Boolean)).size;
  const maxRisk = logs.length ? Math.max(...logs.map(l => Number(l?.mitre?.risk_score || 0))) : 0;
  const systemStatus = logs?.[0]?.ai_final_status || "UNKNOWN";

  // Convert ES timeline buckets to chart-friendly rows:
  // { time: "HH:MM", DOS: 3, SSH: 1, NORMAL: 0 }
  const timelineData = timelineBuckets.map(b => {
    const row = { time: new Date(b.key_as_string).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) };
    (b.by_type?.buckets || []).forEach(t => { row[t.key] = t.doc_count; });
    return row;
  });

  // Determine unique attack types for dynamic lines
  const attackTypesSet = new Set();
  timelineData.forEach(r => Object.keys(r).forEach(k => { if (k !== "time") attackTypesSet.add(k); }));
  const attackTypes = Array.from(attackTypesSet);

  return (
    <div className="min-h-screen p-8">
      {/* HEADER */}
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">PALADIN — Threat Dashboard</h1>
        <p className="text-slate-300 mt-1">Realtime honeypot insights • Elasticsearch: honeypot-logs</p>
      </header>

      {/* STATS */}
      <section className="mb-8">
        <StatsGrid
          totalThreats={totalThreats}
          maxRisk={maxRisk}
          activeAttackers={activeAttackers}
          systemStatus={systemStatus}
          onRefresh={loadAll}
          loading={loading}
        />
      </section>

      {/* CHARTS */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-slate-800 p-5 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Attack Volume Over Time</h2>
          <AttackTimeline data={timelineData} series={attackTypes} />
        </div>

        <div className="bg-slate-800 p-5 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Attack Type Distribution</h2>
          <AttackPie buckets={pieBuckets} />
        </div>
      </section>

      {/* LOGS TABLE */}
      <section className="bg-slate-800 p-5 rounded-lg shadow">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold">Live Logs</h2>
          <div className="text-sm text-slate-400">Showing latest 50 logs</div>
        </div>

        <LogsTable logs={logs} onRowClick={setSelectedLog} />
      </section>

      {/* MODAL */}
      <LogModal log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
}
