import React from "react";

export default function LogModal({ log, onClose }) {
  if (!log) return null;

  const techniques = log?.mitre?.techniques || [];
  const sequence = log?.lstm?.statistics?.recent_sequence || [];
  const recs = log?.lstm?.recommendations || [];

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black/60 z-50">
      <div className="bg-slate-900 text-slate-100 w-11/12 md:w-2/3 lg:w-1/2 p-6 rounded-lg shadow-lg">
        <div className="flex justify-between items-start">
          <h3 className="text-xl font-semibold">Log Detail — {log.src_ip}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white">Close</button>
        </div>

        <div className="mt-4 grid gap-4">
          <div>
            <h4 className="font-semibold">MITRE ATT&CK</h4>
            <div className="text-sm text-slate-300 mt-1">
              <div><strong>Severity:</strong> {log.mitre?.severity || "N/A"}</div>
              <div><strong>Priority:</strong> {log.mitre?.priority || "N/A"}</div>
              <div><strong>Tactics:</strong> {(log.mitre?.tactics || []).join(", ")}</div>
              <div><strong>Techniques:</strong> {techniques.map(t => t.name).join(", ")}</div>
            </div>
          </div>

          <div>
            <h4 className="font-semibold">LSTM Kill Chain</h4>
            <div className="flex gap-2 mt-2">
              {sequence.length ? sequence.map((s, i) => (
                <span key={i} className="px-3 py-1 bg-slate-800 rounded-full text-sm">{s}</span>
              )) : <div className="text-slate-400">No sequence available</div>}
            </div>
          </div>

          <div>
            <h4 className="font-semibold">Recommendations</h4>
            <ul className="list-disc pl-5 text-slate-300 mt-2">
              {recs.length ? recs.map((r, i) => <li key={i}>{r}</li>) : <li>No recommendations</li>}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
