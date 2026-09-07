import React, { useState, useEffect } from 'react';
import { GitFork, Link2, ShieldAlert, AlertCircle, Info, ExternalLink, RefreshCw } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function RelatedIncidentsCard({ caseId, caseNumber }) {
  const [relatedData, setRelatedData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchRelated = async () => {
    if (!caseId && !caseNumber) return;
    setLoading(true);
    setError(null);
    try {
      const targetId = caseNumber || caseId;
      const res = await fetch(`${API_BASE_URL}/api/cases/${targetId}/related`);
      if (!res.ok) {
        throw new Error('Unable to retrieve related incidents');
      }
      const data = await res.json();
      setRelatedData(data);
    } catch (err) {
      console.warn('Failed to load related incidents:', err);
      setError('Related incident discovery is currently unavailable.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRelated();
  }, [caseId, caseNumber]);

  if (!caseId && !caseNumber) {
    return null;
  }

  const results = relatedData?.results || [];

  return (
    <div className="rounded-2xl bg-white border border-slate-200 shadow-sm overflow-hidden text-xs">
      {/* Header */}
      <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-700 flex items-center justify-center">
            <GitFork className="w-4 h-4" />
          </div>
          <div>
            <div className="font-bold text-slate-900 text-sm flex items-center gap-2">
              <span>Potentially Related Incidents</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-200/80 text-slate-700 font-semibold">
                {results.length} identified
              </span>
            </div>
            <div className="text-[11px] text-slate-500">
              Evidence-backed correlation based on shared observable indicators across cases
            </div>
          </div>
        </div>

        <button
          onClick={fetchRelated}
          disabled={loading}
          className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-[11px] font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Body */}
      <div className="p-5 space-y-4">
        {loading && (
          <div className="text-center py-6 text-slate-400 text-xs">
            Querying shared indicators across cases...
          </div>
        )}

        {error && (
          <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-amber-600" />
            <span>{error}</span>
          </div>
        )}

        {!loading && !error && results.length === 0 && (
          <div className="text-center py-6 text-slate-500 space-y-1">
            <div className="font-semibold text-slate-700">No Potentially Related Incidents Identified</div>
            <div className="text-[11px] text-slate-400 max-w-md mx-auto">
              No other persisted cases share high-confidence indicators (matching attachment hashes, normalized URLs, or Reply-To addresses).
            </div>
          </div>
        )}

        {!loading && results.length > 0 && (
          <div className="space-y-3">
            {results.map((rel, idx) => {
              let scoreBadge = 'bg-blue-100 text-blue-800 border-blue-200';
              if (rel.correlationScore >= 70) {
                scoreBadge = 'bg-rose-100 text-rose-800 border-rose-200';
              } else if (rel.correlationScore >= 40) {
                scoreBadge = 'bg-amber-100 text-amber-800 border-amber-200';
              }

              return (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-slate-50/80 border border-slate-200 space-y-3 hover:border-slate-300 transition"
                >
                  {/* Title Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/60 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded text-[11px]">
                        {rel.case?.caseNumber || `CASE-${rel.case?.id}`}
                      </span>
                      <span className="font-bold text-slate-900 text-sm">
                        {rel.case?.title || 'Investigation Case'}
                      </span>
                      {rel.email?.filename && (
                        <span className="text-slate-400 text-[11px] font-mono">
                          ({rel.email.filename})
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-0.5 rounded-full font-bold text-[10px] border ${scoreBadge}`}>
                        Correlation Score: {rel.correlationScore}/100
                      </span>
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-slate-600 text-[10px] font-semibold">
                        Potentially Related
                      </span>
                    </div>
                  </div>

                  {/* Shared Indicators & Reasons */}
                  <div className="space-y-1.5">
                    <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                      Shared Observable Indicators:
                    </div>
                    <ul className="space-y-1">
                      {rel.reasons.map((r, rIdx) => (
                        <li key={rIdx} className="flex items-start gap-2 text-slate-700">
                          <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 mt-1.5 shrink-0"></span>
                          <span className="leading-snug">{r.description}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Explicit Limitation Banner */}
                  <div className="p-2.5 rounded-lg bg-amber-50/80 border border-amber-200 text-amber-900 text-[11px] flex items-start gap-2">
                    <Info className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                    <span>
                      <strong>Forensic Limitation:</strong> Shared observable indicators do not establish common authorship, attacker identity, or a coordinated campaign. Correlation requires independent analyst verification.
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
