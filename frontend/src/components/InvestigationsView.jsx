import React, { useState } from 'react';
import { 
  FolderGit2, 
  Search, 
  Filter, 
  ArrowRight, 
  Calendar, 
  ShieldAlert, 
  FileText,
  Clock,
  CheckCircle2,
  RefreshCw
} from 'lucide-react';

export default function InvestigationsView({
  cases = [],
  onOpenCase,
  onRefresh,
  loading
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const filteredCases = cases.filter(c => {
    const matchesSearch = (c.caseNumber || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (c.title || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || c.status?.toUpperCase() === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-black text-slate-900 tracking-tight">
            Case Investigations Repository
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Indexed case dossiers stored locally in SQLite with deterministic findings and chain-of-custody records.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition shadow-2xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Cases</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-2xs flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by case # or subject..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/20 text-xs font-medium"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          <span className="text-[11px] font-bold uppercase text-slate-400">Status:</span>
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl">
            {['ALL', 'OPEN', 'CLOSED'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition ${
                  statusFilter === st
                    ? 'bg-white text-blue-700 shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Cases List */}
      <div className="rounded-2xl bg-white border border-slate-200 shadow-2xs overflow-hidden">
        {filteredCases.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 text-slate-500 text-[10px] uppercase font-bold border-b border-slate-200">
                  <th className="p-3.5 pl-5">Case Identifier</th>
                  <th className="p-3.5">Investigation Title</th>
                  <th className="p-3.5">Created Date</th>
                  <th className="p-3.5">Attached Emails</th>
                  <th className="p-3.5">Deterministic Findings</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5 pr-5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredCases.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-50/80 transition">
                    <td className="p-3.5 pl-5 font-mono font-bold text-blue-700">
                      {c.caseNumber}
                    </td>
                    <td className="p-3.5 font-bold text-slate-900 max-w-sm truncate" title={c.title}>
                      {c.title || 'Untitled Case'}
                    </td>
                    <td className="p-3.5 text-slate-500 text-[11px]">
                      {c.createdAt ? new Date(c.createdAt).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="p-3.5 font-mono">
                      {c.emailsCount || 1} email(s)
                    </td>
                    <td className="p-3.5 font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className="font-semibold text-slate-900">{c.findingsCount || 0} findings</span>
                        {(c.criticalFindingsCount || 0) > 0 && (
                          <span className="px-1.5 py-0.2 rounded bg-rose-100 text-rose-800 text-[10px] font-bold">
                            {c.criticalFindingsCount} critical
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                        c.status === 'closed'
                          ? 'bg-slate-100 text-slate-600 border-slate-200'
                          : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                      }`}>
                        {c.status || 'open'}
                      </span>
                    </td>
                    <td className="p-3.5 pr-5 text-right">
                      <button
                        onClick={() => onOpenCase && onOpenCase(c)}
                        className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 font-bold text-xs transition"
                      >
                        <span>Open Workspace</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-12 text-center text-slate-500 space-y-2">
            <div className="text-sm font-bold text-slate-800">
              No Cases Match Your Query
            </div>
            <p className="text-xs text-slate-400">
              Try adjusting your search terms or filters.
            </p>
          </div>
        )}
      </div>

    </div>
  );
}
