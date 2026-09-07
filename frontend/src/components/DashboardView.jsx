import React from 'react';
import { 
  FolderGit2, 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Upload, 
  ArrowRight, 
  FileCheck2, 
  Calendar,
  Network,
  Clock,
  Sparkles,
  Search,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

export default function DashboardView({
  cases = [],
  activeDossier,
  onOpenInvestigation,
  onNavigateToAnalyze,
  onNavigateToReports,
  onOpenReportModal
}) {
  // Aggregate stats
  const totalCases = cases.length;
  const totalFindings = cases.reduce((acc, c) => acc + (c.findingsCount || 0), 0);
  const criticalCases = cases.filter(c => (c.criticalFindingsCount || 0) > 0 || c.status === 'critical').length;
  const recentCases = [...cases].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 5);

  return (
    <div className="space-y-6">
      
      {/* Welcome & System Summary Banner */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              AegisMail Automated DFIR Pipeline
            </span>
          </div>
          <h2 className="text-xl font-black text-slate-900 tracking-tight">
            Security Operations & Incident Investigation Dashboard
          </h2>
          <p className="text-xs text-slate-500 mt-1 max-w-2xl leading-relaxed">
            Evidence-first email threat detection, deterministic forensic finding generation, and tamper-evident chain-of-custody reporting.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={onNavigateToAnalyze}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm transition"
          >
            <Upload className="w-4 h-4" />
            <span>Analyze New Email</span>
          </button>
        </div>
      </div>

      {/* 4 Summary Statistic Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Stat 1: Total Investigations */}
        <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Total Investigations
            </span>
            <div className="w-8 h-8 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center">
              <FolderGit2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-slate-900 tracking-tight">
            {totalCases}
          </div>
          <div className="text-[11px] text-slate-500">
            Persisted in SQLite repository
          </div>
        </div>

        {/* Stat 2: Elevated Threat Cases */}
        <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Elevated Signals
            </span>
            <div className="w-8 h-8 rounded-xl bg-rose-50 text-rose-600 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-rose-600 tracking-tight">
            {criticalCases}
          </div>
          <div className="text-[11px] text-slate-500">
            Cases with critical threat findings
          </div>
        </div>

        {/* Stat 3: Total Deterministic Findings */}
        <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Deterministic Findings
            </span>
            <div className="w-8 h-8 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-slate-900 tracking-tight">
            {totalFindings}
          </div>
          <div className="text-[11px] text-slate-500">
            Evidence-traceable findings logged
          </div>
        </div>

        {/* Stat 4: Active Engine Status */}
        <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Forensic Engine
            </span>
            <div className="w-8 h-8 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-black text-emerald-600 tracking-tight">
            Active
          </div>
          <div className="text-[11px] text-slate-500">
            Phase 8 Trust Boundary Enforced
          </div>
        </div>

      </div>

      {/* Active Session Investigation Quick-Card (if one is loaded) */}
      {activeDossier && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-blue-900 to-indigo-900 text-white shadow-md flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-blue-300 text-xs font-bold uppercase tracking-wider">
              <span>Active Investigation In Memory</span>
              <span>&bull;</span>
              <span>UUID: {activeDossier.dossierId}</span>
            </div>
            <h3 className="text-lg font-bold">
              {activeDossier.envelope?.subject || 'Forensic Email Examination'}
            </h3>
            <p className="text-xs text-blue-200">
              From: <span className="font-mono text-white">{activeDossier.envelope?.from?.address}</span> &bull; Heuristic Risk: <strong className="text-amber-300">{activeDossier.aiThreatIntelligence?.riskScore ?? 0}/100</strong>
            </p>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={() => onOpenInvestigation && onOpenInvestigation(activeDossier)}
              className="px-4 py-2 rounded-xl bg-white text-blue-900 hover:bg-blue-50 font-bold text-xs shadow-sm transition"
            >
              Open Workspace
            </button>
            <button
              onClick={onOpenReportModal}
              className="px-4 py-2 rounded-xl bg-blue-800 hover:bg-blue-700 text-white font-semibold text-xs border border-blue-700 transition"
            >
              Forensic Dossier
            </button>
          </div>
        </div>
      )}

      {/* Recent Investigations Table */}
      <div className="rounded-2xl bg-white border border-slate-200 shadow-2xs overflow-hidden">
        <div className="p-5 border-b border-slate-100 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900">
              Recent Case Investigations
            </h3>
            <p className="text-xs text-slate-500">
              Historical case records stored locally in SQLite
            </p>
          </div>

          <span className="text-xs font-semibold text-slate-500">
            Showing {recentCases.length} of {totalCases}
          </span>
        </div>

        {recentCases.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 text-slate-500 text-[10px] uppercase font-bold border-b border-slate-200">
                  <th className="p-3.5 pl-5">Case Number</th>
                  <th className="p-3.5">Investigation Title</th>
                  <th className="p-3.5">Created Date</th>
                  <th className="p-3.5">Findings</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5 pr-5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {recentCases.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-50/80 transition">
                    <td className="p-3.5 pl-5 font-mono font-bold text-blue-700">
                      {c.caseNumber}
                    </td>
                    <td className="p-3.5 font-medium text-slate-900 max-w-xs truncate" title={c.title}>
                      {c.title || 'Untitled Case'}
                    </td>
                    <td className="p-3.5 text-slate-500 text-[11px]">
                      {c.createdAt ? new Date(c.createdAt).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="p-3.5 font-mono">
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-semibold text-[11px]">
                        {c.findingsCount || 0} findings
                      </span>
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
                        onClick={() => onOpenInvestigation && onOpenInvestigation(c)}
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 font-bold text-xs"
                      >
                        <span>Inspect</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-10 text-center space-y-3">
            <div className="w-12 h-12 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
              <FolderGit2 className="w-6 h-6" />
            </div>
            <div className="text-sm font-bold text-slate-800">
              No Investigations Recorded Yet
            </div>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Analyze an email from raw text or preloaded samples to generate your first forensic case.
            </p>
            <button
              onClick={onNavigateToAnalyze}
              className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-xs transition inline-flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Start First Analysis</span>
            </button>
          </div>
        )}
      </div>

    </div>
  );
}
