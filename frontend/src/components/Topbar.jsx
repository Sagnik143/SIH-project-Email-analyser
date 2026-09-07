import React from 'react';
import { 
  Upload, 
  FileText, 
  ChevronDown, 
  Sparkles, 
  CheckCircle, 
  Search,
  Shield,
  Layers,
  ArrowUpRight
} from 'lucide-react';

export default function Topbar({
  activeNavTitle,
  activeCaseNumber,
  samples = [],
  selectedSampleId,
  onSelectSample,
  onOpenAnalyze,
  onOpenReport,
  isAnalyzing,
  hasDossier
}) {
  return (
    <header className="h-16 border-b border-slate-200 bg-white px-6 flex items-center justify-between shrink-0 sticky top-0 z-30">
      
      {/* Left: View Breadcrumbs */}
      <div className="flex items-center gap-2.5">
        <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
          AegisMail DFIR
        </span>
        <span className="text-slate-300">/</span>
        <h2 className="text-sm font-extrabold text-slate-900 tracking-tight flex items-center gap-2">
          {activeNavTitle}
          {activeCaseNumber && (
            <span className="font-mono text-xs font-bold px-2 py-0.5 rounded-lg bg-blue-50 text-blue-700 border border-blue-200">
              {activeCaseNumber}
            </span>
          )}
        </h2>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        
        {/* Sample Dataset Loader */}
        <div className="relative hidden md:block">
          <select
            aria-label="Choose a preloaded email scenario"
            className="appearance-none bg-slate-50 hover:bg-slate-100 border border-slate-300 rounded-xl px-3.5 py-1.5 pr-8 text-xs font-semibold text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20 cursor-pointer transition shadow-2xs"
            value={selectedSampleId || ''}
            onChange={(e) => onSelectSample && onSelectSample(e.target.value)}
            disabled={isAnalyzing}
          >
            <option value="" disabled>-- Load Preloaded Scenario --</option>
            {samples.map((s) => (
              <option key={s.id} value={s.id}>
                {s.riskIndicator === 'CRITICAL' ? '🚨' : s.riskIndicator === 'HIGH' ? '⚠️' : '✅'} {s.title}
              </option>
            ))}
          </select>
          <ChevronDown className="w-3.5 h-3.5 text-slate-500 absolute right-2.5 top-2.5 pointer-events-none" />
        </div>

        {/* Action: Open Ingestion / Analyze */}
        <button
          onClick={onOpenAnalyze}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-xs transition"
          title="Upload or paste a new email"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>New Analysis</span>
        </button>

        {/* Action: View Full Dossier */}
        {hasDossier && (
          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-semibold transition border border-slate-200"
            title="Open 11-section Forensic Dossier"
          >
            <FileText className="w-3.5 h-3.5 text-blue-600" />
            <span className="hidden sm:inline">Forensic Dossier</span>
          </button>
        )}

      </div>

    </header>
  );
}
