import React from 'react';
import { Shield, ShieldAlert, Cpu, Upload, FileText, RefreshCw, ChevronDown, CheckCircle2 } from 'lucide-react';

export default function Header({
  samples,
  selectedSampleId,
  onSelectSample,
  onOpenUploadModal,
  onOpenReportModal,
  isAnalyzing,
  openrouterModel
}) {
  return (
    <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 px-4 lg:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Brand & Platform Title */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
            <Shield className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold font-display tracking-wider text-slate-100 flex items-center gap-1.5">
                AEGIS <span className="text-cyan-400 font-normal">//</span> DFIR-MAIL
              </h1>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300">
                v1.0 INTEL
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              AI Email Threat Detection, GeoLocation & Forensic Intelligence
            </p>
          </div>
        </div>

        {/* Center: OpenRouter AI Engine Badge */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-300">
          <Cpu className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
          <span className="text-slate-400">AI Core:</span>
          <span className="font-mono text-purple-300 font-medium">
            {openrouterModel || 'minimax/minimax-m3:free'}
          </span>
          <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-mono ml-1">
            <CheckCircle2 className="w-3 h-3" /> ONLINE
          </span>
        </div>

        {/* Right Action Controls: Sample selector & Upload */}
        <div className="flex items-center gap-2.5 w-full md:w-auto justify-end">
          
          {/* Sample Dataset Dropdown */}
          <div className="relative">
            <select
              aria-label="Select forensic threat sample"
              className="appearance-none bg-slate-900/90 border border-slate-700/80 hover:border-slate-600 rounded-lg px-3.5 py-2 pr-8 text-xs font-medium text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 cursor-pointer transition-all"
              value={selectedSampleId || ''}
              onChange={(e) => onSelectSample(e.target.value)}
              disabled={isAnalyzing}
            >
              <option value="" disabled>-- Load Threat Sample --</option>
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.riskIndicator}] {s.title}
                </option>
              ))}
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-3 pointer-events-none" />
          </div>

          {/* Upload / Custom Input Button */}
          <button
            onClick={onOpenUploadModal}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-200 hover:text-white transition-all shadow-sm"
            title="Upload .EML file or paste raw RFC headers"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Ingest Email</span>
          </button>

          {/* Export Report Button */}
          <button
            onClick={onOpenReportModal}
            className="btn-cyber flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold"
            title="View and download evidentiary forensic report"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Forensic Dossier</span>
          </button>

        </div>

      </div>
    </header>
  );
}
