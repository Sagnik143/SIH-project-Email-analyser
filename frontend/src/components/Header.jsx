import React from 'react';
import { ShieldCheck, Sparkles, Upload, FileText, ChevronDown, CheckCircle, MailCheck } from 'lucide-react';

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
    <header className="border-b border-slate-200/80 bg-white/95 backdrop-blur-md sticky top-0 z-40 px-4 lg:px-8 py-3.5 shadow-sm">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Brand & Logo */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-11 h-11 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-600 text-white shadow-md shadow-blue-500/20 transform hover:scale-105 transition-transform duration-200">
            <MailCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-slate-900 via-blue-900 to-indigo-800 bg-clip-text text-transparent">
                AegisMail DFIR
              </h1>
              <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 border border-blue-200">
                AICTE PS #26106
              </span>
            </div>
            <p className="text-xs text-slate-500 font-medium">
              AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
            </p>
          </div>
        </div>

        {/* AI Engine Status Pill & Problem Info */}
        <div className="hidden xl:flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-purple-50 border border-purple-200 text-xs text-purple-700 font-medium shadow-xs shrink-0">
          <Sparkles className="w-3.5 h-3.5 text-purple-600 animate-pulse shrink-0" />
          <span className="text-purple-900 font-semibold shrink-0">GPT-6 Astra AI:</span>
          <span className="font-semibold text-purple-700 font-mono text-[11px] max-w-[200px] truncate" title={openrouterModel || 'gpt-6-astra'}>
            {openrouterModel || 'gpt-6-astra'}
          </span>
          <span className="flex items-center gap-1 text-[11px] text-emerald-600 bg-emerald-100/70 px-2 py-0.5 rounded-full font-medium ml-1 shrink-0">
            <CheckCircle className="w-3 h-3" /> Live
          </span>
        </div>

        {/* Right Action Controls: Sample selector & Upload */}
        <div className="flex items-center gap-3 w-full md:w-auto justify-end">
          
          {/* Sample Dataset Dropdown */}
          <div className="relative">
            <select
              aria-label="Choose an email example"
              className="appearance-none bg-slate-50 hover:bg-slate-100 border border-slate-300 rounded-xl px-4 py-2 pr-9 text-xs font-semibold text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/30 cursor-pointer transition shadow-xs"
              value={selectedSampleId || ''}
              onChange={(e) => onSelectSample(e.target.value)}
              disabled={isAnalyzing}
            >
              <option value="" disabled>-- Load Sample Email --</option>
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.riskIndicator === 'CRITICAL' ? '🚨' : s.riskIndicator === 'HIGH' ? '⚠️' : '✅'} {s.title}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-slate-500 absolute right-3 top-2.5 pointer-events-none" />
          </div>

          {/* Upload / Custom Input Button */}
          <button
            onClick={onOpenUploadModal}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-white hover:bg-slate-50 border border-slate-300 text-xs font-semibold text-slate-700 hover:text-slate-900 transition shadow-xs hover:border-slate-400"
            title="Upload .EML file or paste raw text"
          >
            <Upload className="w-3.5 h-3.5 text-blue-600" />
            <span>Analyze Email</span>
          </button>

          {/* Export Report Button */}
          <button
            onClick={onOpenReportModal}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-semibold shadow-sm hover:shadow-md transition-all transform hover:-translate-y-0.5"
            title="View complete incident report"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Forensic Dossier</span>
          </button>

        </div>

      </div>
    </header>
  );
}
