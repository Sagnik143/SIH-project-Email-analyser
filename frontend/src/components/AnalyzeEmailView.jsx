import React, { useState } from 'react';
import { 
  Upload, 
  FileText, 
  Sparkles, 
  Terminal, 
  AlertCircle, 
  Loader2, 
  CheckCircle2, 
  ShieldCheck, 
  Zap,
  FileUp
} from 'lucide-react';

export default function AnalyzeEmailView({
  samples = [],
  onAnalyzeRaw,
  isAnalyzing,
  error
}) {
  const [rawText, setRawText] = useState('');
  const [uploadedFileName, setUploadedFileName] = useState(null);

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadedFileName(file.name);

    const reader = new FileReader();
    reader.onload = (event) => {
      setRawText(event.target.result);
    };
    reader.readAsText(file);
  };

  const handleAnalyze = () => {
    if (!rawText.trim()) return;
    onAnalyzeRaw(rawText);
  };

  const handleLoadSample = (sample) => {
    setRawText(sample.rawEmail);
    setUploadedFileName(`${sample.id}.eml`);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      
      {/* Title Header */}
      <div>
        <h2 className="text-xl font-black text-slate-900 tracking-tight">
          Email Ingestion & Forensic Intake
        </h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Submit RFC 5322 .EML files or raw message bytes into the deterministic AegisMail investigation pipeline.
        </p>
      </div>

      {/* Preloaded Scenario Quick Select Cards */}
      <div className="space-y-2.5">
        <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">
          Select A Standard Threat Scenario:
        </span>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {samples.map((s) => (
            <div
              key={s.id}
              onClick={() => handleLoadSample(s)}
              className="p-4 rounded-xl bg-white border border-slate-200 hover:border-blue-400 shadow-2xs hover:shadow-sm cursor-pointer transition flex flex-col justify-between gap-2 text-xs group"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase border ${
                    s.riskIndicator === 'CRITICAL'
                      ? 'bg-rose-50 text-rose-700 border-rose-200'
                      : s.riskIndicator === 'HIGH'
                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    {s.riskIndicator || 'BASELINE'}
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono font-medium">Scenario</span>
                </div>
                <h4 className="font-bold text-slate-900 group-hover:text-blue-700 transition leading-snug">
                  {s.title}
                </h4>
                <p className="text-[11px] text-slate-500 mt-1 line-clamp-2 leading-relaxed">
                  {s.description}
                </p>
              </div>

              <div className="text-[11px] font-semibold text-blue-600 flex items-center gap-1 pt-2 border-t border-slate-100">
                <span>Load Scenario &bull;</span>
                <span className="font-mono text-[10px]">{s.id}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Ingestion Box */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-4">
        
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3.5">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-blue-600" />
            <span className="text-xs font-bold text-slate-900 uppercase tracking-wide">
              Raw RFC 5322 Payload Input
            </span>
          </div>

          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs cursor-pointer transition border border-slate-200">
              <FileUp className="w-3.5 h-3.5 text-blue-600" />
              <span>{uploadedFileName ? `Replace (${uploadedFileName})` : 'Upload .EML File'}</span>
              <input
                type="file"
                accept=".eml,.txt"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>

            {rawText && (
              <button
                onClick={() => { setRawText(''); setUploadedFileName(null); }}
                className="text-xs text-slate-400 hover:text-slate-700 px-2 py-1"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Text Area */}
        <textarea
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          placeholder="Paste complete raw email headers and body here, or click one of the scenarios above..."
          rows={12}
          className="w-full p-4 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/50 resize-y leading-relaxed"
        />

        {/* Action Button & Disclaimer */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
          <div className="text-[11px] text-slate-500 max-w-md">
            The original RFC 5322 bytes are preserved directly to compute the authoritative SHA-256 acquisition digest.
          </div>

          <button
            onClick={handleAnalyze}
            disabled={!rawText.trim() || isAnalyzing}
            className="flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-md shadow-blue-500/20 transition disabled:opacity-50"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Running Pipeline...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                <span>Run Forensic Investigation</span>
              </>
            )}
          </button>
        </div>

      </div>

    </div>
  );
}
