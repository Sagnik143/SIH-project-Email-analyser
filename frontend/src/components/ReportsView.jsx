import React, { useState } from 'react';
import { 
  FileCheck2, 
  Download, 
  Shield, 
  CheckCircle2, 
  AlertTriangle, 
  FileText, 
  Loader2, 
  Copy, 
  Check, 
  RefreshCw,
  Terminal
} from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function ReportsView({
  dossier,
  caseInfo,
  onOpenReportModal
}) {
  const [verifyInputJson, setVerifyInputJson] = useState('');
  const [verificationResult, setVerificationResult] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const handleVerifyPastedJson = async () => {
    if (!verifyInputJson.trim()) return;
    setIsVerifying(true);
    setVerificationResult(null);

    try {
      const parsed = JSON.parse(verifyInputJson);
      const res = await fetch(`${API_BASE_URL}/api/reports/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed)
      });
      const data = await res.json();
      setVerificationResult(data);
    } catch (err) {
      setVerificationResult({
        status: 'INVALID_FORMAT',
        message: err.message || 'Input is not valid JSON'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleFillActiveDossier = () => {
    if (!dossier) return;
    setVerifyInputJson(JSON.stringify(dossier, null, 2));
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      
      <div>
        <h2 className="text-xl font-black text-slate-900 tracking-tight">
          Forensic Reports & Integrity Verification Center
        </h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Generate tamper-evident forensic dossiers, download offline reports, and verify SHA-256 integrity seals.
        </p>
      </div>

      {/* Active Dossier Export Card */}
      {dossier && (
        <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3.5">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-blue-700 block">
                Active Investigation Ready for Export
              </span>
              <h3 className="text-base font-bold text-slate-900">
                {dossier.envelope?.subject || 'Forensic Dossier'}
              </h3>
            </div>

            <button
              onClick={onOpenReportModal}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition"
            >
              <FileText className="w-4 h-4" />
              <span>Open Dossier Exporter</span>
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-[10px] font-bold uppercase text-slate-400 block">Email Acquisition SHA-256</span>
              <span className="font-mono text-slate-800 text-[11px] font-semibold break-all block">
                {dossier.integrity?.sha256 || 'N/A'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-[10px] font-bold uppercase text-slate-400 block">Dossier Integrity Seal</span>
              <span className="font-mono text-blue-700 text-[11px] font-semibold break-all block">
                {dossier.integrity?.dossierDigest || dossier.integrity?.sha256 || 'N/A'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Tamper Verification Sandbox */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-4">
        
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-600" />
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Independent Integrity Seal Verifier
              </h3>
              <p className="text-[11px] text-slate-500">
                Paste exported canonical JSON to detect unauthorized modifications.
              </p>
            </div>
          </div>

          {dossier && (
            <button
              onClick={handleFillActiveDossier}
              className="text-xs font-bold text-blue-600 hover:text-blue-800 transition underline"
            >
              Paste Current Dossier JSON
            </button>
          )}
        </div>

        {/* Verification Result Banner */}
        {verificationResult && (
          <div className={`p-4 rounded-xl border text-xs flex items-center justify-between gap-3 ${
            verificationResult.status === 'VERIFIED_VALID'
              ? 'bg-emerald-50 text-emerald-950 border-emerald-300'
              : verificationResult.status === 'TAMPERED'
              ? 'bg-rose-50 text-rose-950 border-rose-300'
              : 'bg-amber-50 text-amber-950 border-amber-300'
          }`}>
            <div className="flex items-center gap-2.5">
              {verificationResult.status === 'VERIFIED_VALID' ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
              )}
              <div>
                <span className="font-bold block uppercase text-[11px]">
                  Verification Status: {verificationResult.status}
                </span>
                <span className="text-[11px] leading-relaxed">
                  {verificationResult.message}
                </span>
              </div>
            </div>

            {verificationResult.integrity && (
              <span className="font-mono text-[11px] font-bold shrink-0">
                {verificationResult.integrity.match ? 'MATCH ✓' : 'MISMATCH ✕'}
              </span>
            )}
          </div>
        )}

        <textarea
          value={verifyInputJson}
          onChange={(e) => setVerifyInputJson(e.target.value)}
          placeholder="Paste canonical JSON report dossier payload here..."
          rows={7}
          className="w-full p-3.5 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/50 resize-y leading-relaxed"
        />

        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-400">
            Calls POST /api/reports/verify &bull; Evaluates canonical UTF-16 code unit ordering
          </span>

          <button
            onClick={handleVerifyPastedJson}
            disabled={!verifyInputJson.trim() || isVerifying}
            className="flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition disabled:opacity-50"
          >
            {isVerifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
            <span>Verify Dossier Integrity</span>
          </button>
        </div>

      </div>

    </div>
  );
}
