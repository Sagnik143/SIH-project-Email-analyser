import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, UserCheck, AtSign, ArrowRightLeft, CheckCircle2, XCircle, Info } from 'lucide-react';

export default function AuthMatrix({ authentication, envelope, onSelectEvidence }) {
  if (!authentication) return null;

  const { spf, dkim, dmarc, displayNameAnalysis, domainAnalysis, alignmentAnalysis, authRiskScore } = authentication;

  const getStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">✓ PASS (Reported)</span>;
      case 'FAIL':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">✕ FAIL (Reported)</span>;
      case 'SOFTFAIL':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-200">⚠ SOFTFAIL (Reported)</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">{status || 'NONE'}</span>;
    }
  };

  return (
    <div className="app-card p-6 space-y-4 bg-white border-slate-200 shadow-xs">
      
      {/* Title */}
      <div className="flex items-center justify-between border-b border-slate-100 pb-3.5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-emerald-50 text-emerald-600 border border-emerald-100">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Sender Identity & Reported Authentication
            </h3>
            <p className="text-xs text-slate-500">
              Evaluation of header authentication claims, display name spoofing & typosquatting indicators
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-semibold">Heuristic Auth Risk:</span>
          <span className={`text-xs font-extrabold px-3 py-1 rounded-full ${
            authRiskScore >= 50 ? 'bg-rose-100 text-rose-700 border border-rose-200' : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
          }`}>
            {authRiskScore}/100
          </span>
        </div>
      </div>

      {/* Header Authentication Trust Boundary Banner */}
      <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-700 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-start gap-2">
          <Info className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
          <div>
            <strong>Authentication Trust Boundary:</strong> Authentication claims below were reported by the receiving mail transfer agent inside the ingested message. AegisMail does not assert independent live DNS verification for historical acquired messages.
          </div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-800 border border-blue-200 uppercase">
            Context: Reported by MTA
          </span>
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-300">
            Independent Check: Insufficient Evidence (Offline)
          </span>
        </div>
      </div>

      {/* Row 1: Triple Email Protocols */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        
        {/* SPF */}
        <div className={`p-4 rounded-xl border transition-all ${spf?.status === 'PASS' ? 'bg-slate-50/60 border-slate-200' : 'bg-rose-50/50 border-rose-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <div>
              <span className="text-xs font-bold text-slate-800 block">Reported SPF</span>
              <span className="text-[10px] text-slate-400">{spf?.source || 'Header-reported claim'}</span>
            </div>
            {getStatusBadge(spf?.status)}
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {spf?.details || 'No SPF record found.'}
          </p>
          <div className="mt-2.5 pt-2 border-t border-slate-200/60 text-[10px] text-slate-500 space-y-0.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-600">Verification Source:</span>
              <span className="font-mono uppercase text-blue-700 font-semibold">{spf?.evaluationMode || 'reported'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-600">Current Validation:</span>
              <span className="text-slate-600">Insufficient evidence (offline)</span>
            </div>
          </div>
        </div>

        {/* DKIM */}
        <div className={`p-4 rounded-xl border transition-all ${dkim?.status === 'PASS' ? 'bg-slate-50/60 border-slate-200' : 'bg-rose-50/50 border-rose-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <div>
              <span className="text-xs font-bold text-slate-800 block">Reported DKIM</span>
              <span className="text-[10px] text-slate-400">{dkim?.source || 'Header-reported claim'}</span>
            </div>
            {getStatusBadge(dkim?.status)}
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {dkim?.details || 'No cryptographic signature header found.'}
          </p>
          <div className="mt-2.5 pt-2 border-t border-slate-200/60 text-[10px] text-slate-500 space-y-0.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-600">Verification Source:</span>
              <span className="font-mono uppercase text-blue-700 font-semibold">{dkim?.evaluationMode || 'reported'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-600">Current Validation:</span>
              <span className="text-slate-600">Insufficient evidence (offline)</span>
            </div>
          </div>
        </div>

        {/* DMARC */}
        <div className={`p-4 rounded-xl border transition-all ${dmarc?.status === 'PASS' ? 'bg-slate-50/60 border-slate-200' : 'bg-rose-50/50 border-rose-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <div>
              <span className="text-xs font-bold text-slate-800 block">Reported DMARC</span>
              <span className="text-[10px] text-slate-400">{dmarc?.source || 'Header-reported claim'}</span>
            </div>
            {getStatusBadge(dmarc?.status)}
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {dmarc?.details || 'No DMARC policy reported in headers.'}
          </p>
          <div className="mt-2.5 pt-2 border-t border-slate-200/60 text-[10px] text-slate-500 space-y-0.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-600">Verification Source:</span>
              <span className="font-mono uppercase text-blue-700 font-semibold">{dmarc?.evaluationMode || 'reported'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-600">Current Validation:</span>
              <span className="text-slate-600">Insufficient evidence (offline)</span>
            </div>
          </div>
        </div>

      </div>

      {/* Row 2: Sender Deception Checks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-1">
        
        {/* Display Name & Lookalike Analysis */}
        <div className="p-4 rounded-xl bg-slate-50/70 border border-slate-200 space-y-2 text-xs">
          <div className="flex items-center justify-between border-b border-slate-200/60 pb-2">
            <span className="font-bold text-slate-800 flex items-center gap-1.5">
              <UserCheck className="w-4 h-4 text-blue-600" />
              Display Name & Impersonation Check
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              displayNameAnalysis?.isSpoofed ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'
            }`}>
              {displayNameAnalysis?.isSpoofed ? 'Potential Deception' : 'Conforming'}
            </span>
          </div>
          <p className="text-slate-600 leading-relaxed">
            {displayNameAnalysis?.details || 'No display name impersonation indicators detected.'}
          </p>
          <div className="text-[11px] text-slate-500 space-y-0.5 pt-1">
            <div>Claimed Name: <strong className="text-slate-800 font-mono">"{envelope?.from?.name || 'None'}"</strong></div>
            <div>Actual Address: <strong className="text-slate-800 font-mono">{envelope?.from?.address}</strong></div>
          </div>
        </div>

        {/* Alignment & Reply-To Consistency */}
        <div className="p-4 rounded-xl bg-slate-50/70 border border-slate-200 space-y-2 text-xs">
          <div className="flex items-center justify-between border-b border-slate-200/60 pb-2">
            <span className="font-bold text-slate-800 flex items-center gap-1.5">
              <ArrowRightLeft className="w-4 h-4 text-purple-600" />
              Reply-To & Domain Alignment
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              alignmentAnalysis?.hasMismatch ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'
            }`}>
              {alignmentAnalysis?.hasMismatch ? 'Header Inconsistency' : 'Aligned'}
            </span>
          </div>
          <p className="text-slate-600 leading-relaxed">
            {alignmentAnalysis?.details || 'From and Reply-To domains are mutually aligned.'}
          </p>
          <div className="text-[11px] text-slate-500 space-y-0.5 pt-1">
            <div>From Domain: <span className="font-mono text-slate-700">{envelope?.from?.domain || 'N/A'}</span></div>
            <div>Reply-To: <span className="font-mono text-slate-700">{envelope?.replyTo?.address || 'Same as sender'}</span></div>
          </div>
        </div>

      </div>

    </div>
  );
}
