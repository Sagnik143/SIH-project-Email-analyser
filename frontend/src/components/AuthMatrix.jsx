import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, UserCheck, AtSign, ArrowRightLeft, CheckCircle2, XCircle } from 'lucide-react';

export default function AuthMatrix({ authentication, envelope }) {
  if (!authentication) return null;

  const { spf, dkim, dmarc, displayNameAnalysis, domainAnalysis, alignmentAnalysis, authRiskScore } = authentication;

  const getStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">✓ PASS</span>;
      case 'FAIL':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">✕ FAIL</span>;
      case 'SOFTFAIL':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-200">⚠ SOFTFAIL</span>;
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
              Sender Identity & Authentication Verifications
            </h3>
            <p className="text-xs text-slate-500">
              Cryptographic integrity (SPF, DKIM, DMARC), display name spoofing & typosquatting detection
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-semibold">Security Risk:</span>
          <span className={`text-xs font-extrabold px-3 py-1 rounded-full ${
            authRiskScore >= 50 ? 'bg-rose-100 text-rose-700 border border-rose-200' : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
          }`}>
            {authRiskScore}/100
          </span>
        </div>
      </div>

      {/* Row 1: Triple Email Protocols */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        
        {/* SPF */}
        <div className={`p-4 rounded-xl border transition-all ${spf?.status === 'PASS' ? 'bg-slate-50/60 border-slate-200' : 'bg-rose-50/50 border-rose-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-800">SPF Verification</span>
            {getStatusBadge(spf?.status)}
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {spf?.details || 'No SPF record found.'}
          </p>
        </div>

        {/* DKIM */}
        <div className={`p-4 rounded-xl border transition-all ${dkim?.status === 'PASS' ? 'bg-slate-50/60 border-slate-200' : 'bg-rose-50/50 border-rose-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-800">DKIM Digital Signature</span>
            {getStatusBadge(dkim?.status)}
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {dkim?.details || 'No cryptographic signature header found.'}
          </p>
        </div>

        {/* DMARC */}
        <div className={`p-4 rounded-xl border transition-all ${dmarc?.status === 'PASS' ? 'bg-slate-50/60 border-slate-200' : 'bg-rose-50/50 border-rose-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-800">DMARC Policy Enforcement</span>
            {getStatusBadge(dmarc?.status)}
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {dmarc?.details || 'No DMARC policy assertion identified.'}
          </p>
        </div>

      </div>

      {/* Row 2: Advanced Identity Deception Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 pt-1">
        
        {/* Display Name Spoofing */}
        <div className={`p-4 rounded-xl border transition-all ${displayNameAnalysis?.isSpoofed ? 'bg-rose-50/70 border-rose-300 shadow-xs' : 'bg-slate-50/60 border-slate-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
              <UserCheck className="w-4 h-4 text-blue-600" /> Display-Name Spoof
            </span>
            {displayNameAnalysis?.isSpoofed ? (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">
                SPOOFED
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                NORMAL
              </span>
            )}
          </div>
          <div className="text-xs text-slate-700">
            Display: <strong className="text-slate-900">"{envelope?.from?.name || 'None'}"</strong>
          </div>
          {displayNameAnalysis?.flags?.length > 0 ? (
            <div className="mt-2.5 space-y-1">
              {displayNameAnalysis.flags.map((flag, idx) => (
                <div key={idx} className="text-xs text-rose-700 flex items-start gap-1.5 font-medium">
                  <span className="text-rose-600 font-bold">⚠</span> <span>{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 mt-1">No deceptive display name or authority mismatch.</p>
          )}
        </div>

        {/* Domain Lookalike / Typosquatting */}
        <div className={`p-4 rounded-xl border transition-all ${domainAnalysis?.isLookalike ? 'bg-rose-50/70 border-rose-300 shadow-xs' : 'bg-slate-50/60 border-slate-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
              <AtSign className="w-4 h-4 text-blue-600" /> Lookalike Domain
            </span>
            {domainAnalysis?.isLookalike ? (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">
                TYPOSQUAT
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                AUTHENTIC
              </span>
            )}
          </div>
          <div className="text-xs text-slate-700">
            Domain: <strong className="text-slate-900">{envelope?.from?.domain || 'None'}</strong>
          </div>
          {domainAnalysis?.flags?.length > 0 ? (
            <div className="mt-2.5 space-y-1">
              {domainAnalysis.flags.map((flag, idx) => (
                <div key={idx} className="text-xs text-rose-700 flex items-start gap-1.5 font-medium">
                  <span className="text-rose-600 font-bold">⚠</span> <span>{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 mt-1">Domain does not visually mimic any major corporate brand.</p>
          )}
        </div>

        {/* Reply-To Discrepancy */}
        <div className={`p-4 rounded-xl border transition-all ${alignmentAnalysis?.hasReplyToDiscrepancy ? 'bg-rose-50/70 border-rose-300 shadow-xs' : 'bg-slate-50/60 border-slate-200'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
              <ArrowRightLeft className="w-4 h-4 text-blue-600" /> Header Route Check
            </span>
            {alignmentAnalysis?.hasReplyToDiscrepancy ? (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">
                MISMATCH
              </span>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                ALIGNED
              </span>
            )}
          </div>
          <div className="text-xs text-slate-700">
            Reply-To: <strong className="text-slate-900">{envelope?.replyTo?.address || 'Same as From'}</strong>
          </div>
          {alignmentAnalysis?.flags?.length > 0 ? (
            <div className="mt-2.5 space-y-1">
              {alignmentAnalysis.flags.map((flag, idx) => (
                <div key={idx} className="text-xs text-rose-700 flex items-start gap-1.5 font-medium">
                  <span className="text-rose-600 font-bold">⚠</span> <span>{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 mt-1">From, Reply-To, and Return-Path routes are aligned.</p>
          )}
        </div>

      </div>

    </div>
  );
}
