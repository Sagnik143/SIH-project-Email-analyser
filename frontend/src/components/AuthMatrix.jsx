import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, UserCheck, AtSign, ArrowRightLeft } from 'lucide-react';

export default function AuthMatrix({ authentication, envelope }) {
  if (!authentication) return null;

  const { spf, dkim, dmarc, displayNameAnalysis, domainAnalysis, alignmentAnalysis, authRiskScore } = authentication;

  const getStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">PASS</span>;
      case 'FAIL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/15 border border-rose-500/30 text-rose-400 animate-pulse">FAIL</span>;
      case 'SOFTFAIL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-500/15 border border-amber-500/30 text-amber-400">SOFTFAIL</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-800 border border-slate-700 text-slate-400">{status || 'NONE'}</span>;
    }
  };

  return (
    <div className="glass-panel p-5 space-y-4">
      
      {/* Title */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              Sender Authentication & Identity Forensics
            </h3>
            <p className="text-[11px] text-slate-400">
              Cryptographic integrity verification (SPF, DKIM, DMARC), Display-Name spoofing & lookalike domain analysis
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">Auth Threat Risk:</span>
          <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${authRiskScore >= 50 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
            {authRiskScore}/100
          </span>
        </div>
      </div>

      {/* Row 1: The Triple Protocols (SPF, DKIM, DMARC) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        
        {/* SPF */}
        <div className={`p-3 rounded-lg border ${spf?.status === 'PASS' ? 'bg-slate-900/50 border-slate-800' : 'bg-rose-950/20 border-rose-500/30'}`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold font-mono text-slate-200">SPF (Sender Policy)</span>
            {getStatusBadge(spf?.status)}
          </div>
          <p className="text-xs text-slate-400 leading-relaxed font-sans">
            {spf?.details || 'No SPF records evaluated.'}
          </p>
        </div>

        {/* DKIM */}
        <div className={`p-3 rounded-lg border ${dkim?.status === 'PASS' ? 'bg-slate-900/50 border-slate-800' : 'bg-rose-950/20 border-rose-500/30'}`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold font-mono text-slate-200">DKIM (Crypto Signature)</span>
            {getStatusBadge(dkim?.status)}
          </div>
          <p className="text-xs text-slate-400 leading-relaxed font-sans">
            {dkim?.details || 'No cryptographic signature header found.'}
          </p>
        </div>

        {/* DMARC */}
        <div className={`p-3 rounded-lg border ${dmarc?.status === 'PASS' ? 'bg-slate-900/50 border-slate-800' : 'bg-rose-950/20 border-rose-500/30'}`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold font-mono text-slate-200">DMARC (Domain Policy)</span>
            {getStatusBadge(dmarc?.status)}
          </div>
          <p className="text-xs text-slate-400 leading-relaxed font-sans">
            {dmarc?.details || 'No DMARC policy assertion identified.'}
          </p>
        </div>

      </div>

      {/* Row 2: Advanced Identity Deception Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
        
        {/* Display Name Spoofing */}
        <div className={`p-3 rounded-lg border ${displayNameAnalysis?.isSpoofed ? 'bg-rose-950/30 border-rose-500/40 shadow-sm' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold font-mono text-slate-200 flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" /> Display-Name Spoof
            </span>
            {displayNameAnalysis?.isSpoofed ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 border border-rose-500/40 text-rose-400">
                SPOOFED
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/15 text-emerald-400">
                NORMAL
              </span>
            )}
          </div>
          <div className="text-xs text-slate-300">
            Name: <span className="font-mono text-cyan-300 font-medium">"{envelope?.from?.name || 'None'}"</span>
          </div>
          {displayNameAnalysis?.flags?.length > 0 ? (
            <div className="mt-2 space-y-1">
              {displayNameAnalysis.flags.map((flag, idx) => (
                <div key={idx} className="text-[11px] text-rose-300 flex items-start gap-1 font-mono">
                  <span>⚠</span> <span>{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-slate-500 mt-1">No authority or webmail spoofing patterns detected.</p>
          )}
        </div>

        {/* Domain Lookalike / Typosquatting */}
        <div className={`p-3 rounded-lg border ${domainAnalysis?.isLookalike ? 'bg-rose-950/30 border-rose-500/40 shadow-sm' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold font-mono text-slate-200 flex items-center gap-1.5">
              <AtSign className="w-3.5 h-3.5 text-cyan-400" /> Lookalike Domain
            </span>
            {domainAnalysis?.isLookalike ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 border border-rose-500/40 text-rose-400">
                TYPOSQUAT
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/15 text-emerald-400">
                LEGITIMATE
              </span>
            )}
          </div>
          <div className="text-xs text-slate-300">
            Domain: <span className="font-mono text-cyan-300 font-medium">{envelope?.from?.domain || 'None'}</span>
          </div>
          {domainAnalysis?.flags?.length > 0 ? (
            <div className="mt-2 space-y-1">
              {domainAnalysis.flags.map((flag, idx) => (
                <div key={idx} className="text-[11px] text-rose-300 flex items-start gap-1 font-mono">
                  <span>⚠</span> <span>{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-slate-500 mt-1">Domain does not imitate popular corporate brands or use homoglyphs.</p>
          )}
        </div>

        {/* Reply-To / Return-Path Alignment */}
        <div className={`p-3 rounded-lg border ${alignmentAnalysis?.hasReplyToDiscrepancy ? 'bg-rose-950/30 border-rose-500/40 shadow-sm' : 'bg-slate-900/50 border-slate-800'}`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold font-mono text-slate-200 flex items-center gap-1.5">
              <ArrowRightLeft className="w-3.5 h-3.5 text-cyan-400" /> Header Alignment
            </span>
            {alignmentAnalysis?.hasReplyToDiscrepancy ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 border border-rose-500/40 text-rose-400">
                DISCREPANCY
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/15 text-emerald-400">
                ALIGNED
              </span>
            )}
          </div>
          <div className="text-xs text-slate-300">
            Reply-To: <span className="font-mono text-cyan-300 font-medium">{envelope?.replyTo?.address || '(Default From)'}</span>
          </div>
          {alignmentAnalysis?.flags?.length > 0 ? (
            <div className="mt-2 space-y-1">
              {alignmentAnalysis.flags.map((flag, idx) => (
                <div key={idx} className="text-[11px] text-rose-300 flex items-start gap-1 font-mono">
                  <span>⚠</span> <span>{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-slate-500 mt-1">From, Reply-To, and Return-Path routes are aligned.</p>
          )}
        </div>

      </div>

    </div>
  );
}
