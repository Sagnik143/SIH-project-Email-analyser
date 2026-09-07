import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Globe, Server, UserCheck, Sparkles, MapPin, Activity, Info } from 'lucide-react';

export default function ThreatScoreCard({ dossier, onSelectEvidence }) {
  if (!dossier) return null;

  const ai = dossier.aiThreatIntelligence || {};
  const score = ai.riskScore ?? 0;
  const level = ai.threatLevel || 'LOW';
  const classification = ai.threatClassification || 'Unclassified Telemetry';

  // Determine vibrant colors
  let strokeColor = '#10b981'; // Emerald
  let badgeBg = 'bg-emerald-50 text-emerald-700 border-emerald-200';
  let levelText = 'LOW HEURISTIC RISK';
  let iconComponent = <ShieldCheck className="w-5 h-5 text-emerald-600" />;

  if (score >= 70) {
    strokeColor = '#f43f5e'; // Rose
    badgeBg = 'bg-rose-50 text-rose-700 border-rose-200';
    levelText = 'ELEVATED HEURISTIC RISK';
    iconComponent = <ShieldAlert className="w-5 h-5 text-rose-600 animate-pulse" />;
  } else if (score >= 40) {
    strokeColor = '#f59e0b'; // Amber
    badgeBg = 'bg-amber-50 text-amber-700 border-amber-200';
    levelText = 'SUSPICIOUS SIGNALS DETECTED';
    iconComponent = <AlertTriangle className="w-5 h-5 text-amber-600" />;
  }

  // Circular gauge calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const origin = dossier.originGeo || {};
  const auth = dossier.authentication || {};
  const signals = ai.contributingFactors || ai.keyObservations || [];

  return (
    <div className="app-card p-6 border-slate-200 bg-white space-y-4">
      
      {/* Top Banner: Heuristic Nature Notice */}
      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-600 text-xs flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-blue-600 shrink-0" />
          <span>
            <strong>Heuristic Assessment:</strong> Risk score is a deterministic assessment based on observed telemetry signals. It is not a calibrated probability or certainty of maliciousness.
          </span>
        </div>
        <span className="text-[10px] font-bold uppercase tracking-wider text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200 shrink-0">
          Deterministic Engine
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        
        {/* Left: Circular Risk Score Gauge */}
        <div className="lg:col-span-3 flex flex-col items-center justify-center p-3 bg-slate-50/80 rounded-2xl border border-slate-100">
          <div className="relative flex items-center justify-center">
            <svg className="w-36 h-36 transform -rotate-90" viewBox="0 0 140 140">
              {/* Background Track */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                stroke="#e2e8f0"
                strokeWidth="10"
                fill="transparent"
              />
              {/* Progress Bar Circle */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                stroke={strokeColor}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-1000 ease-out"
              />
            </svg>

            {/* Center Score Label */}
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-black tracking-tight" style={{ color: strokeColor }}>
                {score}
              </span>
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                Heuristic Risk
              </span>
            </div>
          </div>

          <div className="mt-3 text-center">
            <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${badgeBg}`}>
              {levelText}
            </span>
            <div className="text-[10px] text-slate-400 mt-1">
              Score: {score} / 100
            </div>
          </div>
        </div>

        {/* Center: Threat Classification & Contributing Signals */}
        <div className="lg:col-span-5 flex flex-col justify-center space-y-3">
          <div>
            <div className="flex items-center gap-2.5">
              {iconComponent}
              <h2 className="text-2xl font-black text-slate-900 tracking-tight">
                {classification}
              </h2>
            </div>
            <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
              {ai.executiveSummary || 'Comprehensive multi-vector forensic evaluation of email payload, transmission hops, and sender headers.'}
            </p>
          </div>

          {/* Contributing Signals (Explaining why the score increased) */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5 text-xs">
            <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase text-slate-600 tracking-wide">
              <Activity className="w-3.5 h-3.5 text-blue-600" />
              <span>Contributing Observed Signals:</span>
            </div>
            {signals.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {signals.slice(0, 4).map((sig, idx) => (
                  <span key={idx} className="px-2 py-0.5 rounded-lg bg-white border border-slate-200 text-slate-800 text-[11px] font-medium">
                    &bull; {sig}
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-slate-500 text-[11px] italic">
                Baseline email telemetry; no elevated risk indicators identified.
              </div>
            )}
          </div>
        </div>

        {/* Right: Observed Infrastructure & Reported Authentication Badges */}
        <div className="lg:col-span-4 flex flex-col justify-center space-y-3.5 border-t lg:border-t-0 lg:border-l border-slate-100 pt-4 lg:pt-0 lg:pl-6">
          
          {/* Origin Infrastructure Card */}
          <div className="p-3.5 rounded-xl bg-blue-50/60 border border-blue-100 flex items-start gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-xs mt-0.5">
              <Globe className="w-4 h-4" />
            </div>
            <div className="text-xs space-y-0.5">
              <div className="flex items-center gap-1.5">
                <span className="text-blue-800 font-bold text-[11px] uppercase tracking-wide block">Claimed Origin</span>
                <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-amber-100 text-amber-800 border border-amber-200">UNVERIFIED</span>
              </div>
              <span className="font-mono font-bold text-slate-900 text-xs block">
                {origin.ip || 'Unknown IP'}
              </span>
              <span className="text-slate-600 block text-[11px]">
                📍 Observed Infrastructure: {origin.city ? `${origin.city}, ${origin.country}` : origin.country || 'Unknown Location'} ({origin.countryCode || 'N/A'})
              </span>
              <span className="text-slate-500 text-[10px] block truncate max-w-[210px]">
                ISP: {origin.isp || 'Unresolved ISP'}
              </span>
            </div>
          </div>

          {/* Quick Authentication Badges */}
          <div className="grid grid-cols-3 gap-2">
            <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] text-slate-500 block uppercase font-bold tracking-wider" title="Reported by receiving system header">Reported SPF</span>
              <span className={`text-xs font-extrabold ${auth.spf?.status === 'PASS' ? 'text-emerald-600' : 'text-rose-600'}`}>
                {auth.spf?.status === 'PASS' ? '✓ PASS' : (auth.spf?.status || 'FAIL')}
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] text-slate-500 block uppercase font-bold tracking-wider" title="Reported by receiving system header">Reported DKIM</span>
              <span className={`text-xs font-extrabold ${auth.dkim?.status === 'PASS' ? 'text-emerald-600' : 'text-rose-600'}`}>
                {auth.dkim?.status === 'PASS' ? '✓ PASS' : (auth.dkim?.status || 'FAIL')}
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] text-slate-500 block uppercase font-bold tracking-wider" title="Reported by receiving system header">Reported DMARC</span>
              <span className={`text-xs font-extrabold ${auth.dmarc?.status === 'PASS' ? 'text-emerald-600' : 'text-rose-600'}`}>
                {auth.dmarc?.status === 'PASS' ? '✓ PASS' : (auth.dmarc?.status || 'FAIL')}
              </span>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
