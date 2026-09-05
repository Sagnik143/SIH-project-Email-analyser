import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Globe, Server, UserCheck, AlertOctagon, Terminal, Radio } from 'lucide-react';

export default function ThreatScoreCard({ dossier }) {
  if (!dossier) return null;

  const ai = dossier.aiThreatIntelligence || {};
  const score = ai.riskScore ?? 0;
  const level = ai.threatLevel || 'LOW';
  const classification = ai.threatClassification || 'Unclassified';
  const confidence = ai.confidenceScore || 90;

  // Determine score colors
  let strokeColor = '#10b981'; // emerald
  let glowClass = 'glow-border-emerald';
  let badgeColor = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';

  if (score >= 70) {
    strokeColor = '#ff3366'; // crimson
    glowClass = 'glow-border-rose';
    badgeColor = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
  } else if (score >= 40) {
    strokeColor = '#f59e0b'; // amber
    glowClass = 'glow-border-amber';
    badgeColor = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
  }

  // Circular gauge calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const origin = dossier.originGeo || {};
  const auth = dossier.authentication || {};
  const iocs = dossier.iocs || {};

  return (
    <div className={`glass-panel p-5 relative overflow-hidden ${score >= 70 ? 'border-rose-500/30' : 'border-slate-800'}`}>
      
      {/* Background ambient gradient */}
      <div 
        className="absolute -right-16 -top-16 w-56 h-56 rounded-full opacity-15 pointer-events-none blur-3xl"
        style={{ background: strokeColor }}
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        
        {/* Left: Circular Risk Score Gauge */}
        <div className="lg:col-span-3 flex flex-col items-center justify-center p-2">
          <div className="relative flex items-center justify-center">
            <svg className="w-36 h-36 transform -rotate-90" viewBox="0 0 140 140">
              {/* Background Circle Track */}
              <circle
                cx="70"
                cy="70"
                r={radius}
                stroke="currentColor"
                strokeWidth="10"
                fill="transparent"
                className="text-slate-800/80"
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
              <span className="text-3xl font-extrabold font-mono tracking-tight" style={{ color: strokeColor }}>
                {score}
              </span>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
                / 100 Risk
              </span>
            </div>
          </div>

          <div className="mt-2 text-center">
            <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider border ${badgeColor}`}>
              {level} THREAT
            </span>
          </div>
        </div>

        {/* Center: Threat Classification & Attack Persona */}
        <div className="lg:col-span-5 flex flex-col justify-center space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-[11px] uppercase tracking-wider font-mono text-cyan-400 flex items-center gap-1">
              <Radio className="w-3 h-3 animate-pulse" /> Threat Telemetry Assessment
            </span>
            <span className="text-xs text-slate-500 font-mono">•</span>
            <span className="text-[11px] text-slate-400 font-mono">
              Confidence: <strong className="text-slate-200">{confidence}%</strong>
            </span>
          </div>

          <div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
              {classification}
            </h2>
            <p className="text-xs text-slate-400 mt-1 line-clamp-2">
              {ai.executiveSummary || 'Comprehensive multi-vector forensic evaluation of email payload, transmission hops, and sender headers.'}
            </p>
          </div>

          {/* Threat Actor Persona */}
          <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
              <Terminal className="w-3.5 h-3.5" />
            </div>
            <div className="text-xs">
              <span className="text-slate-400 text-[11px] block">Attribution / Actor Persona</span>
              <span className="font-semibold text-purple-300 font-mono">
                {ai.threatActorPersona || 'Unknown Threat Actor'}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Origin Infrastructure & Authentication Health */}
        <div className="lg:col-span-4 flex flex-col justify-center space-y-3 border-t lg:border-t-0 lg:border-l border-slate-800/80 pt-4 lg:pt-0 lg:pl-6">
          
          {/* Originating IP & Geo */}
          <div className="flex items-start gap-2.5">
            <div className="w-7 h-7 rounded-md bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0 mt-0.5">
              <Globe className="w-3.5 h-3.5" />
            </div>
            <div className="text-xs">
              <span className="text-slate-400 text-[11px] block font-mono">Originating Client IP</span>
              <span className="font-mono font-bold text-cyan-300">
                {origin.ip || 'Unknown IP'}
              </span>
              <span className="text-slate-300 block text-[11px]">
                {origin.city ? `${origin.city}, ${origin.country}` : origin.country || 'Unknown Location'} ({origin.countryCode})
              </span>
              <span className="text-slate-400 text-[10px] block truncate max-w-[220px]">
                {origin.isp}
              </span>
            </div>
          </div>

          {/* Quick Status Badges */}
          <div className="grid grid-cols-3 gap-2 pt-2">
            <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">SPF</span>
              <span className={`text-xs font-bold font-mono ${auth.spf?.status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {auth.spf?.status || 'NONE'}
              </span>
            </div>
            <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">DKIM</span>
              <span className={`text-xs font-bold font-mono ${auth.dkim?.status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {auth.dkim?.status || 'NONE'}
              </span>
            </div>
            <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">DMARC</span>
              <span className={`text-xs font-bold font-mono ${auth.dmarc?.status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                {auth.dmarc?.status || 'NONE'}
              </span>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
