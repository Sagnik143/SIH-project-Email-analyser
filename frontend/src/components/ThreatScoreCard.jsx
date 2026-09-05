import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Globe, Server, UserCheck, AlertOctagon, Sparkles, MapPin } from 'lucide-react';

export default function ThreatScoreCard({ dossier }) {
  if (!dossier) return null;

  const ai = dossier.aiThreatIntelligence || {};
  const score = ai.riskScore ?? 0;
  const level = ai.threatLevel || 'LOW';
  const classification = ai.threatClassification || 'Unclassified';
  const confidence = ai.confidenceScore || 90;

  // Determine vibrant colors
  let strokeColor = '#10b981'; // Emerald
  let badgeBg = 'bg-emerald-50 text-emerald-700 border-emerald-200';
  let levelText = 'LOW RISK';
  let iconComponent = <ShieldCheck className="w-5 h-5 text-emerald-600" />;

  if (score >= 70) {
    strokeColor = '#f43f5e'; // Rose
    badgeBg = 'bg-rose-50 text-rose-700 border-rose-200';
    levelText = 'CRITICAL THREAT';
    iconComponent = <ShieldAlert className="w-5 h-5 text-rose-600 animate-bounce" />;
  } else if (score >= 40) {
    strokeColor = '#f59e0b'; // Amber
    badgeBg = 'bg-amber-50 text-amber-700 border-amber-200';
    levelText = 'SUSPICIOUS RISK';
    iconComponent = <AlertTriangle className="w-5 h-5 text-amber-600" />;
  }

  // Circular gauge calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const origin = dossier.originGeo || {};
  const auth = dossier.authentication || {};

  return (
    <div className="app-card p-6 border-slate-200 bg-white">
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
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">
                Risk Score
              </span>
            </div>
          </div>

          <div className="mt-3">
            <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${badgeBg}`}>
              {levelText}
            </span>
          </div>
        </div>

        {/* Center: Threat Classification & Plain-English Verdict */}
        <div className="lg:col-span-5 flex flex-col justify-center space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider text-blue-600 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" /> AI Threat Assessment
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-xs text-slate-500 font-medium">
              Confidence: <strong className="text-slate-700">{confidence}%</strong>
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              {iconComponent}
              <h2 className="text-2xl font-black text-slate-900 tracking-tight">
                {classification}
              </h2>
            </div>
            <p className="text-sm text-slate-600 mt-1.5 leading-relaxed">
              {ai.executiveSummary || 'Comprehensive multi-vector forensic evaluation of email payload, transmission hops, and sender headers.'}
            </p>
          </div>

          {/* Threat Actor Persona / Attribution */}
          <div className="p-3 rounded-xl bg-purple-50/70 border border-purple-100 flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-600 text-white flex items-center justify-center font-bold text-xs shrink-0 shadow-xs">
              🎯
            </div>
            <div className="text-xs">
              <span className="text-purple-600 font-semibold block text-[11px] uppercase tracking-wide">Attribution Profile</span>
              <span className="font-bold text-purple-950 text-sm">
                {ai.threatActorPersona || 'Unknown Threat Profile'}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Origin Infrastructure & Quick Authentication Badges */}
        <div className="lg:col-span-4 flex flex-col justify-center space-y-4 border-t lg:border-t-0 lg:border-l border-slate-100 pt-4 lg:pt-0 lg:pl-6">
          
          {/* Origin Card */}
          <div className="p-3.5 rounded-xl bg-blue-50/60 border border-blue-100 flex items-start gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-sm mt-0.5">
              <Globe className="w-4 h-4" />
            </div>
            <div className="text-xs">
              <span className="text-blue-700 font-semibold text-[11px] uppercase tracking-wide block">Sender Origin Server</span>
              <span className="font-mono font-bold text-slate-900 text-sm">
                {origin.ip || 'Unknown IP'}
              </span>
              <span className="text-slate-600 block text-xs font-medium mt-0.5">
                📍 {origin.city ? `${origin.city}, ${origin.country}` : origin.country || 'Unknown Location'} ({origin.countryCode})
              </span>
              <span className="text-slate-500 text-[11px] block truncate max-w-[220px]">
                {origin.isp}
              </span>
            </div>
          </div>

          {/* Quick Authentication Indicators */}
          <div className="grid grid-cols-3 gap-2">
            <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] text-slate-500 block uppercase font-bold tracking-wider">SPF Check</span>
              <span className={`text-xs font-extrabold ${auth.spf?.status === 'PASS' ? 'text-emerald-600' : 'text-rose-600'}`}>
                {auth.spf?.status === 'PASS' ? '✓ PASS' : (auth.spf?.status || 'FAIL')}
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] text-slate-500 block uppercase font-bold tracking-wider">DKIM Check</span>
              <span className={`text-xs font-extrabold ${auth.dkim?.status === 'PASS' ? 'text-emerald-600' : 'text-rose-600'}`}>
                {auth.dkim?.status === 'PASS' ? '✓ PASS' : (auth.dkim?.status || 'FAIL')}
              </span>
            </div>
            <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] text-slate-500 block uppercase font-bold tracking-wider">DMARC Check</span>
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
