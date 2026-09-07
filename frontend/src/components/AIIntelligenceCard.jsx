import React from 'react';
import { Brain, Sparkles, CheckCircle2, Lightbulb, AlertOctagon, UserX, Shield } from 'lucide-react';

export default function AIIntelligenceCard({ aiThreatIntelligence }) {
  if (!aiThreatIntelligence) return null;

  const ai = aiThreatIntelligence;
  const tactics = ai.socialEngineeringTactics || [];
  const actions = ai.recommendedActions || [];

  return (
    <div className="app-card p-6 space-y-5 bg-white border-slate-200 shadow-xs">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-gradient-to-tr from-purple-600 to-indigo-600 text-white shadow-md shadow-purple-500/20">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
              AI Security Analysis & Deception Detection
            </h3>
            <p className="text-xs text-slate-500">
              Semantic evaluation powered by GPT-6 Astra LLM & psychological manipulation detection
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {ai.reasoningTokens !== undefined && ai.reasoningTokens !== null && (
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-amber-50 text-amber-800 border border-amber-200 flex items-center gap-1 shadow-2xs">
              ⚡ Reasoning: {ai.reasoningTokens} tokens
            </span>
          )}
          <span className="text-xs font-semibold px-3 py-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-1.5 shadow-2xs">
            <Sparkles className="w-3.5 h-3.5 text-purple-600" />
            {ai.modelUsed || 'gpt-6-astra'}
          </span>
        </div>
      </div>

      {/* Social Engineering Tactics Chips */}
      <div>
        <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block mb-2.5">
          Detected Psychological Triggers & Tactics:
        </span>
        <div className="flex flex-wrap gap-2">
          {tactics.map((tactic, idx) => (
            <span 
              key={idx} 
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-bold shadow-2xs"
            >
              <AlertOctagon className="w-3.5 h-3.5 text-rose-500" />
              {tactic}
            </span>
          ))}
        </div>
      </div>

      {/* Incident Hypothesis & Attribution Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        
        {/* Left: Forensic Hypothesis */}
        <div className="md:col-span-7 p-4 rounded-xl bg-slate-50/80 border border-slate-200 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
            <Lightbulb className="w-4 h-4 text-amber-500" />
            <span>Forensic Incident Hypothesis</span>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            {ai.forensicHypothesis || 'No suspicious anomalies detected.'}
          </p>
        </div>

        {/* Right: Threat Actor Profile & Attribution */}
        <div className="md:col-span-5 p-4 rounded-xl bg-purple-50/60 border border-purple-100 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold text-purple-900">
            <UserX className="w-4 h-4 text-purple-600" />
            <span>Probable Attacker Persona</span>
          </div>
          <div className="text-sm font-bold text-purple-950">
            {ai.threatActorPersona || ai.attribution?.probableActorPersona || 'Authorized Sender'}
          </div>
          {ai.attribution?.campaignCluster && (
            <div className="pt-1">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Campaign Cluster: </span>
              <span className="text-xs font-mono font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">
                {ai.attribution.campaignCluster}
              </span>
            </div>
          )}
          {ai.attribution?.infrastructureClassification && (
            <div className="text-[11px] text-slate-600">
              <span className="font-semibold">Infrastructure: </span>
              {ai.attribution.infrastructureClassification}
            </div>
          )}
        </div>

      </div>

      {/* Recommended Security Actions */}
      <div className="p-4 rounded-xl bg-blue-50/50 border border-blue-100 space-y-3">
        <div className="flex items-center gap-2 text-xs font-bold text-blue-900 uppercase tracking-wide">
          <Shield className="w-4 h-4 text-blue-600" />
          <span>Recommended Security Response Checklist:</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          {actions.map((action, idx) => (
            <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-700 bg-white p-3 rounded-xl border border-slate-200 shadow-2xs">
              <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
              <span className="font-medium leading-relaxed">{action}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
