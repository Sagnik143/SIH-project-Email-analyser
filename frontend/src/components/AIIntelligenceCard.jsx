import React from 'react';
import { BrainCircuit, AlertOctagon, CheckSquare, Lightbulb, UserX, Cpu, Sparkles } from 'lucide-react';

export default function AIIntelligenceCard({ aiThreatIntelligence }) {
  if (!aiThreatIntelligence) return null;

  const ai = aiThreatIntelligence;
  const tactics = ai.socialEngineeringTactics || [];
  const actions = ai.recommendedActions || [];

  return (
    <div className="glass-panel p-5 space-y-4 border-purple-500/20">
      
      {/* Card Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-purple-500/15 text-purple-400 border border-purple-500/30 shadow-sm shadow-purple-500/10">
            <BrainCircuit className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-1.5">
              AI Forensic Intelligence & Attack Analysis
            </h3>
            <p className="text-[11px] text-slate-400">
              OpenRouter LLM semantic analysis, cognitive deception profiling & mitigation recommendations
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-purple-950/60 border border-purple-800/60 text-purple-300 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-purple-400" />
            Model: {ai.modelUsed || 'minimax/minimax-m3:free'}
          </span>
          {ai.reasoningTokens > 0 && (
            <span className="text-[10px] font-mono text-slate-400">
              ({ai.reasoningTokens} tokens)
            </span>
          )}
        </div>
      </div>

      {/* Social Engineering Tactics Chips */}
      <div>
        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-2">
          Identified Social Engineering & Deception Tactics:
        </span>
        <div className="flex flex-wrap gap-2">
          {tactics.map((tactic, idx) => (
            <span 
              key={idx} 
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono font-medium shadow-sm"
            >
              <AlertOctagon className="w-3 h-3 text-rose-400" />
              {tactic}
            </span>
          ))}
        </div>
      </div>

      {/* Forensic Hypothesis & Attack Vector */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        
        {/* Left: Forensic Hypothesis */}
        <div className="md:col-span-7 p-3.5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200 font-mono">
            <Lightbulb className="w-3.5 h-3.5 text-amber-400" />
            <span>Forensic Incident Hypothesis:</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            {ai.forensicHypothesis || 'No anomaly hypothesis generated.'}
          </p>
        </div>

        {/* Right: Threat Actor Profile */}
        <div className="md:col-span-5 p-3.5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200 font-mono">
            <UserX className="w-3.5 h-3.5 text-rose-400" />
            <span>Threat Actor Persona:</span>
          </div>
          <div className="font-mono text-sm font-bold text-rose-300">
            {ai.threatActorPersona || 'Unknown Actor'}
          </div>
          <p className="text-[11px] text-slate-400 leading-normal">
            Profile derived through correlation of linguistic pressure cues, relay hop evasion, and sender impersonation.
          </p>
        </div>

      </div>

      {/* SOC Mitigation Playbook */}
      <div className="p-3.5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2.5">
        <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-300 font-mono uppercase tracking-wider">
          <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
          <span>Recommended SOC Mitigation Playbook:</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {actions.map((action, idx) => (
            <div key={idx} className="flex items-start gap-2 text-xs text-slate-300 bg-slate-950/60 p-2 rounded border border-slate-800/80">
              <span className="text-cyan-400 font-mono font-bold shrink-0">0{idx + 1}.</span>
              <span>{action}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
