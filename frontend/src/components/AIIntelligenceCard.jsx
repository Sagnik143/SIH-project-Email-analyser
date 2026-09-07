import React from 'react';
import { Brain, Sparkles, CheckCircle2, Lightbulb, AlertOctagon, UserX, Shield, Info, ArrowRight } from 'lucide-react';

export default function AIIntelligenceCard({ aiThreatIntelligence }) {
  if (!aiThreatIntelligence) return null;

  const ai = aiThreatIntelligence;
  const observations = ai.keyObservations || ai.observedTactics || ai.socialEngineeringTactics || [];
  const actions = ai.recommendedNextSteps || ai.recommendedActions || [];
  const hypotheses = Array.isArray(ai.investigativeHypotheses) && ai.investigativeHypotheses.length > 0
    ? ai.investigativeHypotheses
    : [
        {
          hypothesis: ai.investigativeHypothesis || ai.forensicHypothesis || 'No suspicious anomalies detected.',
          supportingFindingIds: [],
          confidence: 'low'
        }
      ];

  const isAvailable = ai.available !== false && ai.status !== 'unavailable';

  return (
    <div className="app-card p-6 space-y-5 bg-white border border-purple-200/80 shadow-xs">
      
      {/* Header with Visual Advisory Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-purple-100 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-purple-600 text-white shadow-xs">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-900 tracking-tight">
                AI Advisory &bull; Analyst Assistance
              </h3>
              <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-purple-100 text-purple-800 border border-purple-200 uppercase tracking-wide">
                Non-Authoritative
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Advisory synthesis and hypothesis generation grounded strictly in deterministic findings
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isAvailable ? (
            <span className="text-xs font-semibold px-3 py-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-1.5 shadow-2xs">
              <Sparkles className="w-3.5 h-3.5 text-purple-600" />
              <span>Advisory Assistant Active</span>
            </span>
          ) : (
            <span className="text-xs font-semibold px-3 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200 flex items-center gap-1.5 shadow-2xs">
              <AlertOctagon className="w-3.5 h-3.5 text-slate-400" />
              <span>AI Advisory: Unavailable</span>
            </span>
          )}
        </div>
      </div>

      {/* Mandatory Advisory Notice */}
      <div className="p-3.5 rounded-xl bg-purple-50/60 border border-purple-200 text-purple-950 text-xs flex items-start gap-2.5 leading-relaxed">
        <Info className="w-4 h-4 text-purple-700 shrink-0 mt-0.5" />
        <div>
          <strong>AI Advisory Limitation Notice:</strong> AI-generated content is advisory and does not constitute forensic evidence. Deterministic evidence and forensic findings are strictly authoritative. The AI engine does not create, modify, or delete authoritative findings.
        </div>
      </div>

      {/* 3 Core Structured Sections */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        
        {/* 1. What the evidence may indicate */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
          <span className="text-[11px] font-bold uppercase text-slate-700 tracking-wider flex items-center gap-1.5">
            <Lightbulb className="w-3.5 h-3.5 text-amber-500" />
            What the Evidence May Indicate:
          </span>
          <p className="text-slate-700 leading-relaxed font-medium">
            {ai.forensicHypothesis || ai.executiveSummary || 'Observed telemetry conforms to standard corporate mail patterns without critical anomalies.'}
          </p>
        </div>

        {/* 2. Suggested analyst checks */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
          <span className="text-[11px] font-bold uppercase text-slate-700 tracking-wider flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-blue-600" />
            Suggested Analyst Checks:
          </span>
          <ul className="space-y-1 text-slate-600 list-disc list-inside">
            <li>Verify originating MTA hostname against published SPF records.</li>
            <li>Inspect potential lookalike domains in corporate DNS logs.</li>
            <li>Confirm transaction authorization via secondary out-of-band communication.</li>
          </ul>
        </div>

        {/* 3. Potential investigative leads */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
          <span className="text-[11px] font-bold uppercase text-slate-700 tracking-wider flex items-center gap-1.5">
            <UserX className="w-3.5 h-3.5 text-purple-600" />
            Observed Tactics & Hypotheses:
          </span>
          <div className="text-slate-700 space-y-1">
            <div>Pattern: <strong>{ai.threatActorPersona || 'Unclassified Threat Profile'}</strong></div>
            <div className="text-[11px] text-slate-500 italic pt-1 border-t border-slate-200">
              Investigative hypothesis only. Attribution is not established from this email alone.
            </div>
          </div>
        </div>

      </div>

      {/* Actionable Recommended SOC Verification Steps */}
      {actions.length > 0 && (
        <div className="p-4 rounded-xl bg-blue-50/50 border border-blue-100 space-y-3 text-xs">
          <div className="flex items-center gap-2 font-bold text-blue-950 uppercase tracking-wide text-[11px]">
            <CheckCircle2 className="w-4 h-4 text-blue-600" />
            <span>Recommended SOC Action Checklist:</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {actions.map((act, i) => (
              <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-white border border-slate-200 text-slate-800">
                <span className="font-bold text-blue-600 shrink-0">0{i + 1}.</span>
                <span className="font-medium leading-relaxed">{act}</span>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
