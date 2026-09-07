import React from 'react';
import { ShieldAlert, Terminal, Layers, Info } from 'lucide-react';
import IoCVault from './IoCVault';
import AttributionGraphCard from './AttributionGraphCard';

export default function ThreatIntelView({ dossier }) {
  if (!dossier) {
    return (
      <div className="p-12 text-center bg-white border border-slate-200 rounded-2xl shadow-xs space-y-3">
        <div className="text-base font-bold text-slate-800">
          No Active Threat Telemetry Loaded
        </div>
        <p className="text-xs text-slate-500">
          Analyze an email or load a preloaded scenario to populate threat intelligence telemetry.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      
      <div>
        <h2 className="text-xl font-black text-slate-900 tracking-tight">
          Observable Threat Intelligence & Entity Telemetry
        </h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Extracted indicators of compromise (IoCs), observable infrastructure nodes, and behavioral tactics.
        </p>
      </div>

      <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-600 text-xs flex items-start gap-2.5 leading-relaxed">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <div>
          <strong>Intelligence Boundary:</strong> Observable IoCs represent extracted technical entities (domains, IPs, URLs, attachment hashes). Observed tactics represent investigative hypotheses rather than confirmed attribution.
        </div>
      </div>

      {/* IoC Vault */}
      <IoCVault iocs={dossier.iocs} />

      {/* Observed Tactics & Entity Graph */}
      <AttributionGraphCard attributionAndGraph={dossier.attributionAndGraph} />

    </div>
  );
}
