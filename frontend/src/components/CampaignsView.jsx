import React from 'react';
import { Network, GitFork, Info, ArrowRight, Shield } from 'lucide-react';
import RelatedIncidentsCard from './RelatedIncidentsCard';

export default function CampaignsView({
  activeCaseNumber,
  cases = [],
  onSelectCase
}) {
  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      
      <div>
        <h2 className="text-xl font-black text-slate-900 tracking-tight">
          Campaigns & Potentially Related Activity
        </h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Automated cross-case correlation based on shared observable indicators (URLs, attachment hashes, and Reply-To addresses).
        </p>
      </div>

      {/* Trust Boundary Limitation Notice */}
      <div className="p-3.5 rounded-xl bg-blue-50/70 border border-blue-200 text-blue-950 text-xs flex items-start gap-2.5 leading-relaxed">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <div>
          <strong>Correlation Boundary Notice:</strong> Correlation scores and relationships indicate shared technical infrastructure and observable indicators. They do <em>not</em> establish common authorship, attacker identity, or a single confirmed campaign.
        </div>
      </div>

      {/* Active Case Correlation Card */}
      {activeCaseNumber ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-800">
              Active Investigation Focus: <strong className="text-blue-700 font-mono">{activeCaseNumber}</strong>
            </span>
          </div>
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xs p-4">
            <RelatedIncidentsCard caseNumber={activeCaseNumber} />
          </div>
        </div>
      ) : (
        <div className="p-8 rounded-2xl bg-white border border-slate-200 text-center space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center mx-auto">
            <Network className="w-6 h-6" />
          </div>
          <div className="text-sm font-bold text-slate-800">
            Select a Case to Inspect Related Incidents
          </div>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Choose a case from your investigations repository below to discover potentially correlated emails and shared indicators.
          </p>
          
          <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
            {cases.slice(0, 4).map(c => (
              <button
                key={c.id}
                onClick={() => onSelectCase && onSelectCase(c)}
                className="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-blue-50 hover:text-blue-700 border border-slate-200 text-slate-700 text-xs font-semibold transition"
              >
                {c.caseNumber} &bull; {c.title?.slice(0, 25)}...
              </button>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
