import React from 'react';
import { Network, ShieldAlert, Globe, Server, Hash, Layers, CheckCircle2, ArrowRight } from 'lucide-react';

export default function AttributionGraphCard({ attributionAndGraph }) {
  if (!attributionAndGraph) return null;

  const { attributionClassification, graphCorrelation, earliestReliableSendingNode, originatingGeoLocation, evidentiaryChainOfCustody } = attributionAndGraph;
  const nodes = graphCorrelation?.nodes || [];
  const edges = graphCorrelation?.edges || [];

  const getNodeColor = (type) => {
    switch (type) {
      case 'MALICIOUS_IP':
      case 'LOOKALIKE_DOMAIN':
      case 'MALICIOUS_URL':
      case 'MALICIOUS_PAYLOAD':
      case 'SUSPICIOUS_REDIRECT':
        return 'bg-rose-50 border-rose-200 text-rose-800';
      case 'ORIGIN_IP':
        return 'bg-amber-50 border-amber-200 text-amber-800';
      case 'RELAY_MTA':
        return 'bg-blue-50 border-blue-200 text-blue-800';
      case 'SENDER_IDENTITY':
      case 'DOMAIN':
        return 'bg-indigo-50 border-indigo-200 text-indigo-800';
      default:
        return 'bg-slate-50 border-slate-200 text-slate-800';
    }
  };

  return (
    <div className="app-card p-6 space-y-6 bg-white border border-slate-200 shadow-xs">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-gradient-to-tr from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-500/20">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-900 tracking-tight">
                Graph Correlation & Sender Attribution
              </h3>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-100 text-cyan-800 border border-cyan-200">
                AICTE Key Component 4
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Graph-based relationship analysis across domains, IPs, mail hops, and campaign infrastructure
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold px-3 py-1 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
            Confidence: <strong className="text-blue-600">{attributionClassification?.confidenceScore}%</strong>
          </span>
        </div>
      </div>

      {/* Attribution Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-blue-600" />
            Infrastructure Profile
          </div>
          <div className="text-xs font-bold text-slate-900 leading-snug">
            {attributionClassification?.infrastructureType}
          </div>
          <div className="text-[11px] text-slate-500">
            Earliest Node: <span className="font-mono font-medium text-slate-700">{earliestReliableSendingNode}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-purple-50/70 border border-purple-100 space-y-1.5">
          <div className="text-[11px] font-bold text-purple-700 uppercase tracking-wider flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-purple-600" />
            Campaign Clustering
          </div>
          <div className="text-xs font-bold text-purple-950 font-mono leading-snug">
            {attributionClassification?.campaignCluster}
          </div>
          <div className="text-[11px] text-purple-700">
            Persona: <span className="font-medium text-purple-900">{attributionClassification?.probableActorType}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-emerald-50/70 border border-emerald-100 space-y-1.5">
          <div className="text-[11px] font-bold text-emerald-700 uppercase tracking-wider flex items-center gap-1.5">
            <Hash className="w-3.5 h-3.5 text-emerald-600" />
            Evidentiary Custody
          </div>
          <div className="text-xs font-bold text-emerald-950 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            {evidentiaryChainOfCustody?.status}
          </div>
          <div className="text-[11px] text-emerald-800 truncate font-mono" title={evidentiaryChainOfCustody?.evidenceHash}>
            SHA-256: {evidentiaryChainOfCustody?.evidenceHash ? `${evidentiaryChainOfCustody.evidenceHash.substring(0, 18)}...` : 'N/A'}
          </div>
        </div>

      </div>

      {/* Visual Graph Node Correlation Timeline */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
            <Network className="w-3.5 h-3.5 text-blue-600" />
            Correlated Graph Entities ({nodes.length} nodes, {edges.length} relationships)
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 text-slate-100 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            {nodes.map((node, i) => (
              <React.Fragment key={node.id}>
                <div 
                  className={`px-3 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition ${getNodeColor(node.type)}`}
                  title={`${node.type}: ${node.details}`}
                >
                  <span className="text-[10px] font-bold opacity-75 uppercase">{node.type.replace('_', ' ')}:</span>
                  <span className="font-semibold">{node.label}</span>
                </div>
                {i < nodes.length - 1 && (
                  <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>

          <div className="border-t border-slate-800 pt-3 text-[11px] text-slate-400 flex flex-wrap items-center justify-between gap-2">
            <span>
              Origin Geo: <strong className="text-slate-200">{originatingGeoLocation?.city}, {originatingGeoLocation?.country}</strong> ({originatingGeoLocation?.isp})
            </span>
            <span className="text-slate-400">
              Compliant with AICTE / Indian IT Act Digital Evidence Preservation
            </span>
          </div>
        </div>
      </div>

    </div>
  );
}
