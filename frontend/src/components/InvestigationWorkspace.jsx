import React, { useState } from 'react';
import { 
  Shield, 
  Activity, 
  Globe, 
  Key, 
  Terminal, 
  Network, 
  Brain, 
  FileText, 
  Download, 
  Printer, 
  CheckCircle2, 
  AlertTriangle,
  FolderPlus,
  Loader2,
  Calendar,
  Hash
} from 'lucide-react';
import ThreatScoreCard from './ThreatScoreCard';
import AuthMatrix from './AuthMatrix';
import GeoRelayMap from './GeoRelayMap';
import RelayTimeline from './RelayTimeline';
import IoCVault from './IoCVault';
import HeaderInspector from './HeaderInspector';
import AttributionGraphCard from './AttributionGraphCard';
import AIIntelligenceCard from './AIIntelligenceCard';
import RelatedIncidentsCard from './RelatedIncidentsCard';

export default function InvestigationWorkspace({
  dossier,
  caseInfo,
  onOpenReportModal,
  onSelectEvidence,
  onSaveToCase,
  isSavingCase,
  savedCaseNumber
}) {
  const [activeTab, setActiveTab] = useState('overview');

  if (!dossier) {
    return (
      <div className="p-12 text-center bg-white border border-slate-200 rounded-2xl shadow-xs space-y-3">
        <div className="text-base font-bold text-slate-800">
          No Active Investigation In Memory
        </div>
        <p className="text-xs text-slate-500">
          Please select an investigation from the dashboard or analyze a new email.
        </p>
      </div>
    );
  }

  const { envelope, findings = [], evidence = [], integrity, originGeo, relay, authentication, aiThreatIntelligence, iocs } = dossier;
  const activeCaseNum = savedCaseNumber || caseInfo?.caseNumber || dossier.caseNumber || 'SESSION';
  const rawSha = integrity?.sha256 || dossier.hashes?.sha256 || 'N/A';

  const tabs = [
    { id: 'overview', label: 'Overview & Risk', icon: Activity, count: null },
    { id: 'evidence', label: 'Authoritative Evidence', icon: Shield, count: evidence.length },
    { id: 'findings', label: 'Deterministic Findings', icon: AlertTriangle, count: findings.length },
    { id: 'routing', label: 'Relay & Routing', icon: Globe, count: relay?.totalHops || null },
    { id: 'auth', label: 'Authentication', icon: Key, count: null },
    { id: 'indicators', label: 'Indicators & Headers', icon: Terminal, count: iocs?.length || null },
    { id: 'related', label: 'Related Activity', icon: Network, count: null },
    { id: 'ai', label: 'AI Advisory', icon: Brain, count: null },
    { id: 'report', label: 'Report & Seals', icon: FileText, count: null }
  ];

  return (
    <div className="space-y-5">
      
      {/* Investigation Meta Banner */}
      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-2xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold px-2.5 py-0.5 rounded-lg bg-blue-50 text-blue-800 border border-blue-200">
              {activeCaseNum}
            </span>
            <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 uppercase tracking-wide">
              DFIR Investigation Workspace
            </span>
            {savedCaseNumber && (
              <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                <span>Persisted in SQLite</span>
              </span>
            )}
          </div>

          <h2 className="text-lg font-bold text-slate-900 tracking-tight">
            {envelope?.subject || 'Forensic Email Examination'}
          </h2>

          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 font-mono">
            <span>From: <strong className="text-slate-800 font-sans">{envelope?.from?.address || 'Unknown'}</strong></span>
            <span>&bull;</span>
            <span className="truncate max-w-xs" title={rawSha}>Acquisition SHA-256: {rawSha.slice(0, 16)}...</span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {!savedCaseNumber && onSaveToCase && (
            <button
              onClick={onSaveToCase}
              disabled={isSavingCase}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-semibold text-blue-800 transition disabled:opacity-50"
            >
              {isSavingCase ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FolderPlus className="w-3.5 h-3.5 text-blue-600" />}
              <span>Save to Case</span>
            </button>
          )}

          <button
            onClick={onOpenReportModal}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-bold text-xs shadow-xs transition"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Open Complete Dossier</span>
          </button>
        </div>
      </div>

      {/* Investigation Sub-Navigation Tabs */}
      <div className="border-b border-slate-200 flex items-center gap-1 overflow-x-auto select-none bg-white p-1 rounded-xl shadow-2xs">
        {tabs.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition shrink-0 ${
                isActive
                  ? 'bg-blue-50 text-blue-700 border border-blue-200 shadow-2xs'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-600' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
              {tab.count !== null && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                  isActive ? 'bg-blue-200 text-blue-900' : 'bg-slate-100 text-slate-600'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Active Workspace View Content */}
      <div className="space-y-6">

        {/* Tab 1: Overview & Risk */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <ThreatScoreCard dossier={dossier} onSelectEvidence={onSelectEvidence} />
            <AttributionGraphCard attributionAndGraph={dossier.attributionAndGraph} />
          </div>
        )}

        {/* Tab 2: Evidence */}
        {activeTab === 'evidence' && (
          <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                  Authoritative Evidence Ledger ({evidence.length} items)
                </h3>
                <p className="text-xs text-slate-500">
                  Directly extracted technical artifacts from original RFC 5322 payload.
                </p>
              </div>
              <span className="text-xs font-semibold text-blue-700">
                Click any E-xxx to inspect raw evidence
              </span>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 text-slate-600 text-[10px] uppercase font-bold border-b border-slate-200">
                    <th className="p-3 pl-4">Evidence ID</th>
                    <th className="p-3">Source</th>
                    <th className="p-3">Field</th>
                    <th className="p-3">Observed Value</th>
                    <th className="p-3 pr-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  {evidence.map(ev => (
                    <tr key={ev.id} className="hover:bg-blue-50/40 transition">
                      <td className="p-3 pl-4 font-bold text-blue-700">
                        <button
                          onClick={() => onSelectEvidence && onSelectEvidence(ev.id)}
                          className="px-2.5 py-0.5 rounded-lg bg-blue-100 text-blue-900 hover:bg-blue-200 transition font-bold"
                        >
                          {ev.id}
                        </button>
                      </td>
                      <td className="p-3 text-slate-600 font-sans text-xs">{ev.source}</td>
                      <td className="p-3 text-slate-900 font-semibold">{ev.field}</td>
                      <td className="p-3 text-slate-700 max-w-sm truncate" title={ev.value}>{ev.value}</td>
                      <td className="p-3 pr-4 text-right font-sans">
                        <button
                          onClick={() => onSelectEvidence && onSelectEvidence(ev.id)}
                          className="text-blue-600 hover:text-blue-800 text-xs font-bold underline"
                        >
                          Inspect Record
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 3: Findings */}
        {activeTab === 'findings' && (
          <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-4">
            <div className="border-b border-slate-100 pb-3">
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Deterministic Forensic Findings ({findings.length} findings)
              </h3>
              <p className="text-xs text-slate-500">
                Generated strictly by deterministic forensic rules and backed by evidence records.
              </p>
            </div>

            <div className="space-y-3.5">
              {findings.map(finding => {
                let sevBadge = 'bg-slate-100 text-slate-700 border-slate-200';
                if (finding.severity === 'critical') sevBadge = 'bg-rose-100 text-rose-800 border-rose-200';
                else if (finding.severity === 'high') sevBadge = 'bg-orange-100 text-orange-800 border-orange-200';
                else if (finding.severity === 'medium') sevBadge = 'bg-amber-100 text-amber-800 border-amber-200';
                else if (finding.severity === 'low') sevBadge = 'bg-emerald-100 text-emerald-800 border-emerald-200';

                return (
                  <div key={finding.id} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/60 pb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-blue-700 bg-blue-100/70 border border-blue-200 px-2 py-0.5 rounded text-[11px]">
                          {finding.id}
                        </span>
                        <span className="font-bold text-slate-900 text-sm">
                          {finding.title}
                        </span>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded-full font-bold uppercase text-[10px] border ${sevBadge}`}>
                        {finding.severity}
                      </span>
                    </div>

                    <p className="text-slate-700 leading-relaxed">
                      {finding.summary}
                    </p>

                    {/* Supporting Evidence IDs */}
                    <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1.5">
                      <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                        Supporting Evidence IDs:
                      </span>
                      <div className="flex flex-wrap items-center gap-1.5">
                        {(finding.evidenceIds || []).map(evId => (
                          <button
                            key={evId}
                            onClick={() => onSelectEvidence && onSelectEvidence(evId)}
                            className="px-2.5 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 hover:bg-blue-100 transition font-mono font-bold text-xs"
                            title="Click to view raw evidence in Inspector"
                          >
                            {evId}
                          </button>
                        ))}
                      </div>
                    </div>

                    {finding.limitations && finding.limitations.length > 0 && (
                      <div className="space-y-0.5">
                        <span className="text-[10px] uppercase font-bold text-slate-500 block">Forensic Limitations:</span>
                        <ul className="list-disc list-inside text-slate-600 text-[11px] space-y-0.5">
                          {finding.limitations.map((lim, lIdx) => (
                            <li key={lIdx}>{lim}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {finding.recommendedAction && (
                      <div className="p-2.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-[11px] flex items-start gap-1.5">
                        <strong className="text-blue-800 shrink-0">Recommended Action:</strong>
                        <span>{finding.recommendedAction}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Tab 4: Relay & Routing */}
        {activeTab === 'routing' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7">
              <GeoRelayMap relay={dossier.relay} originGeo={dossier.originGeo} />
            </div>
            <div className="lg:col-span-5">
              <RelayTimeline relay={dossier.relay} />
            </div>
          </div>
        )}

        {/* Tab 5: Authentication */}
        {activeTab === 'auth' && (
          <AuthMatrix 
            authentication={dossier.authentication} 
            envelope={dossier.envelope} 
            onSelectEvidence={onSelectEvidence}
          />
        )}

        {/* Tab 6: Indicators & Technical Headers */}
        {activeTab === 'indicators' && (
          <div className="space-y-6">
            <IoCVault iocs={dossier.iocs} />
            <HeaderInspector headerLines={dossier.headerLines} rawHeaders={dossier.rawHeaders} />
          </div>
        )}

        {/* Tab 7: Related Activity */}
        {activeTab === 'related' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs">
              <RelatedIncidentsCard caseNumber={activeCaseNum} />
            </div>
          </div>
        )}

        {/* Tab 8: AI Advisory */}
        {activeTab === 'ai' && (
          <AIIntelligenceCard aiThreatIntelligence={dossier.aiThreatIntelligence} />
        )}

        {/* Tab 9: Report & Integrity Seals */}
        {activeTab === 'report' && (
          <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-2xs space-y-5 text-xs">
            <div className="border-b border-slate-100 pb-3">
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Forensic Dossier & Tamper-Evident Integrity Seals
              </h3>
              <p className="text-xs text-slate-500">
                Export canonical forensic reports and verify local cryptographic integrity.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <span className="text-[10px] font-bold uppercase text-slate-400 block">
                  Original Email SHA-256 (Acquisition)
                </span>
                <span className="font-mono text-xs font-bold text-slate-900 break-all block">
                  {rawSha}
                </span>
                <span className="text-[11px] text-slate-500 block">
                  Calculated from original acquired RFC 5322 byte payload.
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <span className="text-[10px] font-bold uppercase text-slate-400 block">
                  Dossier Integrity Seal (SHA-256)
                </span>
                <span className="font-mono text-xs font-bold text-blue-700 break-all block">
                  {dossier.integrity?.dossierDigest || rawSha}
                </span>
                <span className="text-[11px] text-slate-500 block">
                  Deterministic seal calculated over canonical investigation findings.
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={onOpenReportModal}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-xs transition"
              >
                Open Full Interactive Dossier
              </button>
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
