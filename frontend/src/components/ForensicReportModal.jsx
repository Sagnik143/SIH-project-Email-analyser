import React from 'react';
import { X, Download, Printer, Shield, CheckCircle2, AlertTriangle, Terminal, Globe, Calendar, Hash } from 'lucide-react';

export default function ForensicReportModal({ dossier, isOpen, onClose }) {
  if (!isOpen || !dossier) return null;

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(dossier, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Dossier_${dossier.dossierId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const { dossierId, timestamp, integrity, envelope, originGeo, relay, authentication, aiThreatIntelligence, iocs } = dossier;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-slate-950 border border-slate-700 rounded-xl shadow-2xl p-6 md:p-8 my-8 text-slate-200">
        
        {/* Top Control Bar */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6 print:hidden">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold font-mono uppercase tracking-wider text-slate-100">
              Evidentiary Forensic Intelligence Dossier
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-300 transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-xs font-mono font-bold text-slate-950 transition"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Export PDF</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Report Document */}
        <div className="space-y-6 print:text-black">
          
          {/* Header & Integrity Stamp */}
          <div className="border-b border-slate-800 pb-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div>
                <h1 className="text-xl font-bold font-display tracking-wide text-white">
                  INCIDENT FORENSIC DOSSIER // {dossierId}
                </h1>
                <div className="text-xs text-slate-400 font-mono mt-1 flex items-center gap-2">
                  <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Generated At: {new Date(timestamp).toUTCString()}</span>
                </div>
              </div>

              <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-right">
                <span className="text-[10px] uppercase text-slate-400 block font-mono">Assessed Threat Level</span>
                <span className={`text-sm font-bold font-mono ${
                  aiThreatIntelligence?.threatLevel === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'
                }`}>
                  {aiThreatIntelligence?.threatLevel} // {aiThreatIntelligence?.threatClassification}
                </span>
              </div>
            </div>

            {/* Cryptographic Chain of Custody */}
            <div className="mt-4 p-3 rounded bg-slate-900/60 border border-slate-800 text-[11px] font-mono space-y-1">
              <div className="text-slate-400 flex items-center gap-1">
                <Hash className="w-3 h-3 text-cyan-400" />
                <span>EVIDENTIARY HASH FINGERPRINT (RFC RAW STREAM):</span>
              </div>
              <div className="text-slate-300 break-all select-all">
                SHA-256: <strong className="text-cyan-300">{integrity?.sha256}</strong>
              </div>
              <div className="text-slate-400 break-all">
                MD5: <span className="text-slate-300">{integrity?.md5}</span> | Size: {integrity?.rawBytes} bytes
              </div>
            </div>
          </div>

          {/* Envelope Summary */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3.5 rounded bg-slate-900/40 border border-slate-800 space-y-1.5">
              <div className="text-[11px] text-cyan-400 uppercase font-bold">Sender Identity Profile</div>
              <div>From Display: <strong className="text-slate-200">"{envelope?.from?.name || 'None'}"</strong></div>
              <div>From Address: <span className="text-slate-300">{envelope?.from?.address}</span></div>
              <div>Sender Domain: <span className="text-slate-300">{envelope?.from?.domain}</span></div>
              <div>Reply-To: <span className="text-slate-300">{envelope?.replyTo?.address || 'Aligned with From'}</span></div>
            </div>

            <div className="p-3.5 rounded bg-slate-900/40 border border-slate-800 space-y-1.5">
              <div className="text-[11px] text-cyan-400 uppercase font-bold">Network Origin & Relay</div>
              <div>Origin IP: <strong className="text-cyan-300">{originGeo?.ip}</strong></div>
              <div>Location: <span className="text-slate-200">{originGeo?.city}, {originGeo?.country}</span></div>
              <div>ISP / ASN: <span className="text-slate-300">{originGeo?.isp} ({originGeo?.asn})</span></div>
              <div>Total Hops: <span className="text-slate-200">{relay?.totalHops}</span> ({relay?.totalTransitTimeSeconds}s latency)</div>
            </div>
          </div>

          {/* Executive Summary & Hypothesis */}
          <div className="space-y-3">
            <div className="text-xs uppercase font-mono font-bold text-slate-300">
              AI Incident Assessment & Forensic Hypothesis
            </div>
            <div className="p-4 rounded bg-slate-900/50 border border-slate-800 text-xs leading-relaxed space-y-2">
              <p><strong>Executive Summary:</strong> {aiThreatIntelligence?.executiveSummary}</p>
              <p><strong>Forensic Hypothesis:</strong> {aiThreatIntelligence?.forensicHypothesis}</p>
              <p><strong>Attribution Persona:</strong> {aiThreatIntelligence?.threatActorPersona}</p>
            </div>
          </div>

          {/* Mitigation Actions */}
          <div className="space-y-2">
            <div className="text-xs uppercase font-mono font-bold text-cyan-400">
              Prescribed SOC Incident Response Playbook
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              {(aiThreatIntelligence?.recommendedActions || []).map((act, i) => (
                <div key={i} className="p-2 rounded bg-slate-900/40 border border-slate-800 text-slate-300 flex items-start gap-2 font-mono">
                  <span className="text-cyan-400 font-bold">0{i + 1}.</span>
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
