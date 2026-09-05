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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-white border border-slate-200 rounded-2xl shadow-2xl p-6 md:p-8 my-8 text-slate-800">
        
        {/* Top Control Bar */}
        <div className="flex items-center justify-between border-b border-slate-100 pb-4 mb-6 print:hidden">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-blue-600 text-white flex items-center justify-center">
              <Shield className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold text-slate-900">
              Evidentiary Forensic Intelligence Dossier
            </h2>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs font-semibold text-slate-700 transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold shadow-xs transition"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Export PDF</span>
            </button>

            <button
              onClick={onClose}
              className="p-2 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Report Document */}
        <div className="space-y-6">
          
          {/* Header & Integrity Stamp */}
          <div className="border-b border-slate-100 pb-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h1 className="text-2xl font-black tracking-tight text-slate-950">
                  INCIDENT FORENSIC REPORT
                </h1>
                <div className="text-xs text-slate-500 mt-1 flex items-center gap-2">
                  <Calendar className="w-3.5 h-3.5 text-blue-600" />
                  <span>Dossier ID: <strong>{dossierId}</strong> &bull; Generated: {new Date(timestamp).toUTCString()}</span>
                </div>
              </div>

              <div className="px-4 py-2 rounded-xl bg-slate-50 border border-slate-200 text-right">
                <span className="text-[10px] uppercase font-bold text-slate-500 block">Threat Classification</span>
                <span className={`text-sm font-extrabold ${
                  aiThreatIntelligence?.threatLevel === 'CRITICAL' ? 'text-rose-600' : 'text-amber-600'
                }`}>
                  {aiThreatIntelligence?.threatLevel} &bull; {aiThreatIntelligence?.threatClassification}
                </span>
              </div>
            </div>

            {/* Cryptographic Hash Verification */}
            <div className="mt-4 p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono space-y-1">
              <div className="text-slate-600 font-bold flex items-center gap-1.5">
                <Hash className="w-3.5 h-3.5 text-blue-600" />
                <span>CRYPTOGRAPHIC RAW EMAIL FINGERPRINT:</span>
              </div>
              <div className="text-slate-900 break-all select-all font-semibold">
                SHA-256: <span className="text-blue-700">{integrity?.sha256}</span>
              </div>
              <div className="text-slate-600 break-all">
                MD5: {integrity?.md5} | Size: {integrity?.rawBytes} bytes
              </div>
            </div>
          </div>

          {/* Envelope Summary */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <div className="text-xs text-blue-700 font-bold uppercase tracking-wide">Sender Identity Details</div>
              <div>From Display: <strong className="text-slate-900">"{envelope?.from?.name || 'None'}"</strong></div>
              <div>From Address: <span className="text-slate-700 font-mono">{envelope?.from?.address}</span></div>
              <div>Sender Domain: <span className="text-slate-700 font-mono">{envelope?.from?.domain}</span></div>
              <div>Reply-To: <span className="text-slate-700 font-mono">{envelope?.replyTo?.address || 'Same as sender'}</span></div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <div className="text-xs text-blue-700 font-bold uppercase tracking-wide">Server Origin & Relay</div>
              <div>Origin IP: <strong className="text-slate-900 font-mono">{originGeo?.ip}</strong></div>
              <div>Location: <span className="text-slate-800 font-medium">📍 {originGeo?.city}, {originGeo?.country}</span></div>
              <div>ISP / ASN: <span className="text-slate-700">{originGeo?.isp} ({originGeo?.asn})</span></div>
              <div>Total Relay Hops: <span className="text-slate-900 font-semibold">{relay?.totalHops}</span> ({relay?.totalTransitTimeSeconds}s transit)</div>
            </div>
          </div>

          {/* Executive Summary & Hypothesis */}
          <div className="space-y-2.5">
            <div className="text-xs uppercase font-bold text-slate-700">
              AI Incident Assessment & Forensic Hypothesis
            </div>
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs leading-relaxed space-y-2 text-slate-700">
              <p><strong>Executive Summary:</strong> {aiThreatIntelligence?.executiveSummary}</p>
              <p><strong>Forensic Hypothesis:</strong> {aiThreatIntelligence?.forensicHypothesis}</p>
              <p><strong>Attribution Persona:</strong> {aiThreatIntelligence?.threatActorPersona}</p>
            </div>
          </div>

          {/* Mitigation Actions */}
          <div className="space-y-2.5">
            <div className="text-xs uppercase font-bold text-blue-700">
              Recommended Security Actions
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              {(aiThreatIntelligence?.recommendedActions || []).map((act, i) => (
                <div key={i} className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-800 flex items-start gap-2.5">
                  <span className="font-bold text-blue-600">0{i + 1}.</span>
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
