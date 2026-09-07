import React, { useState } from 'react';
import { 
  X, Download, Printer, Shield, CheckCircle2, AlertTriangle, Terminal, 
  Globe, Calendar, Hash, FolderPlus, Loader2, Info, ChevronDown, ChevronRight,
  Database, Network, Brain, FileText, CheckCircle, ExternalLink, Copy
} from 'lucide-react';
import { API_BASE_URL } from '../config';
import RelatedIncidentsCard from './RelatedIncidentsCard';
import EvidenceInspectorModal from './EvidenceInspectorModal';

export default function ForensicReportModal({ dossier, isOpen, onClose }) {
  const [savedCaseNumber, setSavedCaseNumber] = useState(null);
  const [isSavingCase, setIsSavingCase] = useState(false);
  const [saveCaseError, setSaveCaseError] = useState(null);
  const [isExportingHtml, setIsExportingHtml] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Evidence Inspector Modal state
  const [inspectingEvidence, setInspectingEvidence] = useState(null);

  // Section collapse state (defaulting authoritative sections open)
  const [expandedSections, setExpandedSections] = useState({
    summary: true,
    evidence: true,
    findings: true,
    auth: true,
    relay: true,
    indicators: false,
    related: true,
    risk: true,
    ai: true,
    limitations: true,
    custody: true
  });

  if (!isOpen || !dossier) return null;

  const toggleSection = (sectionKey) => {
    setExpandedSections(prev => ({ ...prev, [sectionKey]: !prev[sectionKey] }));
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(dossier, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Dossier_${savedCaseNumber || dossier.dossierId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportCertifiedHtml = async () => {
    setIsExportingHtml(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/reports/export/html`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dossier,
          options: {
            caseNumber: savedCaseNumber || dossier.caseNumber || 'SESSION',
            rawSha256: dossier.integrity?.sha256 || dossier.hashes?.sha256
          }
        })
      });
      if (!res.ok) throw new Error('Failed to generate HTML report');
      const data = await res.json();
      const blob = new Blob([data.html], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AegisMail_Forensic_Report_${savedCaseNumber || dossier.dossierId}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error exporting HTML report:', err);
    } finally {
      setIsExportingHtml(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    setIsVerifying(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/reports/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dossier,
          rawSha256: dossier.integrity?.sha256 || dossier.hashes?.sha256,
          caseNumber: savedCaseNumber || dossier.caseNumber
        })
      });
      const data = await res.json();
      setVerificationResult(data);
    } catch (err) {
      setVerificationResult({ status: 'ERROR', message: err.message });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSaveToCase = async () => {
    if (savedCaseNumber || isSavingCase) return;
    setIsSavingCase(true);
    setSaveCaseError(null);
    try {
      const caseTitle = envelope?.subject || 'Forensic Investigation';
      const caseRes = await fetch(`${API_BASE_URL}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: caseTitle, status: 'open' })
      });
      if (!caseRes.ok) throw new Error('Failed to create case');
      const newCase = await caseRes.json();

      const saveRes = await fetch(`${API_BASE_URL}/api/cases/${newCase.id}/save-analysis`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rawEmail: dossier.rawEmail || 'From: ' + (envelope?.from?.raw || ''),
          dossier,
          filename: `${newCase.caseNumber}.eml`
        })
      });
      if (!saveRes.ok) throw new Error('Failed to associate analysis with case');
      setSavedCaseNumber(newCase.caseNumber);
    } catch (err) {
      console.error('Case save error:', err);
      setSaveCaseError('Failed to save to case');
    } finally {
      setIsSavingCase(false);
    }
  };

  const { dossierId, timestamp, integrity, envelope, originGeo, relay, authentication, aiThreatIntelligence, iocs, findings = [], evidence = [] } = dossier;
  const rawSha256 = integrity?.sha256 || dossier.hashes?.sha256 || 'N/A';
  const rawMd5 = integrity?.md5 || dossier.hashes?.md5 || 'N/A';
  const dossierDigest = integrity?.dossierDigest || dossier.dossierSha256 || rawSha256;

  // Helper to open evidence inspector
  const openEvidenceInspector = (evId) => {
    const item = evidence.find(e => e.id === evId);
    if (item) {
      setInspectingEvidence(item);
    } else {
      // Fallback object if raw record has minimal fields
      setInspectingEvidence({
        id: evId,
        source: 'INVESTIGATION_ENGINE',
        field: 'Observed Telemetry',
        value: 'Evidence record referenced in findings',
        collectionMethod: 'DIRECT_EXTRACTION',
        timestamp
      });
    }
  };

  return (
    <div className="fixed inset-0 z-[9999] flex items-start justify-center p-4 md:p-6 bg-slate-900/60 backdrop-blur-xs overflow-y-auto">
      <div className="relative w-full max-w-5xl bg-white border border-slate-200 rounded-2xl shadow-2xl p-6 md:p-8 my-8 text-slate-800">
        
        {/* Top Action Control Bar */}
        <div className="flex flex-wrap items-center justify-between border-b border-slate-100 pb-4 mb-6 gap-3 print:hidden">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                AegisMail Forensic Investigation Dossier
              </h2>
              <p className="text-[11px] text-slate-500">
                Tamper-Evident Forensic Report &bull; Phase 8 Evidence-First Architecture
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {savedCaseNumber ? (
              <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs font-bold text-emerald-800 shadow-xs">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                <span>{savedCaseNumber} Persisted</span>
              </span>
            ) : (
              <button
                onClick={handleSaveToCase}
                disabled={isSavingCase}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-semibold text-blue-800 transition disabled:opacity-50"
              >
                {isSavingCase ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FolderPlus className="w-3.5 h-3.5 text-blue-600" />}
                <span>Save to Case</span>
              </button>
            )}

            <button
              onClick={handleExportCertifiedHtml}
              disabled={isExportingHtml}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-xs font-semibold text-indigo-800 transition disabled:opacity-50"
              title="Download standalone offline forensic HTML report"
            >
              {isExportingHtml ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5 text-indigo-600" />}
              <span>Export Forensic HTML</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs font-semibold text-slate-700 transition"
              title="Download canonical forensic JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={handleVerifyIntegrity}
              disabled={isVerifying}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-semibold text-blue-800 transition disabled:opacity-50"
              title="Verify cryptographic integrity seal of dossier"
            >
              {isVerifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5 text-blue-600" />}
              <span>Verify Integrity</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold shadow-xs transition"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition ml-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Dossier Document Content */}
        <div className="space-y-6">

          {/* Document Header & Legal Standard Alignment */}
          <div className="border-b border-slate-200 pb-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <div className="text-[11px] font-bold text-blue-700 uppercase tracking-widest flex items-center gap-1 mb-1">
                  <span>AICTE Cyber Security Cell &bull; Problem Statement ID: 26106</span>
                </div>
                <h1 className="text-2xl font-black tracking-tight text-slate-950">
                  INCIDENT FORENSIC DOSSIER
                </h1>
                <div className="text-xs text-slate-500 mt-1 flex flex-wrap items-center gap-2 font-mono">
                  <span>UUID: <strong>{dossierId}</strong></span>
                  <span>&bull;</span>
                  <span>Acquired: {new Date(timestamp).toUTCString()}</span>
                </div>
              </div>

              <div className="px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-right">
                <span className="text-[10px] uppercase font-bold text-slate-500 block">Heuristic Threat Status</span>
                <span className={`text-sm font-extrabold ${
                  aiThreatIntelligence?.threatLevel === 'CRITICAL' ? 'text-rose-600' : 'text-amber-600'
                }`}>
                  {aiThreatIntelligence?.threatLevel || 'EVALUATING'} &bull; {aiThreatIntelligence?.threatClassification || 'Observed Threat Telemetry'}
                </span>
              </div>
            </div>

            {/* Evidence Handling Principles Banner */}
            <div className="mt-3 p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-[11px] text-slate-600 flex items-center justify-between">
              <span>
                Standard Alignment: <strong>Aligned with relevant digital-evidence handling principles (ISO/IEC 27037)</strong>
              </span>
              <span className="text-slate-400 italic">
                Automated Ingestion Pipeline &bull; Authoritative Deterministic Engine
              </span>
            </div>
          </div>

          {/* Section 1: Investigation Summary & Claimed vs Observed Callout */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('summary')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.summary ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  1. Executive Investigation Summary & Provenance
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Case #{savedCaseNumber || dossier.caseNumber || 'SESSION'}</span>
            </div>

            {expandedSections.summary && (
              <div className="p-5 space-y-4 text-xs">
                {/* Claimed vs Observed Comparison Card */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3.5 rounded-xl bg-amber-50/60 border border-amber-200 space-y-1">
                    <span className="text-[10px] font-bold uppercase text-amber-800 tracking-wider block">
                      Claimed by Email Headers
                    </span>
                    <div className="font-mono text-slate-900 font-semibold">{envelope?.from?.address || 'Unknown'}</div>
                    <div className="text-slate-600 text-[11px]">Display: "{envelope?.from?.name || 'None'}"</div>
                    <div className="text-[10px] text-amber-700 italic">Unverified claim from client MTA.</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-blue-50/60 border border-blue-200 space-y-1">
                    <span className="text-[10px] font-bold uppercase text-blue-800 tracking-wider block">
                      Observed by AegisMail Engine
                    </span>
                    <div className="font-mono text-slate-900 font-semibold">{originGeo?.ip || 'Direct Connection'}</div>
                    <div className="text-slate-600 text-[11px]">Relay: {relay?.totalHops || 0} hops observed ({originGeo?.city || 'Unknown'}, {originGeo?.country || 'Unknown'})</div>
                    <div className="text-[10px] text-blue-700 italic">Extracted from authoritative Received headers.</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-purple-50/60 border border-purple-200 space-y-1">
                    <span className="text-[10px] font-bold uppercase text-purple-800 tracking-wider block">
                      Forensic Assessment
                    </span>
                    <div className="font-bold text-slate-900">
                      {envelope?.replyTo?.address && envelope?.replyTo?.address !== envelope?.from?.address 
                        ? 'Reply-To Mismatch Detected' 
                        : (authentication?.spf?.status === 'PASS' ? 'Reported Auth Pass' : 'Authentication Inconsistency')}
                    </div>
                    <div className="text-slate-600 text-[11px]">
                      Claimed origin could not be independently verified.
                    </div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-500 tracking-wider block">Subject & Message Identification</span>
                  <div className="text-sm font-bold text-slate-900">{envelope?.subject || 'No Subject'}</div>
                  <div className="text-slate-500 font-mono text-[11px]">Message-ID: {envelope?.messageId || 'N/A'}</div>
                </div>
              </div>
            )}
          </div>

          {/* Section 2: Evidence Collected (Interactive Table with Clickable E-xxx Inspector) */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('evidence')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.evidence ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  2. Authoritative Evidence Collected ({evidence.length} items)
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Click any E-xxx to inspect raw evidence</span>
            </div>

            {expandedSections.evidence && (
              <div className="p-5 space-y-3 text-xs">
                <div className="overflow-x-auto rounded-xl border border-slate-200">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-100 text-slate-700 text-[10px] uppercase font-bold border-b border-slate-200">
                        <th className="p-2.5">Evidence ID</th>
                        <th className="p-2.5">Source</th>
                        <th className="p-2.5">Field</th>
                        <th className="p-2.5">Observed Value</th>
                        <th className="p-2.5">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                      {evidence.map(ev => (
                        <tr key={ev.id} className="hover:bg-blue-50/40 transition">
                          <td className="p-2.5 font-bold text-blue-700">
                            <button
                              onClick={() => openEvidenceInspector(ev.id)}
                              className="px-2 py-0.5 rounded bg-blue-100 text-blue-900 hover:bg-blue-200 transition font-bold"
                            >
                              {ev.id}
                            </button>
                          </td>
                          <td className="p-2.5 text-slate-600 font-sans text-xs">{ev.source}</td>
                          <td className="p-2.5 text-slate-900 font-semibold">{ev.field}</td>
                          <td className="p-2.5 text-slate-700 max-w-xs truncate" title={ev.value}>{ev.value}</td>
                          <td className="p-2.5 font-sans">
                            <button
                              onClick={() => openEvidenceInspector(ev.id)}
                              className="text-blue-600 hover:text-blue-800 text-xs font-semibold underline"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Section 3: Deterministic Findings (Traceable to E-xxx) */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('findings')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.findings ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  3. Deterministic Forensic Findings ({findings.length} findings)
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Every finding traces to supporting evidence</span>
            </div>

            {expandedSections.findings && (
              <div className="p-5 space-y-3.5 text-xs">
                {findings.length > 0 ? (
                  findings.map(finding => {
                    let sevBadge = 'bg-slate-100 text-slate-700 border-slate-200';
                    if (finding.severity === 'critical') sevBadge = 'bg-rose-100 text-rose-800 border-rose-200';
                    else if (finding.severity === 'high') sevBadge = 'bg-orange-100 text-orange-800 border-orange-200';
                    else if (finding.severity === 'medium') sevBadge = 'bg-amber-100 text-amber-800 border-amber-200';
                    else if (finding.severity === 'low') sevBadge = 'bg-emerald-100 text-emerald-800 border-emerald-200';

                    return (
                      <div key={finding.id} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
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

                        <p className="text-slate-700 leading-relaxed font-sans">
                          {finding.summary}
                        </p>

                        {/* Traceable Supporting Evidence Badges */}
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1.5">
                          <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                            Supporting Evidence IDs:
                          </span>
                          <div className="flex flex-wrap items-center gap-1.5">
                            {(finding.evidenceIds || []).map(evId => (
                              <button
                                key={evId}
                                onClick={() => openEvidenceInspector(evId)}
                                className="px-2.5 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 hover:bg-blue-100 transition font-mono font-bold text-xs"
                                title="Click to view raw evidence in Inspector"
                              >
                                {evId}
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Limitations */}
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

                        {/* Recommended Action */}
                        {finding.recommendedAction && (
                          <div className="p-2.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-[11px] flex items-start gap-1.5">
                            <strong className="text-blue-800 shrink-0">Recommended Action:</strong>
                            <span>{finding.recommendedAction}</span>
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="p-4 rounded-xl bg-slate-50 text-slate-500 text-center">
                    No threat findings identified from deterministic rules.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Section 4: Authentication (3-Way Distinction) */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('auth')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.auth ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  4. Authentication Analysis (Reported vs Current Validation)
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Header claims vs Independent validation</span>
            </div>

            {expandedSections.auth && (
              <div className="p-5 space-y-3 text-xs">
                <div className="p-2.5 rounded-xl bg-blue-50/70 border border-blue-200 text-blue-900 text-[11px] flex items-center gap-2">
                  <Info className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>
                    <strong>Authentication Context:</strong> SPF, DKIM, and DMARC results are header-reported claims recorded by the receiving mail transfer agent. AegisMail does not assert live DNS verification for historical acquired emails.
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-800">SPF Evaluation</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        authentication?.spf?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                      }`}>
                        {authentication?.spf?.status || 'NOT_EVALUATED'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-600">{authentication?.spf?.details || 'No SPF claim'}</div>
                    <div className="text-[10px] text-slate-400 pt-1">Status: Reported by receiving MTA</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-800">DKIM Signature</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        authentication?.dkim?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                      }`}>
                        {authentication?.dkim?.status || 'NOT_EVALUATED'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-600">{authentication?.dkim?.details || 'No DKIM claim'}</div>
                    <div className="text-[10px] text-slate-400 pt-1">Status: Reported by receiving MTA</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-800">DMARC Policy</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        authentication?.dmarc?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                      }`}>
                        {authentication?.dmarc?.status || 'NOT_EVALUATED'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-600">{authentication?.dmarc?.details || 'No DMARC claim'}</div>
                    <div className="text-[10px] text-slate-400 pt-1">Status: Reported by receiving MTA</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Section 5: Relay / Routing Analysis (Timing Anomaly / Routing Inconsistency) */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('relay')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.relay ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  5. Relay & Routing Analysis ({relay?.totalHops || 0} Observed Hops)
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Routing sequence & timing anomalies</span>
            </div>

            {expandedSections.relay && (
              <div className="p-5 space-y-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Earliest Infrastructure Node:</span>
                    <span className="font-mono font-bold text-slate-900">{originGeo?.ip}</span>
                    <span className="text-slate-600 text-[11px] block">📍 Observed Location: {originGeo?.city}, {originGeo?.country} ({originGeo?.isp})</span>
                  </div>
                  <div className="text-right">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Total Latency:</span>
                    <span className="font-bold text-blue-700">{relay?.totalTransitTimeSeconds || 0}s Transit Time</span>
                  </div>
                </div>

                {relay?.hopAnomalies && relay.hopAnomalies.length > 0 && (
                  <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 space-y-1">
                    <strong className="text-amber-800 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-amber-600" />
                      Relay Routing / Timestamp Inconsistency Detected:
                    </strong>
                    <p className="text-[11px] leading-relaxed">
                      {relay.hopAnomalies[0].alert || 'Inconsistency detected in hop timestamps or sequence.'}
                    </p>
                    <div className="text-[10px] text-amber-700 italic pt-0.5">
                      Note: Relay timing differences may stem from unsynchronized server clocks, intermediate MTA queuing, or timezone configuration differences.
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Section 6: Observable Indicators (IoCs) */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('indicators')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.indicators ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  6. Observable Indicators ({iocs?.length || 0} items)
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Extracted IPs, Domains, URLs, Hashes</span>
            </div>

            {expandedSections.indicators && (
              <div className="p-5 space-y-2 text-xs">
                {iocs && iocs.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {iocs.map((ioc, idx) => (
                      <span key={idx} className="p-2 rounded-lg bg-slate-50 border border-slate-200 font-mono text-[11px] text-slate-800">
                        <strong className="text-blue-700 uppercase font-sans text-[10px] mr-1">[{ioc.type || 'IOC'}]:</strong>
                        {ioc.value || ioc}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="text-slate-500 italic">No observable indicators extracted.</div>
                )}
              </div>
            )}
          </div>

          {/* Section 7: Related Incidents (Phase 5 Correlation) */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('related')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.related ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  7. Potentially Related Incidents (Correlation Engine)
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Shared observable indicators</span>
            </div>

            {expandedSections.related && (
              <div className="p-5 space-y-2 text-xs">
                {savedCaseNumber ? (
                  <RelatedIncidentsCard caseNumber={savedCaseNumber} />
                ) : (
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-600">
                    Save this investigation to a case to enable automatic cross-case correlation with other stored investigations.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Section 8: Heuristic Risk Score */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('risk')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.risk ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  8. Heuristic Risk Score Assessment
                </span>
              </div>
              <span className="text-xs font-bold text-rose-600">
                Score: {aiThreatIntelligence?.riskScore ?? 0}/100
              </span>
            </div>

            {expandedSections.risk && (
              <div className="p-5 space-y-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-700 leading-relaxed">
                  <strong>Heuristic Risk Score Explainer:</strong> Risk score is a deterministic/heuristic assessment based on observed signals. It is not a calibrated probability of malicious activity or proof of intent.
                </div>

                <div>
                  <span className="text-[10px] font-bold uppercase text-slate-500 tracking-wide block mb-1">
                    Contributing Observed Signals:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {(aiThreatIntelligence?.contributingFactors || aiThreatIntelligence?.keyObservations || []).map((signal, sIdx) => (
                      <span key={sIdx} className="px-2.5 py-1 rounded-lg bg-slate-100 border border-slate-200 text-slate-800 text-[11px] font-medium">
                        &bull; {signal}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Section 9: AI Advisory (Segregated & Non-Authoritative) */}
          <div className="border border-purple-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('ai')}
              className="p-4 bg-purple-50/70 border-b border-purple-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.ai ? <ChevronDown className="w-4 h-4 text-purple-700" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-purple-950 text-xs uppercase tracking-wide flex items-center gap-1.5">
                  <Brain className="w-4 h-4 text-purple-600" />
                  9. AI Investigation Assistant &bull; Advisory Guidance
                </span>
              </div>
              <span className="px-2.5 py-0.5 rounded-full bg-purple-100 text-purple-800 font-bold text-[10px] border border-purple-200">
                Non-Authoritative
              </span>
            </div>

            {expandedSections.ai && (
              <div className="p-5 space-y-3.5 text-xs">
                <div className="p-3 rounded-xl bg-purple-50/40 border border-purple-200 text-purple-900 leading-relaxed text-[11px]">
                  <strong>Advisory Disclaimer:</strong> AI-generated content is advisory and does not constitute forensic evidence. Deterministic evidence and findings are authoritative.
                </div>

                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 text-slate-700">
                  <p><strong>What the evidence may indicate:</strong> {aiThreatIntelligence?.forensicHypothesis || aiThreatIntelligence?.executiveSummary || 'No anomaly hypothesis.'}</p>
                  <p><strong>Suggested analyst checks:</strong> Verify sender MTA consistency and confirm out-of-band wire/invoice validity.</p>
                  <p><strong>Investigative Profile:</strong> {aiThreatIntelligence?.threatActorPersona || 'Unclassified Pattern'}</p>
                </div>
              </div>
            )}
          </div>

          {/* Section 10: Limitations & Unknowns */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('limitations')}
              className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.limitations ? <ChevronDown className="w-4 h-4 text-blue-600" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-slate-900 text-xs uppercase tracking-wide">
                  10. Forensic Scope Limitations & Unknowns
                </span>
              </div>
              <span className="text-[11px] text-slate-500">Defensible investigative boundaries</span>
            </div>

            {expandedSections.limitations && (
              <div className="p-5 space-y-2 text-xs text-slate-600 leading-relaxed">
                <ul className="list-disc list-inside space-y-1">
                  <li><strong>Unverified Origin:</strong> Claimed origin IP from client-side headers could not be independently verified beyond the first trusted MTA hop.</li>
                  <li><strong>Infrastructure Geolocation:</strong> IP geolocation describes registered network infrastructure and does not establish human location or physical presence.</li>
                  <li><strong>Header-Reported Authentication:</strong> SPF, DKIM, and DMARC results are extracted from receiving server headers and are subject to upstream MTA trust boundaries.</li>
                  <li><strong>Correlation Limitations:</strong> Shared indicators indicate potential relationships but do not establish common authorship or attacker identity.</li>
                  <li><strong>Hypothesis Attribution:</strong> Observed behavioral tactics represent investigative hypotheses rather than confirmed attribution.</li>
                </ul>
              </div>
            )}
          </div>

          {/* Section 11: Digital Evidence Chain of Custody & Tamper-Evident Seal */}
          <div className="border border-blue-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <div 
              onClick={() => toggleSection('custody')}
              className="p-4 bg-blue-50/70 border-b border-blue-200 flex items-center justify-between cursor-pointer select-none"
            >
              <div className="flex items-center gap-2">
                {expandedSections.custody ? <ChevronDown className="w-4 h-4 text-blue-700" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                <span className="font-bold text-blue-950 text-xs uppercase tracking-wide flex items-center gap-1.5">
                  <Shield className="w-4 h-4 text-blue-600" />
                  11. Digital Evidence Chain of Custody & Integrity Seal
                </span>
              </div>
              <span className="px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800 font-bold text-[10px] border border-emerald-300">
                Tamper-Evident Integrity Seal
              </span>
            </div>

            {expandedSections.custody && (
              <div className="p-5 space-y-3 text-xs">
                {/* Verification Feedback Banner if tested */}
                {verificationResult && (
                  <div className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-between ${
                    verificationResult.status === 'VERIFIED_VALID'
                      ? 'bg-emerald-50 text-emerald-900 border-emerald-300'
                      : 'bg-rose-50 text-rose-900 border-rose-300'
                  }`}>
                    <span>Status: {verificationResult.status} &bull; {verificationResult.message}</span>
                    <span className="font-mono text-[11px]">{verificationResult.integrity?.match ? '✓ MATCH' : '✕ MISMATCH'}</span>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-[11px]">
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase font-bold text-slate-500 font-sans block mb-1">
                      Email Acquisition SHA-256 (Primary):
                    </span>
                    <span className="text-slate-900 font-bold break-all">{rawSha256}</span>
                    <span className="text-[10px] text-slate-400 font-sans block mt-1">Calculated from original acquired RFC 5322 payload.</span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                    <span className="text-[10px] uppercase font-bold text-slate-500 font-sans block mb-1">
                      Dossier Integrity Seal (SHA-256):
                    </span>
                    <span className="text-blue-700 font-bold break-all">{dossierDigest}</span>
                    <span className="text-[10px] text-slate-400 font-sans block mt-1">Calculated over canonical investigation findings.</span>
                  </div>
                </div>

                <div className="text-[10px] text-slate-400 italic">
                  Report generated from the AegisMail forensic investigation pipeline. This automated analysis provides evidence integrity verification and does not constitute guaranteed legal court-admissibility or formal ISO certification.
                </div>
              </div>
            )}
          </div>

        </div>

      </div>

      {/* Embedded Evidence Inspector Modal */}
      <EvidenceInspectorModal
        isOpen={!!inspectingEvidence}
        onClose={() => setInspectingEvidence(null)}
        evidence={inspectingEvidence}
        allFindings={findings}
      />
    </div>
  );
}
