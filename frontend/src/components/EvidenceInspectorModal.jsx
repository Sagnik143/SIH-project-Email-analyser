import React, { useState } from 'react';
import { X, Shield, Copy, Check, ExternalLink, Info, MapPin, Clock, Database, Tag } from 'lucide-react';

/**
 * Evidence Inspector Modal (Phase 8: Trust Boundary + Evidence UX Polish)
 * 
 * Provides an authoritative deep-dive view into any specific evidence record (E-xxx).
 * Emphasizes that this is OBSERVED EVIDENCE, preserves the raw value unaltered,
 * and shows all deterministic findings (F-xxx) that rely upon this evidence.
 */
export default function EvidenceInspectorModal({ 
  isOpen, 
  onClose, 
  evidence, 
  allFindings = [], 
  onSelectFinding 
}) {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !evidence) return null;

  const handleCopy = () => {
    if (!evidence.value) return;
    navigator.clipboard.writeText(String(evidence.value));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Resolve findings that reference this evidence item
  const relatedFindings = allFindings.filter(f => 
    Array.isArray(f.evidenceIds) && f.evidenceIds.includes(evidence.id)
  );

  const isIpAddress = evidence.field?.toLowerCase().includes('ip') || 
    (typeof evidence.value === 'string' && /^(\d{1,3}\.){3}\d{1,3}$/.test(evidence.value.trim()));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 animate-in fade-in duration-200">
      <div 
        className="bg-white border border-slate-200 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
        role="dialog"
        aria-labelledby="evidence-inspector-title"
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center font-black text-sm shadow-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold px-2.5 py-0.5 rounded-lg bg-blue-100 text-blue-800 border border-blue-200">
                  {evidence.id}
                </span>
                <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 uppercase tracking-wide">
                  Observed Evidence
                </span>
              </div>
              <h2 id="evidence-inspector-title" className="text-base font-bold text-slate-900 mt-0.5">
                Evidence Inspector &bull; {evidence.field || 'Direct Artifact'}
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition"
            aria-label="Close Inspector"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs">
          
          {/* Trust Boundary Notice */}
          <div className="p-3 rounded-xl bg-blue-50/70 border border-blue-200 text-blue-950 flex items-start gap-2.5">
            <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
            <div className="leading-relaxed">
              <strong>Trust Boundary Definition:</strong> This record constitutes directly extracted, authoritative technical evidence from the ingested RFC 5322 payload. It has not been modified or inferred by AI.
            </div>
          </div>

          {/* Core Metadata Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-[10px] font-bold uppercase text-slate-400 flex items-center gap-1">
                <Database className="w-3 h-3 text-slate-500" /> Evidence Source
              </span>
              <span className="font-semibold text-slate-900 font-mono text-xs block">
                {evidence.source || 'RFC5322_HEADER'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-[10px] font-bold uppercase text-slate-400 flex items-center gap-1">
                <Tag className="w-3 h-3 text-slate-500" /> Field / Property
              </span>
              <span className="font-semibold text-slate-900 font-mono text-xs block">
                {evidence.field || 'Header Value'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-[10px] font-bold uppercase text-slate-400 flex items-center gap-1">
                <Shield className="w-3 h-3 text-slate-500" /> Collection Method
              </span>
              <span className="font-semibold text-slate-900 font-mono text-xs block">
                {evidence.collectionMethod || 'DIRECT_EXTRACTION'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
              <span className="text-[10px] font-bold uppercase text-slate-400 flex items-center gap-1">
                <Clock className="w-3 h-3 text-slate-500" /> Ingestion Timestamp
              </span>
              <span className="font-semibold text-slate-700 text-xs block">
                {evidence.timestamp ? new Date(evidence.timestamp).toUTCString() : 'Active Ingestion Pipeline'}
              </span>
            </div>
          </div>

          {/* Raw Evidence Value (Authoritative & Unaltered) */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-slate-700 tracking-wide">
                Authoritative Observed Value
              </span>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-[11px] transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Value'}</span>
              </button>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs break-all select-all leading-relaxed shadow-inner">
              {String(evidence.value || 'N/A')}
            </div>
          </div>

          {/* IP Geolocation Infrastructure Notice if applicable */}
          {isIpAddress && (
            <div className="p-3 rounded-xl bg-amber-50/70 border border-amber-200 text-amber-900 flex items-start gap-2.5">
              <MapPin className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <div className="leading-relaxed text-[11px]">
                <strong>Observed Infrastructure Geolocation Notice:</strong> IP geolocation describes the registered/observed network routing infrastructure associated with this IP address. It does <em>not</em> establish the physical location or identity of a person.
              </div>
            </div>
          )}

          {/* Details / Additional Context */}
          {evidence.details && (
            <div className="space-y-1">
              <span className="text-[11px] font-bold uppercase text-slate-700 tracking-wide">
                Evidence Details & Telemetry
              </span>
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-700 leading-relaxed font-sans">
                {typeof evidence.details === 'object' 
                  ? JSON.stringify(evidence.details, null, 2) 
                  : String(evidence.details)}
              </div>
            </div>
          )}

          {/* Traceability: Linked Deterministic Findings */}
          <div className="space-y-2 border-t border-slate-100 pt-4">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-slate-800 tracking-wide flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-blue-600" />
                Linked Deterministic Findings ({relatedFindings.length})
              </span>
              <span className="text-[10px] text-slate-500">
                Evidence-to-Finding Traceability
              </span>
            </div>

            {relatedFindings.length > 0 ? (
              <div className="space-y-2">
                {relatedFindings.map(finding => {
                  let sevBadge = 'bg-slate-100 text-slate-700 border-slate-200';
                  if (finding.severity === 'critical') sevBadge = 'bg-rose-100 text-rose-800 border-rose-200';
                  else if (finding.severity === 'high') sevBadge = 'bg-orange-100 text-orange-800 border-orange-200';
                  else if (finding.severity === 'medium') sevBadge = 'bg-amber-100 text-amber-800 border-amber-200';
                  else if (finding.severity === 'low') sevBadge = 'bg-emerald-100 text-emerald-800 border-emerald-200';

                  return (
                    <div 
                      key={finding.id}
                      className="p-3 rounded-xl bg-slate-50 hover:bg-slate-100/80 border border-slate-200 transition space-y-1.5 cursor-pointer"
                      onClick={() => onSelectFinding && onSelectFinding(finding.id)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded text-[10px]">
                            {finding.id}
                          </span>
                          <span className="font-bold text-slate-900 text-xs">
                            {finding.title}
                          </span>
                        </div>
                        <span className={`px-2 py-0.5 rounded-full font-bold uppercase text-[9px] border ${sevBadge}`}>
                          {finding.severity}
                        </span>
                      </div>
                      <p className="text-slate-600 text-[11px] leading-relaxed">
                        {finding.summary}
                      </p>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-500 text-center text-xs">
                This evidence item represents baseline telemetry and is not currently associated with a threat finding.
              </div>
            )}
          </div>

        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50 flex items-center justify-between text-xs">
          <span className="text-slate-400 font-mono text-[11px]">
            AegisMail Evidence Ref: {evidence.id}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-200 hover:bg-slate-300 font-bold text-slate-800 transition"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
