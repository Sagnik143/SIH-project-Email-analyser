import React, { useState } from 'react';
import { GitCommit, ArrowRight, Lock, Unlock, Server, Clock, ChevronDown, ChevronUp, ShieldCheck, Info } from 'lucide-react';

export default function RelayTimeline({ relay }) {
  const [expandedHop, setExpandedHop] = useState(null);

  if (!relay || !relay.hops || relay.hops.length === 0) {
    return (
      <div className="app-card p-6 text-center text-slate-400 text-xs font-medium">
        No Received: header hops detected in email.
      </div>
    );
  }

  const hops = relay.hops;

  return (
    <div className="app-card p-5 space-y-3.5 bg-white border-slate-200">
      
      {/* Title */}
      <div className="flex items-center justify-between border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-50 text-purple-600 border border-purple-100">
            <GitCommit className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Observable Relay Sequence
            </h3>
            <p className="text-xs text-slate-500">
              Transmission path reconstructed from authoritative Received: headers
            </p>
          </div>
        </div>

        <span className="text-xs font-bold px-3 py-1 rounded-full bg-slate-100 text-slate-700">
          {hops.length} Hops Chain
        </span>
      </div>

      {/* Limitation Notice */}
      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-600 text-[11px] flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-purple-600 shrink-0 mt-0.5" />
        <span className="leading-relaxed">
          Hop order reflects outer-to-inner parsing of Received: headers. Timestamps are recorded by individual MTAs and subject to server clock synchronization limitations.
        </span>
      </div>

      {/* Hop Flow List */}
      <div className="space-y-2.5 pt-1">
        {hops.map((hop, index) => {
          const isOrigin = hop.isOriginHop || index === 0;
          const isFinal = index === hops.length - 1;
          const isExpanded = expandedHop === hop.hopNumber;

          return (
            <div 
              key={hop.hopNumber} 
              className={`p-3.5 rounded-xl border transition-all ${
                isOrigin 
                  ? 'bg-rose-50/50 border-rose-200 shadow-xs' 
                  : (isFinal ? 'bg-purple-50/50 border-purple-200' : 'bg-slate-50/70 border-slate-200 hover:border-slate-300')
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                
                {/* Hop Identifier & Status Badge */}
                <div className="flex items-center gap-3 shrink-0">
                  <div className={`w-8 h-8 rounded-xl flex items-center justify-center font-bold text-xs ${
                    isOrigin 
                      ? 'bg-rose-600 text-white shadow-xs' 
                      : (isFinal ? 'bg-purple-600 text-white' : 'bg-blue-600 text-white')
                  }`}>
                    #{hop.hopNumber}
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-900">
                        {hop.ip || 'Direct Host'}
                      </span>

                      {isOrigin && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200 uppercase" title="Reported in earliest header; unverified human origin">
                          Claimed Origin (UNVERIFIED)
                        </span>
                      )}

                      {isFinal && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 uppercase">
                          Destination MX
                        </span>
                      )}

                      {hop.isPrivate && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-200 text-slate-600">
                          Internal Network
                        </span>
                      )}
                    </div>

                    <div className="text-xs text-slate-500 flex items-center gap-1.5 mt-0.5">
                      <span>📍 Observed Infrastructure: {hop.geo?.city || 'Unknown'}, {hop.geo?.country || 'Unknown'}</span>
                      <span className="text-slate-300">•</span>
                      <span className="text-slate-500 truncate max-w-[180px]">{hop.geo?.isp || 'Standard Carrier'}</span>
                    </div>
                  </div>
                </div>

                {/* Timing & Expand Controls */}
                <div className="flex items-center gap-3 text-xs">
                  <div className="text-right">
                    <span className="text-slate-400 text-[10px] block uppercase font-bold">Transit Delta</span>
                    <span className="font-mono font-semibold text-slate-700">
                      {hop.delaySeconds !== null ? `+${hop.delaySeconds}s` : 'Base Hop'}
                    </span>
                  </div>

                  <button
                    onClick={() => setExpandedHop(isExpanded ? null : hop.hopNumber)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
                  >
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Collapsible Hop Technical Header Details */}
              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-slate-200/60 text-xs space-y-2 font-mono text-slate-700 bg-white/80 p-3 rounded-lg">
                  <div><strong>From MTA:</strong> {hop.from || 'Direct Handshake'}</div>
                  <div><strong>By MTA:</strong> {hop.by || 'Local MX'}</div>
                  <div><strong>Timestamp:</strong> {hop.timestamp || 'Not Specified'}</div>
                  <div><strong>Security Protocol:</strong> {hop.tls || 'Plaintext / Standard SMTP'}</div>
                </div>
              )}
            </div>
          );
        })}
      </div>

    </div>
  );
}
