import React, { useState } from 'react';
import { GitCommit, ArrowRight, Lock, Unlock, Server, Clock, ChevronDown, ChevronUp, ShieldCheck } from 'lucide-react';

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
              Server Relay Sequence
            </h3>
            <p className="text-xs text-slate-500">
              Step-by-step route hops from sender's device to destination mailbox
            </p>
          </div>
        </div>

        <span className="text-xs font-bold px-3 py-1 rounded-full bg-slate-100 text-slate-700">
          {hops.length} Hops Chain
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
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 uppercase">
                          Sender Origin
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
                      <span>📍 {hop.geo?.city || 'Unknown'}, {hop.geo?.country || 'Unknown'}</span>
                      <span className="text-slate-300">•</span>
                      <span className="text-slate-500 truncate max-w-[180px]">{hop.geo?.isp || 'Standard Carrier'}</span>
                    </div>
                  </div>
                </div>

                {/* MTA Transition: From -> By */}
                <div className="flex items-center gap-1.5 text-xs font-mono text-slate-700 bg-white px-2.5 py-1.5 rounded-lg border border-slate-200 overflow-hidden text-ellipsis shadow-2xs">
                  <span className="text-slate-500 truncate max-w-[120px]" title={hop.fromHost}>
                    {hop.fromHost}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-blue-500 shrink-0" />
                  <span className="text-blue-700 font-semibold truncate max-w-[120px]" title={hop.byHost}>
                    {hop.byHost}
                  </span>
                </div>

                {/* Security & Transit Delay Badges */}
                <div className="flex items-center gap-2 shrink-0">
                  {/* Protocol / TLS status */}
                  <div className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white border border-slate-200 text-xs font-semibold">
                    {hop.tlsCipher ? (
                      <>
                        <Lock className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-700">Encrypted</span>
                      </>
                    ) : (
                      <>
                        <Unlock className="w-3.5 h-3.5 text-amber-600" />
                        <span className="text-amber-700">Plaintext</span>
                      </>
                    )}
                  </div>

                  {/* Delay Delta */}
                  <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-white border border-slate-200 text-xs text-slate-600 font-medium">
                    <Clock className="w-3 h-3 text-slate-400" />
                    <span>+{hop.transitDelaySeconds ?? 0}s</span>
                  </div>

                  {/* Expand Toggle */}
                  <button
                    onClick={() => setExpandedHop(isExpanded ? null : hop.hopNumber)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
                    title="View Raw Header Line"
                  >
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>

              </div>

              {/* Collapsible Raw Header */}
              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-slate-200/80 text-xs font-mono text-slate-700 bg-white p-3 rounded-lg border border-slate-100 shadow-inner">
                  <div className="text-[11px] text-slate-400 font-bold uppercase mb-1">
                    Raw Received Header Content:
                  </div>
                  <div className="break-all whitespace-pre-wrap select-all text-slate-800 leading-relaxed">
                    {hop.rawText}
                  </div>
                  {hop.timestampISO && (
                    <div className="mt-2 text-slate-500 text-[11px]">
                      Hop Timestamp: <span className="text-blue-600 font-semibold">{hop.timestampISO}</span>
                    </div>
                  )}
                </div>
              )}

            </div>
          );
        })}
      </div>

    </div>
  );
}
