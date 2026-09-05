import React, { useState } from 'react';
import { GitCommit, ArrowRight, Lock, Unlock, Server, Clock, ShieldAlert, Eye, ChevronDown, ChevronUp } from 'lucide-react';

export default function RelayTimeline({ relay }) {
  const [expandedHop, setExpandedHop] = useState(null);

  if (!relay || !relay.hops || relay.hops.length === 0) {
    return (
      <div className="glass-panel p-5 text-center text-slate-400 text-xs font-mono">
        No Received: header hops detected in email.
      </div>
    );
  }

  const hops = relay.hops;

  return (
    <div className="glass-panel p-4 space-y-3">
      
      {/* Title */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <GitCommit className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              SMTP Relay Hop Chain & Transmission Timeline
            </h3>
            <p className="text-[11px] text-slate-400">
              Reconstructed chronological server hops from originating client MTA to final destination MX
            </p>
          </div>
        </div>

        <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
          {hops.length} Sequential Hops
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
              className={`p-3 rounded-lg border transition-all ${
                isOrigin 
                  ? 'bg-rose-950/20 border-rose-500/40 shadow-sm' 
                  : (isFinal ? 'bg-purple-950/20 border-purple-500/30' : 'bg-slate-900/50 border-slate-800 hover:border-slate-700')
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                
                {/* Hop Identifier & Status Badge */}
                <div className="flex items-center gap-3 shrink-0">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono font-bold text-xs ${
                    isOrigin 
                      ? 'bg-rose-500 text-white shadow-md shadow-rose-500/30' 
                      : (isFinal ? 'bg-purple-600 text-white' : 'bg-slate-800 text-cyan-300 border border-slate-700')
                  }`}>
                    #{hop.hopNumber}
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-slate-200">
                        {hop.ip || 'No IP in header'}
                      </span>

                      {hop.isPrivate ? (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300">
                          RFC 1918 Private IP
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-300">
                          Public IP
                        </span>
                      )}

                      {isOrigin && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 font-bold animate-pulse">
                          ORIGINATING HOST
                        </span>
                      )}

                      {isFinal && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-300 font-bold">
                          DESTINATION MX
                        </span>
                      )}
                    </div>

                    <div className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                      <span>{hop.geo?.city || 'Unknown'}, {hop.geo?.country || 'Unknown'}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-400 truncate max-w-[200px]">{hop.geo?.isp || 'Unknown ISP'}</span>
                    </div>
                  </div>
                </div>

                {/* MTA Transition: From -> By */}
                <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-950/60 px-3 py-1.5 rounded border border-slate-800/80 overflow-hidden text-ellipsis">
                  <span className="text-slate-400 truncate max-w-[140px]" title={hop.fromHost}>
                    {hop.fromHost}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="text-cyan-300 truncate max-w-[140px]" title={hop.byHost}>
                    {hop.byHost}
                  </span>
                </div>

                {/* Security & Transit Delay Badges */}
                <div className="flex items-center gap-2 shrink-0">
                  {/* Protocol / TLS status */}
                  <div className="flex items-center gap-1 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono">
                    {hop.tlsCipher ? (
                      <>
                        <Lock className="w-3 h-3 text-emerald-400" />
                        <span className="text-emerald-300 truncate max-w-[100px]" title={hop.tlsCipher}>
                          {hop.protocol || 'TLS'}
                        </span>
                      </>
                    ) : (
                      <>
                        <Unlock className="w-3 h-3 text-amber-400" />
                        <span className="text-amber-400">{hop.protocol || 'PLAINTEXT'}</span>
                      </>
                    )}
                  </div>

                  {/* Delay Delta */}
                  <div className="flex items-center gap-1 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300">
                    <Clock className="w-3 h-3 text-cyan-400" />
                    <span>+{hop.transitDelaySeconds ?? 0}s</span>
                  </div>

                  {/* Expand / Raw Toggle */}
                  <button
                    onClick={() => setExpandedHop(isExpanded ? null : hop.hopNumber)}
                    className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
                    title="View Raw Received Header Line"
                  >
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>

              </div>

              {/* Collapsible Raw Header Details */}
              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-300 bg-slate-950 p-2.5 rounded">
                  <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                    Raw RFC Received Header:
                  </div>
                  <div className="break-all whitespace-pre-wrap select-all text-slate-300">
                    {hop.rawText}
                  </div>
                  {hop.timestampISO && (
                    <div className="mt-2 text-slate-400 text-[10px]">
                      Timestamp: <span className="text-cyan-400">{hop.timestampISO}</span>
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
