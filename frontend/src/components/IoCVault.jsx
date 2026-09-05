import React, { useState } from 'react';
import { Database, Link, Paperclip, Globe, Copy, Check, AlertTriangle, ShieldAlert } from 'lucide-react';

export default function IoCVault({ iocs }) {
  const [activeTab, setActiveTab] = useState('urls');
  const [copiedKey, setCopiedKey] = useState(null);

  if (!iocs) return null;

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const urls = iocs.urls || [];
  const attachments = iocs.attachments || [];
  const ips = iocs.ips || [];
  const domains = iocs.domains || [];

  return (
    <div className="glass-panel p-5 space-y-4">
      
      {/* Title and Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              Indicators of Compromise (IoC) Vault
            </h3>
            <p className="text-[11px] text-slate-400">
              Extracted threat telemetry artifacts: defanged URLs, network addresses, and cryptographic file hashes
            </p>
          </div>
        </div>

        {/* Tab Buttons */}
        <div className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-lg border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('urls')}
            className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 ${
              activeTab === 'urls' ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Link className="w-3.5 h-3.5" />
            <span>URLs ({urls.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('attachments')}
            className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 ${
              activeTab === 'attachments' ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Paperclip className="w-3.5 h-3.5" />
            <span>Files ({attachments.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('ips')}
            className={`px-3 py-1.5 rounded-md transition flex items-center gap-1.5 ${
              activeTab === 'ips' ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>IPs & Domains ({ips.length + domains.length})</span>
          </button>
        </div>
      </div>

      {/* Tab 1: URLs */}
      {activeTab === 'urls' && (
        <div className="space-y-2">
          {urls.length === 0 ? (
            <div className="p-6 text-center text-xs font-mono text-slate-500">
              No hyperlinks extracted from email body.
            </div>
          ) : (
            <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
              {urls.map((u, i) => (
                <div 
                  key={i} 
                  className={`p-3 rounded-lg border text-xs flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                    u.isSuspicious ? 'bg-rose-950/20 border-rose-500/30' : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <div className="space-y-1 overflow-hidden">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-200 truncate max-w-[400px]">
                        {u.defanged}
                      </span>
                      {u.isSuspicious && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          SUSPICIOUS
                        </span>
                      )}
                    </div>
                    {u.flags.length > 0 && (
                      <div className="space-y-0.5">
                        {u.flags.map((flag, fIdx) => (
                          <div key={fIdx} className="text-[11px] text-rose-300 font-mono flex items-center gap-1">
                            <span>⚠</span> <span>{flag}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <button
                    onClick={() => copyToClipboard(u.original, `url-${i}`)}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-slate-300 shrink-0 transition"
                    title="Copy original URL"
                  >
                    {copiedKey === `url-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === `url-${i}` ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Attachments */}
      {activeTab === 'attachments' && (
        <div className="space-y-2">
          {attachments.length === 0 ? (
            <div className="p-6 text-center text-xs font-mono text-slate-500">
              No file attachments found in this message.
            </div>
          ) : (
            <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
              {attachments.map((att, i) => (
                <div 
                  key={i} 
                  className={`p-3 rounded-lg border text-xs ${
                    att.isDangerous ? 'bg-rose-950/25 border-rose-500/40' : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Paperclip className={`w-4 h-4 ${att.isDangerous ? 'text-rose-400' : 'text-cyan-400'}`} />
                      <span className="font-mono font-bold text-slate-100">{att.filename}</span>
                      <span className="text-slate-500 font-mono text-[11px]">({Math.round(att.size / 1024)} KB)</span>
                      {att.isDangerous && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                          HIGH RISK PAYLOAD
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => copyToClipboard(att.sha256, `sha-${i}`)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-slate-300 shrink-0 transition"
                      title="Copy SHA-256 hash"
                    >
                      {copiedKey === `sha-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy SHA-256</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2 pt-2 border-t border-slate-800/80 font-mono text-[11px]">
                    <div className="truncate text-slate-400">
                      SHA256: <span className="text-cyan-300 select-all">{att.sha256}</span>
                    </div>
                    <div className="truncate text-slate-400">
                      MD5: <span className="text-cyan-300 select-all">{att.md5}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: IPs & Domains */}
      {activeTab === 'ips' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* IPs */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-mono uppercase text-slate-400 block">Extracted Transmission IPs:</span>
            <div className="space-y-1 max-h-[220px] overflow-y-auto">
              {ips.map((ip, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <span className="text-cyan-300">{ip}</span>
                  <button
                    onClick={() => copyToClipboard(ip, `ip-${i}`)}
                    className="p-1 text-slate-400 hover:text-slate-200"
                  >
                    {copiedKey === `ip-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Domains */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-mono uppercase text-slate-400 block">Extracted Host Domains:</span>
            <div className="space-y-1 max-h-[220px] overflow-y-auto">
              {domains.map((dom, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <span className="text-slate-300">{dom}</span>
                  <button
                    onClick={() => copyToClipboard(dom, `dom-${i}`)}
                    className="p-1 text-slate-400 hover:text-slate-200"
                  >
                    {copiedKey === `dom-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
