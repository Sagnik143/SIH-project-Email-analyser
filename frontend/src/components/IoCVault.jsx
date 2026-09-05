import React, { useState } from 'react';
import { Database, Link, Paperclip, Globe, Copy, Check, AlertTriangle } from 'lucide-react';

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
    <div className="app-card p-6 space-y-4 bg-white border-slate-200 shadow-xs">
      
      {/* Title and Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-blue-50 text-blue-600 border border-blue-100">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Threat Indicators & Extracted Evidence (IoCs)
            </h3>
            <p className="text-xs text-slate-500">
              Safe defanged hyperlinks, file attachment hashes, and network addresses
            </p>
          </div>
        </div>

        {/* Tab Buttons */}
        <div className="flex items-center gap-1.5 bg-slate-100 p-1.5 rounded-xl border border-slate-200 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('urls')}
            className={`px-3.5 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'urls' ? 'bg-white text-blue-600 shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Link className="w-3.5 h-3.5" />
            <span>Links ({urls.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('attachments')}
            className={`px-3.5 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'attachments' ? 'bg-white text-purple-600 shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Paperclip className="w-3.5 h-3.5" />
            <span>Attachments ({attachments.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('ips')}
            className={`px-3.5 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'ips' ? 'bg-white text-emerald-600 shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>IPs & Domains ({ips.length + domains.length})</span>
          </button>
        </div>
      </div>

      {/* Tab 1: URLs */}
      {activeTab === 'urls' && (
        <div className="space-y-2.5">
          {urls.length === 0 ? (
            <div className="p-8 text-center text-xs font-medium text-slate-400 bg-slate-50 rounded-xl">
              No hyperlinks detected in email body.
            </div>
          ) : (
            <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
              {urls.map((u, i) => (
                <div 
                  key={i} 
                  className={`p-3.5 rounded-xl border text-xs flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                    u.isSuspicious ? 'bg-rose-50/60 border-rose-200' : 'bg-slate-50/60 border-slate-200'
                  }`}
                >
                  <div className="space-y-1 overflow-hidden">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-900 truncate max-w-[420px]">
                        {u.defanged}
                      </span>
                      {u.isSuspicious && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-700 border border-rose-200">
                          SUSPICIOUS LINK
                        </span>
                      )}
                    </div>
                    {u.flags.length > 0 && (
                      <div className="space-y-0.5">
                        {u.flags.map((flag, fIdx) => (
                          <div key={fIdx} className="text-xs text-rose-700 font-medium flex items-center gap-1">
                            <span>⚠</span> <span>{flag}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <button
                    onClick={() => copyToClipboard(u.original, `url-${i}`)}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:border-slate-300 text-xs font-semibold text-slate-700 shadow-2xs shrink-0 transition"
                    title="Copy original link"
                  >
                    {copiedKey === `url-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
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
        <div className="space-y-2.5">
          {attachments.length === 0 ? (
            <div className="p-8 text-center text-xs font-medium text-slate-400 bg-slate-50 rounded-xl">
              No attachments present in this email message.
            </div>
          ) : (
            <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
              {attachments.map((att, i) => (
                <div 
                  key={i} 
                  className={`p-3.5 rounded-xl border text-xs ${
                    att.isDangerous ? 'bg-rose-50/70 border-rose-300 shadow-xs' : 'bg-slate-50/70 border-slate-200'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Paperclip className={`w-4 h-4 ${att.isDangerous ? 'text-rose-600' : 'text-purple-600'}`} />
                      <span className="font-bold text-slate-900">{att.filename}</span>
                      <span className="text-slate-500 text-xs">({Math.round(att.size / 1024)} KB)</span>
                      {att.isDangerous && (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-extrabold bg-rose-600 text-white shadow-2xs">
                          HIGH RISK FILE EXTENSION
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => copyToClipboard(att.sha256, `sha-${i}`)}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:border-slate-300 text-xs font-semibold text-slate-700 shadow-2xs shrink-0 transition"
                      title="Copy SHA-256 hash"
                    >
                      {copiedKey === `sha-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                      <span>Copy SHA-256</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2.5 pt-2.5 border-t border-slate-200/80 font-mono text-xs">
                    <div className="truncate text-slate-500">
                      SHA256: <span className="text-slate-800 font-semibold select-all">{att.sha256}</span>
                    </div>
                    <div className="truncate text-slate-500">
                      MD5: <span className="text-slate-800 font-semibold select-all">{att.md5}</span>
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
          <div className="space-y-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Extracted Transmission IPs:</span>
            <div className="space-y-1.5 max-h-[220px] overflow-y-auto">
              {ips.map((ip, i) => (
                <div key={i} className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono">
                  <span className="text-slate-800 font-semibold">{ip}</span>
                  <button
                    onClick={() => copyToClipboard(ip, `ip-${i}`)}
                    className="p-1 text-slate-400 hover:text-slate-700"
                  >
                    {copiedKey === `ip-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Domains */}
          <div className="space-y-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Extracted Domains:</span>
            <div className="space-y-1.5 max-h-[220px] overflow-y-auto">
              {domains.map((dom, i) => (
                <div key={i} className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono">
                  <span className="text-slate-800 font-semibold">{dom}</span>
                  <button
                    onClick={() => copyToClipboard(dom, `dom-${i}`)}
                    className="p-1 text-slate-400 hover:text-slate-700"
                  >
                    {copiedKey === `dom-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
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
