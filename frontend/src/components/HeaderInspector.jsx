import React, { useState } from 'react';
import { Terminal, Search, Copy, Check, Filter } from 'lucide-react';

export default function HeaderInspector({ headerLines, rawHeaders }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [copied, setCopied] = useState(false);

  if (!headerLines || headerLines.length === 0) {
    return null;
  }

  const filteredLines = headerLines.filter((h) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return h.key.toLowerCase().includes(term) || h.line.toLowerCase().includes(term);
  });

  const copyAllHeaders = () => {
    const fullText = headerLines.map(h => h.line).join('\n');
    navigator.clipboard.writeText(fullText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isHighPriorityHeader = (key) => {
    const k = key.toLowerCase();
    return ['received', 'authentication-results', 'received-spf', 'dkim-signature', 'from', 'reply-to', 'return-path', 'subject'].includes(k);
  };

  return (
    <div className="glass-panel p-5 space-y-4">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              RFC 5322 Raw Header Explorer
            </h3>
            <p className="text-[11px] text-slate-400">
              Low-level technical header analyzer with security-critical highlighting & live search filter
            </p>
          </div>
        </div>

        {/* Search & Copy Controls */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Filter headers (e.g., received, spf)..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 w-52 sm:w-64"
            />
          </div>

          <button
            onClick={copyAllHeaders}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 transition"
            title="Copy all raw headers"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy All'}</span>
          </button>
        </div>
      </div>

      {/* Raw Headers List */}
      <div className="rounded-lg bg-[#060911] border border-slate-800/90 p-3 max-h-[360px] overflow-y-auto font-mono text-xs space-y-1.5 select-text">
        {filteredLines.length === 0 ? (
          <div className="p-4 text-center text-slate-500">
            No headers match search filter "{searchTerm}".
          </div>
        ) : (
          filteredLines.map((item, idx) => {
            const isImportant = isHighPriorityHeader(item.key);
            const isReceived = item.key.toLowerCase() === 'received';
            const isAuth = item.key.toLowerCase().includes('auth') || item.key.toLowerCase().includes('spf') || item.key.toLowerCase().includes('dkim');

            return (
              <div 
                key={idx} 
                className={`py-1 px-2 rounded break-all transition-colors ${
                  isReceived 
                    ? 'bg-cyan-950/20 text-cyan-200 border-l-2 border-cyan-500' 
                    : (isAuth 
                      ? 'bg-purple-950/20 text-purple-200 border-l-2 border-purple-500' 
                      : (isImportant 
                        ? 'bg-slate-900/60 text-slate-200' 
                        : 'text-slate-400 hover:text-slate-300'))
                }`}
              >
                <strong className={`font-semibold mr-1.5 ${
                  isReceived ? 'text-cyan-400' : (isAuth ? 'text-purple-400' : 'text-slate-300')
                }`}>
                  {item.key}:
                </strong>
                <span>{item.line.replace(new RegExp(`^${item.key}:\\s*`, 'i'), '')}</span>
              </div>
            );
          })
        )}
      </div>

    </div>
  );
}
