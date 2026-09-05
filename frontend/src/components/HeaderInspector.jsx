import React, { useState } from 'react';
import { Terminal, Search, Copy, Check } from 'lucide-react';

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
    <div className="app-card p-6 space-y-4 bg-white border-slate-200 shadow-xs">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-slate-100 text-slate-700 border border-slate-200">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Raw RFC 5322 Technical Email Headers
            </h3>
            <p className="text-xs text-slate-500">
              Direct inspection of MIME headers with instant text search and line filtering
            </p>
          </div>
        </div>

        {/* Search & Copy Controls */}
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search headers (e.g. received, spf)..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-50 border border-slate-300 rounded-xl pl-9 pr-3.5 py-1.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 w-52 sm:w-64"
            />
          </div>

          <button
            onClick={copyAllHeaders}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-white border border-slate-300 hover:bg-slate-50 text-xs font-semibold text-slate-700 shadow-2xs transition"
            title="Copy all raw headers"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span>{copied ? 'Copied' : 'Copy All'}</span>
          </button>
        </div>
      </div>

      {/* Raw Headers List */}
      <div className="rounded-xl bg-slate-900 text-slate-200 p-4 max-h-[360px] overflow-y-auto font-mono text-xs space-y-1.5 select-text shadow-inner">
        {filteredLines.length === 0 ? (
          <div className="p-6 text-center text-slate-400">
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
                className={`py-1 px-2.5 rounded transition-colors ${
                  isReceived 
                    ? 'bg-blue-950/60 text-blue-200 border-l-3 border-blue-400' 
                    : (isAuth 
                      ? 'bg-purple-950/60 text-purple-200 border-l-3 border-purple-400' 
                      : (isImportant 
                        ? 'bg-slate-800/80 text-slate-100' 
                        : 'text-slate-400 hover:text-slate-200'))
                }`}
              >
                <strong className={`font-bold mr-2 ${
                  isReceived ? 'text-cyan-400' : (isAuth ? 'text-purple-300' : 'text-slate-200')
                }`}>
                  {item.key}:
                </strong>
                <span className="leading-relaxed">{item.line.replace(new RegExp(`^${item.key}:\\s*`, 'i'), '')}</span>
              </div>
            );
          })
        )}
      </div>

    </div>
  );
}
