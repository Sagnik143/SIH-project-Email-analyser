import React from 'react';
import { 
  LayoutDashboard, 
  Mail, 
  FolderGit2, 
  Network, 
  ShieldAlert, 
  FileCheck2, 
  Settings, 
  ShieldCheck, 
  ChevronRight,
  Database,
  Terminal,
  Activity
} from 'lucide-react';

export default function Sidebar({ activeNav, onSelectNav, pendingCasesCount = 0 }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, badge: null },
    { id: 'analyze', label: 'Analyze Email', icon: Mail, badge: 'Active' },
    { id: 'investigations', label: 'Investigations', icon: FolderGit2, badge: pendingCasesCount > 0 ? String(pendingCasesCount) : null },
    { id: 'campaigns', label: 'Campaigns & Activity', icon: Network, badge: null },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: ShieldAlert, badge: null },
    { id: 'reports', label: 'Reports & Audits', icon: FileCheck2, badge: null },
    { id: 'settings', label: 'System Settings', icon: Settings, badge: null }
  ];

  return (
    <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col shrink-0 border-r border-slate-800 select-none min-h-screen">
      
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-white font-black shadow-lg shadow-blue-500/20">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <h1 className="text-base font-black text-white tracking-tight">
              AegisMail
            </h1>
            <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
              DFIR
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-medium truncate max-w-[150px]">
            Forensic Investigation
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 py-2">
          Investigation Modules
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onSelectNav(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all group ${
                isActive
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 transition ${isActive ? 'text-white' : 'text-slate-400 group-hover:text-slate-200'}`} />
                <span>{item.label}</span>
              </div>

              {item.badge && (
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                  isActive 
                    ? 'bg-blue-700/80 text-white' 
                    : 'bg-slate-800 text-slate-300 border border-slate-700'
                }`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Engine & Database Status Card */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 space-y-2 text-xs">
        <div className="flex items-center justify-between text-[11px] text-slate-400 font-medium">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Heuristic Engine</span>
          </span>
          <span className="text-emerald-400 font-bold">Online</span>
        </div>

        <div className="p-2 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1 text-[11px]">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1">
              <Database className="w-3 h-3 text-blue-400" /> Storage:
            </span>
            <span className="font-mono text-slate-300">SQLite (Local)</span>
          </div>
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1">
              <Activity className="w-3 h-3 text-purple-400" /> Standard:
            </span>
            <span className="text-slate-300 text-[10px]">ISO/IEC 27037 Aligned</span>
          </div>
        </div>
      </div>

    </aside>
  );
}
