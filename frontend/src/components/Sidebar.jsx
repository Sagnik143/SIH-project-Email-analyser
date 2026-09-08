/**
 * Sidebar Navigation Component
 */

import { NavLink } from 'react-router-dom';
import { useState } from 'react';

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { section: 'Home' },
    { path: '/', icon: '📊', label: 'Dashboard' },
    { section: 'Tools' },
    { path: '/analyze', icon: '🔍', label: 'Check Email' },
    { path: '/geo-tracer', icon: '🌍', label: 'IP Location Map' },
    { section: 'Manage' },
    { path: '/cases', icon: '📁', label: 'My Cases' },
    { path: '/reports', icon: '📋', label: 'Reports' },
  ];

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-brand">
        <div className="brand-icon">🛡️</div>
        <div className="brand-text">
          <h2>MailGuard</h2>
          <span>Email Safety Platform</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item, index) => {
          if (item.section) {
            return (
              <div key={`section-${index}`} className="sidebar-section-label">
                {item.section}
              </div>
            );
          }

          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="sidebar-footer" style={{ padding: '12px 16px', borderTop: '1px solid var(--border-default)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: 'var(--accent-green, #059669)',
            boxShadow: '0 0 8px #059669'
          }} />
          <span>System Online</span>
        </div>
      </div>

      <div className="sidebar-toggle">
        <button onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? '→' : '← Collapse'}
        </button>
      </div>
    </aside>
  );
}
