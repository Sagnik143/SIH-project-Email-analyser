/**
 * Case Management Page
 * Track, group, and manage analyzed emails as investigation cases.
 * Connected directly to Python FastAPI & persistent Database.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useEmail } from '../context/EmailContext';

export default function CaseManagement() {
  const {
    analyzedEmails,
    cases,
    createCase,
    updateCase,
    deleteCase,
    deleteAnalysis,
    addEmailToCase,
    dispatch,
    backendConnected,
  } = useEmail();

  const navigate = useNavigate();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const handleCreateCase = async () => {
    if (newCaseName.trim()) {
      await createCase(newCaseName.trim());
      setNewCaseName('');
      setShowCreateModal(false);
    }
  };

  const filteredEmails = analyzedEmails.filter((email) => {
    const matchesSearch = searchQuery
      ? (email.parsed?.subject || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (email.parsed?.from?.email || '').toLowerCase().includes(searchQuery.toLowerCase())
      : true;

    const matchesFilter =
      filterStatus === 'all'
        ? true
        : filterStatus === 'threats'
        ? email.threatAssessment?.threatScore >= 35
        : filterStatus === 'safe'
        ? email.threatAssessment?.threatScore < 35
        : filterStatus === 'critical'
        ? email.threatAssessment?.threatScore >= 75
        : true;

    return matchesSearch && matchesFilter;
  });

  const getSeverityClass = (score) => {
    if (score >= 75) return 'critical';
    if (score >= 55) return 'high';
    if (score >= 35) return 'medium';
    return 'low';
  };

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1>My Cases</h1>
          <p>Keep track of your email investigations</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 14px', borderRadius: '20px', background: 'rgba(0,0,0,0.03)', border: '1px solid var(--border-default)', fontSize: '0.8rem' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: backendConnected ? '#059669' : '#d97706', boxShadow: backendConnected ? '0 0 8px #059669' : 'none' }} />
          <span>{backendConnected ? 'Connected to server' : 'Offline mode (data saved locally)'}</span>
        </div>
      </div>

      {/* Controls */}
      <div className="glass-card no-hover section-gap" style={{ padding: 'var(--space-lg)' }}>
        <div style={{ display: 'flex', gap: 'var(--space-md)', alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="input"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="🔍 Search by subject or sender..."
            style={{ maxWidth: '350px' }}
          />
          <select
            className="select"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
          >
            <option value="all">All Emails</option>
            <option value="threats">Threats Only</option>
            <option value="critical">Critical Only</option>
            <option value="safe">Safe Only</option>
          </select>
          <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
            + New Case
          </button>
          <button className="btn btn-ghost" onClick={() => navigate('/analyze')}>
            🔍 Analyze New Email
          </button>
        </div>
      </div>

      {/* Cases Grid */}
      {cases.length > 0 && (
        <div className="section-gap">
          <h3 style={{ marginBottom: 'var(--space-md)', fontSize: '1rem', color: 'var(--text-secondary)' }}>
            📁 Active Cases ({cases.length})
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 'var(--space-md)' }}>
            {cases.map((c) => (
              <div key={c.id} className="glass-card" style={{ padding: 'var(--space-lg)', position: 'relative' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-sm)' }}>
                  <h4 style={{ fontSize: '0.98rem', fontWeight: 600 }}>{c.name}</h4>
                  <span className={`case-status ${c.status}`}>{c.status}</span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  ID: <code style={{ color: 'var(--accent-blue)' }}>{c.id}</code> • {(c.emails || []).length} email(s) attached
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Created: {new Date(c.createdAt).toLocaleDateString()}
                </div>

                <div style={{ marginTop: 'var(--space-md)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <select
                    className="select"
                    value={c.status}
                    onChange={(e) => updateCase(c.id, { status: e.target.value })}
                    style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                  >
                    <option value="new">Status: New</option>
                    <option value="investigating">Status: Investigating</option>
                    <option value="confirmed">Status: Confirmed Threat</option>
                    <option value="resolved">Status: Resolved</option>
                    <option value="false-positive">Status: False Positive</option>
                  </select>

                  <button
                    className="btn btn-ghost btn-sm"
                    style={{ color: 'var(--danger)', fontSize: '0.75rem' }}
                    onClick={() => deleteCase(c.id)}
                    title="Delete Case"
                  >
                    🗑️ Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analyzed Emails Table */}
      <div className="glass-card no-hover" style={{ padding: 'var(--space-lg)' }}>
        <h3 style={{ marginBottom: 'var(--space-md)', fontSize: '0.95rem', color: 'var(--text-secondary)', fontWeight: '600' }}>
          📧 Scanned Emails ({filteredEmails.length})
        </h3>

        {filteredEmails.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Score</th>
                  <th>Classification</th>
                  <th>Subject</th>
                  <th>Sender</th>
                  <th>Date</th>
                  <th>Assign Case</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredEmails.map((email) => {
                  const score = email.threatAssessment?.threatScore || 0;
                  return (
                    <tr key={email.id}>
                      <td>
                        <span className={`alert-score ${getSeverityClass(score)}`}>{score}</span>
                      </td>
                      <td>
                        <span className={`threat-badge ${email.threatAssessment?.classification || 'suspicious'}`}>
                          {email.threatAssessment?.classification || 'unknown'}
                        </span>
                      </td>
                      <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {email.parsed?.subject || '(No Subject)'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                        {email.parsed?.from?.email || 'unknown'}
                      </td>
                      <td style={{ fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                        {new Date(email.timestamp).toLocaleDateString()}
                      </td>
                      <td>
                        {cases.length > 0 ? (
                          <select
                            className="select"
                            style={{ fontSize: '0.72rem', padding: '3px 6px', maxWidth: '140px' }}
                            defaultValue=""
                            onChange={(e) => {
                              if (e.target.value) {
                                addEmailToCase(e.target.value, email.id);
                                e.target.value = "";
                              }
                            }}
                          >
                            <option value="" disabled>+ Add to Case</option>
                            {cases.map((cs) => (
                              <option key={cs.id} value={cs.id}>{cs.name}</option>
                            ))}
                          </select>
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>No cases</span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => {
                              dispatch({ type: 'SET_CURRENT_ANALYSIS', payload: email });
                              navigate('/reports');
                            }}
                            title="View Forensic Report"
                          >
                            📋 Report
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => {
                              dispatch({ type: 'SET_CURRENT_ANALYSIS', payload: email });
                              navigate('/geo-tracer');
                            }}
                            title="View Geo Path"
                          >
                            🌍
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            style={{ color: 'var(--danger)' }}
                            onClick={() => deleteAnalysis(email.id)}
                            title="Delete Report from DB"
                          >
                            🗑️
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">📁</div>
            <div className="empty-title">No emails in database</div>
            <div className="empty-desc">
              {searchQuery ? 'No results match your search.' : 'Scan emails to build your case database.'}
            </div>
            <button className="btn btn-primary" style={{ marginTop: '16px' }} onClick={() => navigate('/analyze')}>
              🔍 Scan First Email
            </button>
          </div>
        )}
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="analyzing-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="glass-card" style={{ padding: 'var(--space-xl)', minWidth: '400px', maxWidth: '500px' }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginBottom: 'var(--space-lg)' }}>📁 Create New Case</h3>
            <input
              className="input"
              value={newCaseName}
              onChange={(e) => setNewCaseName(e.target.value)}
              placeholder="e.g. PayPal Phishing Campaign Q3"
              onKeyDown={(e) => e.key === 'Enter' && handleCreateCase()}
              autoFocus
            />
            <div style={{ marginTop: 'var(--space-lg)', display: 'flex', gap: 'var(--space-md)', justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setShowCreateModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreateCase} disabled={!newCaseName.trim()}>Create Case</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
