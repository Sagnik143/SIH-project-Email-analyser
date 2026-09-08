/**
 * Email Analyzer Page
 * Input email, run analysis, view results.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useEmail } from '../context/EmailContext';
import EmailInput from '../components/EmailInput';
import ThreatGauge from '../components/ThreatGauge';
import AuthBadges from '../components/AuthBadges';
import RelayPath from '../components/RelayPath';

export default function EmailAnalyzer() {
  const { analyzeEmail, isAnalyzing, analysisStep, currentAnalysis, error, dispatch } = useEmail();
  const [activeTab, setActiveTab] = useState('overview');
  const navigate = useNavigate();

  const handleAnalyze = async (rawEmail) => {
    try {
      await analyzeEmail(rawEmail);
    } catch (e) {
      console.error('Analysis failed:', e);
    }
  };

  const result = currentAnalysis;

  return (
    <div>
      <div className="page-header">
        <h1>Check an Email</h1>
        <p>Paste or upload an email to check if it's safe</p>
      </div>

      {/* Analyzing Overlay */}
      {isAnalyzing && (
        <div className="analyzing-overlay">
          <div className="analyzing-spinner" />
          <div className="analyzing-text">Scanning email...</div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="glass-card" style={{ padding: 'var(--space-lg)', marginBottom: 'var(--space-lg)', borderColor: 'var(--danger)' }}>
          <span style={{ color: 'var(--danger)' }}>❌ Error: {error}</span>
        </div>
      )}

      {/* Email Input */}
      <div className="glass-card no-hover" style={{ padding: 'var(--space-lg)', marginBottom: 'var(--space-xl)' }}>
        <EmailInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />
      </div>

      {/* Results */}
      {result && (
        <div className="animate-fade-in-up">
          {/* Score + Classification Header */}
          <div className="glass-card section-gap" style={{ padding: 'var(--space-xl)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2xl)', flexWrap: 'wrap' }}>
              <ThreatGauge score={result.threatAssessment?.threatScore || 0} />

              <div style={{ flex: 1, minWidth: '300px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-md)', marginBottom: 'var(--space-md)', flexWrap: 'wrap' }}>
                  <span className={`threat-badge ${result.threatAssessment?.classification || 'suspicious'}`}>
                    {result.threatAssessment?.classification || 'Unknown'}
                  </span>
                  <span className="badge info">
                    Confidence: {result.threatAssessment?.confidence || 0}%
                  </span>
                  <span className="badge" style={{ background: 'rgba(5, 150, 105, 0.1)', color: '#059669', border: '1px solid rgba(5, 150, 105, 0.25)', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                    💾 Saved: {result.id}
                  </span>
                </div>

                <h3 style={{ marginBottom: 'var(--space-sm)' }}>{result.parsed?.subject}</h3>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>
                  From: <strong style={{ color: 'var(--text-primary)' }}>{result.parsed?.from?.raw || 'Unknown'}</strong>
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-md)' }}>
                  To: <strong style={{ color: 'var(--text-primary)' }}>{result.parsed?.to?.raw || 'Unknown'}</strong>
                </div>

                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                  {result.threatAssessment?.summary}
                </p>

                {/* Recommendation */}
                {result.threatAssessment?.recommendation && (
                  <div style={{
                    marginTop: 'var(--space-md)',
                    padding: 'var(--space-md)',
                    borderRadius: 'var(--radius-md)',
                    background: result.threatAssessment.recommendation.color === 'danger' ? 'var(--danger-dim)' :
                                result.threatAssessment.recommendation.color === 'warning' ? 'var(--warning-dim)' :
                                result.threatAssessment.recommendation.color === 'success' ? 'var(--success-dim)' : 'var(--accent-blue-dim)',
                    borderLeft: `3px solid ${result.threatAssessment.recommendation.color === 'danger' ? 'var(--danger)' :
                                            result.threatAssessment.recommendation.color === 'warning' ? 'var(--warning)' :
                                            result.threatAssessment.recommendation.color === 'success' ? 'var(--success)' : 'var(--accent-blue)'}`,
                  }}>
                    <div style={{ fontWeight: '700', fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '4px' }}>
                      What to do: {result.threatAssessment.recommendation.action}
                    </div>
                    <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      {result.threatAssessment.recommendation.text}
                    </div>
                  </div>
                )}

                <div style={{ marginTop: 'var(--space-md)', display: 'flex', gap: 'var(--space-sm)' }}>
                  <button className="btn btn-primary btn-sm" onClick={() => {
                    dispatch({ type: 'SET_CURRENT_ANALYSIS', payload: result });
                    navigate('/reports');
                  }}>
                    📋 View Full Report
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => {
                    dispatch({ type: 'SET_CURRENT_ANALYSIS', payload: result });
                    navigate('/geo-tracer');
                  }}>
                    🌍 See on Map
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="tabs">
            {['overview', 'headers', 'nlp', 'links', 'authentication'].map(tab => (
              <button
                key={tab}
                className={`tab ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab === 'overview' && '📊 Summary'}
                {tab === 'headers' && '📨 Route Info'}
                {tab === 'nlp' && '🧠 Language Clues'}
                {tab === 'links' && '🔗 Links Found'}
                {tab === 'authentication' && '🔐 Verification'}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="glass-card no-hover" style={{ padding: 'var(--space-lg)' }}>
            {activeTab === 'overview' && <OverviewTab result={result} />}
            {activeTab === 'headers' && <HeadersTab result={result} />}
            {activeTab === 'nlp' && <NLPTab result={result} />}
            {activeTab === 'links' && <LinksTab result={result} />}
            {activeTab === 'authentication' && <AuthTab result={result} />}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Tab Components ── */

function OverviewTab({ result }) {
  return (
    <div>
      <h4 style={{ marginBottom: 'var(--space-md)' }}>🔍 What We Found</h4>
      {result.threatAssessment?.findings?.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
          {result.threatAssessment.findings.map((finding, i) => (
            <div key={i} className={`nlp-finding ${finding.severity}`}>
              <div>
                <div style={{ fontWeight: '700', fontSize: '0.85rem', marginBottom: '4px' }}>
                  {finding.category}
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                  {finding.description}
                </div>
                {finding.details && finding.details.length > 0 && (
                  <ul style={{ marginTop: '6px', paddingLeft: '16px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {finding.details.slice(0, 5).map((d, j) => (
                      <li key={j}>{d}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <div className="empty-title">No significant findings</div>
          <div className="empty-desc">This email does not exhibit notable threat indicators.</div>
        </div>
      )}

      {/* Score Breakdown */}
      <h4 style={{ marginTop: 'var(--space-xl)', marginBottom: 'var(--space-md)' }}>📊 Risk Breakdown</h4>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-md)' }}>
        {Object.entries(result.threatAssessment?.scores || {}).map(([key, value]) => (
          <div key={key} style={{
            padding: 'var(--space-md)',
            background: 'rgba(0,0,0,0.02)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-subtle)',
          }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              {key.replace(/([A-Z])/g, ' $1').trim()}
            </div>
            <div style={{ fontSize: '1.5rem', fontWeight: '800', color: getScoreColor(value), marginTop: '4px' }}>
              {Math.round(value)}
            </div>
            <div style={{ height: '4px', borderRadius: '2px', background: 'rgba(0,0,0,0.06)', marginTop: '8px' }}>
              <div style={{
                height: '100%',
                borderRadius: '2px',
                width: `${Math.min(100, value)}%`,
                background: getScoreColor(value),
                transition: 'width 1s ease-out',
              }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function HeadersTab({ result }) {
  return (
    <div>
      <h4 style={{ marginBottom: 'var(--space-md)' }}>📨 Email Route</h4>
      <RelayPath hops={result.relayPath || []} ipResults={result.ipResults || []} />

      {/* Header Anomalies */}
      {result.headerAnomalies?.length > 0 && (
        <>
          <h4 style={{ marginTop: 'var(--space-xl)', marginBottom: 'var(--space-md)' }}>⚠️ Header Anomalies</h4>
          {result.headerAnomalies.map((anomaly, i) => (
            <div key={i} className={`nlp-finding ${anomaly.severity === 'high' ? 'danger' : anomaly.severity === 'info' ? 'info' : ''}`}>
              <div>
                <div style={{ fontWeight: '700', fontSize: '0.85rem' }}>{anomaly.type.replace(/_/g, ' ')}</div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{anomaly.description}</div>
              </div>
            </div>
          ))}
        </>
      )}

      {/* Raw Headers */}
      <h4 style={{ marginTop: 'var(--space-xl)', marginBottom: 'var(--space-md)' }}>📋 Parsed Headers</h4>
      <div style={{ maxHeight: '400px', overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr><th>Header</th><th>Value</th></tr>
          </thead>
          <tbody>
            {Object.entries(result.parsed?.headers || {}).map(([key, value], i) => (
              <tr key={i}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-blue)', whiteSpace: 'nowrap' }}>{key}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', wordBreak: 'break-all' }}>
                  {Array.isArray(value) ? value.join('\n') : String(value)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function NLPTab({ result }) {
  const nlp = result.nlpResult;
  if (!nlp) return <div className="empty-state"><div className="empty-title">No NLP data</div></div>;

  return (
    <div>
      <h4 style={{ marginBottom: 'var(--space-md)' }}>🧠 Content Analysis</h4>

      {/* Sentiment Bars */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-md)', marginBottom: 'var(--space-xl)' }}>
        {[
          { label: 'Fear/Threat', score: nlp.sentiment?.fearScore || 0, color: '#dc2626' },
          { label: 'Urgency', score: nlp.sentiment?.urgencyScore || 0, color: '#d97706' },
          { label: 'Authority', score: nlp.sentiment?.authorityScore || 0, color: '#7c3aed' },
          { label: 'Reward/Lure', score: nlp.sentiment?.rewardScore || 0, color: '#2563eb' },
          { label: 'Manipulation', score: nlp.sentiment?.manipulationScore || 0, color: '#be185d' },
        ].map(item => (
          <div key={item.label} style={{ padding: 'var(--space-md)', background: 'rgba(0,0,0,0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '6px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
              <span style={{ color: item.color, fontWeight: '700' }}>{item.score}%</span>
            </div>
            <div style={{ height: '6px', borderRadius: '3px', background: 'rgba(0,0,0,0.06)' }}>
              <div style={{ height: '100%', borderRadius: '3px', width: `${item.score}%`, background: item.color, transition: 'width 1s ease-out' }} />
            </div>
          </div>
        ))}
      </div>

      {/* NLP Findings */}
      <h4 style={{ marginBottom: 'var(--space-md)' }}>🔍 Detected Patterns</h4>
      {nlp.findings?.length > 0 ? (
        nlp.findings.map((finding, i) => (
          <div key={i} className={`nlp-finding ${finding.severity}`} style={{ marginBottom: 'var(--space-sm)' }}>
            <div>
              <div style={{ fontWeight: '700', fontSize: '0.85rem', marginBottom: '4px' }}>{finding.category}</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{finding.description}</div>
              {finding.details?.length > 0 && (
                <ul style={{ marginTop: '6px', paddingLeft: '16px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  {finding.details.map((d, j) => <li key={j}>{d}</li>)}
                </ul>
              )}
            </div>
          </div>
        ))
      ) : (
        <div className="empty-state"><div className="empty-title">No suspicious patterns detected</div></div>
      )}
    </div>
  );
}

function LinksTab({ result }) {
  const links = result.linkResult;
  if (!links || links.totalLinks === 0) {
    return <div className="empty-state"><div className="empty-icon">🔗</div><div className="empty-title">No links found in email</div></div>;
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 'var(--space-md)', marginBottom: 'var(--space-lg)' }}>
        <span className="badge info">Total: {links.totalLinks}</span>
        {links.highRiskLinks > 0 && <span className="badge fail">High Risk: {links.highRiskLinks}</span>}
      </div>

      <table className="data-table">
        <thead>
          <tr><th>URL</th><th>Risk Score</th><th>Indicators</th></tr>
        </thead>
        <tbody>
          {links.urls.map((urlInfo, i) => (
            <tr key={i}>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', wordBreak: 'break-all', maxWidth: '400px' }}>
                {urlInfo.url}
              </td>
              <td>
                <span className={`badge ${urlInfo.isHighRisk ? 'fail' : urlInfo.riskScore >= 30 ? 'warn' : 'pass'}`}>
                  {urlInfo.riskScore}
                </span>
              </td>
              <td style={{ fontSize: '0.78rem' }}>
                {urlInfo.indicators.map((ind, j) => (
                  <div key={j} style={{ color: ind.severity === 'high' || ind.severity === 'critical' ? 'var(--danger)' : 'var(--warning)', marginBottom: '2px' }}>
                    • {ind.description}
                  </div>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuthTab({ result }) {
  return (
    <div>
      <h4 style={{ marginBottom: 'var(--space-lg)' }}>🔐 Email Verification</h4>
      <AuthBadges authResult={result.authResult} />

      <div style={{ marginTop: 'var(--space-xl)', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.7' }}>
        <p>{result.authResult?.summary}</p>
      </div>

      {/* Details table */}
      <div style={{ marginTop: 'var(--space-lg)' }}>
        <table className="data-table">
          <thead><tr><th>Protocol</th><th>Status</th><th>Details</th></tr></thead>
          <tbody>
            <tr>
              <td style={{ fontWeight: '700' }}>SPF</td>
              <td><span className={`badge ${result.authResult?.spf?.status === 'pass' ? 'pass' : result.authResult?.spf?.status === 'fail' ? 'fail' : 'warn'}`}>{result.authResult?.spf?.status}</span></td>
              <td style={{ fontSize: '0.8rem' }}>{result.authResult?.spf?.details}</td>
            </tr>
            <tr>
              <td style={{ fontWeight: '700' }}>DKIM</td>
              <td><span className={`badge ${result.authResult?.dkim?.status === 'pass' ? 'pass' : result.authResult?.dkim?.status === 'fail' ? 'fail' : 'warn'}`}>{result.authResult?.dkim?.status}</span></td>
              <td style={{ fontSize: '0.8rem' }}>{result.authResult?.dkim?.details}</td>
            </tr>
            <tr>
              <td style={{ fontWeight: '700' }}>DMARC</td>
              <td><span className={`badge ${result.authResult?.dmarc?.status === 'pass' ? 'pass' : result.authResult?.dmarc?.status === 'fail' ? 'fail' : 'warn'}`}>{result.authResult?.dmarc?.status}</span></td>
              <td style={{ fontSize: '0.8rem' }}>{result.authResult?.dmarc?.details}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

function getScoreColor(value) {
  if (value >= 60) return '#dc2626';
  if (value >= 35) return '#d97706';
  if (value >= 15) return '#2563eb';
  return '#059669';
}
