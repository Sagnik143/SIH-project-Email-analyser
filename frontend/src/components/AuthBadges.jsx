/**
 * Authentication Badges (SPF/DKIM/DMARC)
 */

export default function AuthBadges({ authResult }) {
  if (!authResult) return null;

  const getStatusClass = (status) => {
    if (['pass'].includes(status)) return 'pass';
    if (['fail'].includes(status)) return 'fail';
    if (['softfail', 'neutral', 'present', 'bestguesspass'].includes(status)) return 'warn';
    return 'none';
  };

  const getStatusIcon = (status) => {
    if (status === 'pass') return '✅';
    if (status === 'fail') return '❌';
    if (['softfail', 'neutral'].includes(status)) return '⚠️';
    if (status === 'present' || status === 'bestguesspass') return '🔶';
    return '⬜';
  };

  const items = [
    { label: 'SPF', data: authResult.spf },
    { label: 'DKIM', data: authResult.dkim },
    { label: 'DMARC', data: authResult.dmarc },
  ];

  return (
    <div className="auth-badges">
      {items.map(({ label, data }) => (
        <div key={label} className={`auth-badge-card glass-card`}>
          <div>
            <div className="auth-label">{label}</div>
            <div className={`auth-status`} style={{ color: getStatusColor(data.status) }}>
              {getStatusIcon(data.status)} {data.status.toUpperCase()}
            </div>
          </div>
          <div className="tooltip-wrapper" style={{ marginLeft: 'auto' }}>
            <span className={`badge ${getStatusClass(data.status)}`}>
              {data.status}
            </span>
            <span className="tooltip-text">{data.details}</span>
          </div>
        </div>
      ))}

      <div className="auth-badge-card glass-card">
        <div>
          <div className="auth-label">Auth Score</div>
          <div className="auth-status" style={{ color: getScoreColor(authResult.overallScore), fontSize: '1.2rem', fontWeight: '800' }}>
            {authResult.overallScore}/100
          </div>
        </div>
      </div>
    </div>
  );
}

function getStatusColor(status) {
  if (status === 'pass') return '#059669';
  if (status === 'fail') return '#dc2626';
  if (['softfail', 'neutral'].includes(status)) return '#d97706';
  if (status === 'present' || status === 'bestguesspass') return '#2563eb';
  return '#718096';
}

function getScoreColor(score) {
  if (score >= 80) return '#059669';
  if (score >= 50) return '#d97706';
  if (score >= 20) return '#ea580c';
  return '#dc2626';
}
