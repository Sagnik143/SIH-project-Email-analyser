/**
 * Alert Card Component
 */

import { useNavigate } from 'react-router-dom';
import { useEmail } from '../context/EmailContext';

export default function AlertCard({ analysis }) {
  const navigate = useNavigate();
  const { dispatch } = useEmail();

  if (!analysis) return null;

  const { threatAssessment, parsed } = analysis;
  const score = threatAssessment?.threatScore || 0;

  const getSeverityClass = (s) => {
    if (s >= 75) return 'critical';
    if (s >= 55) return 'high';
    if (s >= 35) return 'medium';
    return 'low';
  };

  const severity = getSeverityClass(score);

  const handleClick = () => {
    dispatch({ type: 'SET_CURRENT_ANALYSIS', payload: analysis });
    navigate('/reports');
  };

  return (
    <div className="alert-card" onClick={handleClick}>
      <div className={`alert-severity ${severity}`} />
      <div className="alert-content">
        <div className="alert-subject">{parsed?.subject || '(No Subject)'}</div>
        <div className="alert-meta">
          <span>From: {parsed?.from?.email || 'unknown'}</span>
          <span>{new Date(analysis.timestamp).toLocaleString()}</span>
        </div>
      </div>
      <span className={`threat-badge ${threatAssessment?.classification || 'suspicious'}`}>
        {threatAssessment?.classification || 'unknown'}
      </span>
      <span className={`alert-score ${severity}`}>
        {score}
      </span>
    </div>
  );
}
