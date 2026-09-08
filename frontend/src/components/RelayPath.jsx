/**
 * SMTP Relay Path Visualization
 */

import { getCountryFlag } from '../engine/ipIntelligence';

export default function RelayPath({ hops = [], ipResults = [] }) {
  if (hops.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-icon">🔗</div>
        <div className="empty-title">No relay path data</div>
        <div className="empty-desc">SMTP relay hops will appear here after analysis.</div>
      </div>
    );
  }

  const getIPInfo = (ip) => {
    return ipResults.find(r => r.ip === ip) || null;
  };

  return (
    <div className="relay-path">
      {hops.map((hop, index) => {
        const ipInfo = hop.ip ? getIPInfo(hop.ip) : null;
        const isFirst = index === 0;
        const isLast = index === hops.length - 1;

        return (
          <div
            className="relay-hop animate-fade-in"
            key={index}
            style={{ animationDelay: `${index * 150}ms` }}
          >
            <div className="relay-line">
              <div className={`relay-dot ${isFirst ? 'origin' : isLast ? 'destination' : ''}`} />
              {!isLast && <div className="relay-connector" />}
            </div>
            <div className="relay-info">
              <div className="relay-server">
                {isFirst ? '📤 ' : isLast ? '📥 ' : '🔄 '}
                Hop {hop.hopNumber}: {hop.by !== 'unknown' ? hop.by : hop.from}
              </div>
              <div className="relay-details">
                {hop.from !== 'unknown' && (
                  <span>From: <strong>{hop.from}</strong></span>
                )}
                {hop.by !== 'unknown' && (
                  <span> → By: <strong>{hop.by}</strong></span>
                )}
              </div>
              {hop.ip && (
                <div className="relay-details" style={{ marginTop: '4px' }}>
                  <span className="relay-ip">IP: {hop.ip}</span>
                  {ipInfo && (
                    <span style={{ marginLeft: '12px' }}>
                      {getCountryFlag(ipInfo.countryCode)} {ipInfo.city}, {ipInfo.country}
                      {ipInfo.isp !== 'Unknown' && ` • ${ipInfo.isp}`}
                    </span>
                  )}
                </div>
              )}
              {hop.protocol && (
                <div className="relay-details">
                  Protocol: <span className="badge info">{hop.protocol}</span>
                </div>
              )}
              {hop.timestamp && (
                <div className="relay-details" style={{ marginTop: '2px', fontSize: '0.7rem' }}>
                  ⏱️ {hop.timestamp}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
