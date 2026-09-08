/**
 * Geo Tracer Page
 * Full-page interactive map for IP geolocation tracing.
 */

import { useState } from 'react';
import { useEmail } from '../context/EmailContext';
import WorldMap from '../components/WorldMap';
import { lookupIP, getCountryFlag, calculateIPRiskScore } from '../engine/ipIntelligence';

export default function GeoTracer() {
  const { currentAnalysis, analyzedEmails } = useEmail();
  const [manualIP, setManualIP] = useState('');
  const [manualResults, setManualResults] = useState([]);
  const [isLooking, setIsLooking] = useState(false);
  const [selectedIP, setSelectedIP] = useState(null);

  const ipResults = currentAnalysis?.ipResults || manualResults;

  const handleLookup = async () => {
    if (!manualIP.trim()) return;
    setIsLooking(true);

    const ips = manualIP.split(/[,\n\s]+/).filter(Boolean);
    const results = [];

    for (const ip of ips.slice(0, 10)) {
      const result = await lookupIP(ip.trim());
      results.push(result);
    }

    setManualResults(prev => [...results, ...prev]);
    setIsLooking(false);
    setManualIP('');
  };

  return (
    <div>
      <div className="page-header">
        <h1>IP Location Map</h1>
        <p>See where emails came from on a world map</p>
      </div>

      {/* IP Input */}
      <div className="glass-card no-hover section-gap" style={{ padding: 'var(--space-lg)' }}>
        <div style={{ display: 'flex', gap: 'var(--space-md)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '250px' }}>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block', fontWeight: '600' }}>
              Enter IP address(es):
            </label>
            <input
              className="input"
              value={manualIP}
              onChange={(e) => setManualIP(e.target.value)}
              placeholder="e.g., 185.234.72.19, 91.234.56.78"
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            />
          </div>
          <button
            className="btn btn-primary"
            onClick={handleLookup}
            disabled={isLooking || !manualIP.trim()}
            style={{ opacity: (isLooking || !manualIP.trim()) ? 0.5 : 1 }}
          >
            {isLooking ? '⏳ Finding location...' : '🌍 Look Up'}
          </button>

          {/* Quick load from analyses */}
          {analyzedEmails.length > 0 && !currentAnalysis && (
            <div className="sample-selector" style={{ width: '100%', marginTop: 'var(--space-sm)' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Quick load from analysis:</span>
              {analyzedEmails.slice(0, 5).map(email => (
                <button
                  key={email.id}
                  className="sample-btn"
                  onClick={() => setManualResults(email.ipResults || [])}
                >
                  {email.parsed?.subject?.substring(0, 30) || email.id}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Map + Details Layout */}
      <div className="grid-2-1" style={{ gap: 'var(--space-lg)' }}>
        {/* Map */}
        <div className="glass-card no-hover" style={{ padding: 'var(--space-md)' }}>
          <WorldMap
            ipResults={ipResults}
            height="550px"
            showTrace={true}
          />
        </div>

        {/* IP Details Panel */}
        <div className="glass-card no-hover" style={{ padding: 'var(--space-lg)', maxHeight: '600px', overflowY: 'auto' }}>
          <h3 style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', fontWeight: '600', marginBottom: 'var(--space-md)' }}>
            📡 Location Details
          </h3>

          {ipResults.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-md)' }}>
              {ipResults.map((ip, i) => (
                <div
                  key={i}
                  className="glass-card"
                  style={{
                    padding: 'var(--space-md)',
                    cursor: 'pointer',
                    borderColor: selectedIP === ip.ip ? 'var(--accent-blue)' : undefined,
                  }}
                  onClick={() => setSelectedIP(selectedIP === ip.ip ? null : ip.ip)}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', fontWeight: '600', color: 'var(--accent-blue)' }}>
                        {ip.ip}
                      </div>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {getCountryFlag(ip.countryCode)} {ip.city}, {ip.country}
                      </div>
                    </div>
                    <div>
                      <span className={`badge ${calculateIPRiskScore(ip) >= 40 ? 'fail' : calculateIPRiskScore(ip) >= 20 ? 'warn' : 'pass'}`}>
                        Risk: {calculateIPRiskScore(ip)}
                      </span>
                    </div>
                  </div>

                  {selectedIP === ip.ip && (
                    <div style={{ marginTop: 'var(--space-md)', fontSize: '0.8rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-subtle)', paddingTop: 'var(--space-md)' }}>
                      <DetailRow label="ISP" value={ip.isp} />
                      <DetailRow label="Organization" value={ip.org} />
                      <DetailRow label="ASN" value={ip.as} />
                      <DetailRow label="Region" value={ip.region} />
                      <DetailRow label="Timezone" value={ip.timezone} />
                      <DetailRow label="Reverse DNS" value={ip.reverse || 'N/A'} />
                      <DetailRow label="Coordinates" value={`${ip.lat}, ${ip.lon}`} />

                      {ip.isProxy && (
                        <div style={{ color: 'var(--danger)', fontWeight: '600', marginTop: '8px' }}>
                          ⚠️ Proxy/VPN Detected
                        </div>
                      )}
                      {ip.isHosting && (
                        <div style={{ color: 'var(--warning)', fontWeight: '600', marginTop: '4px' }}>
                          ☁️ Hosting/Cloud Provider
                        </div>
                      )}

                      {ip.riskIndicators?.length > 0 && (
                        <div style={{ marginTop: '8px' }}>
                          <div style={{ fontWeight: '600', fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '4px' }}>
                            Risk Indicators:
                          </div>
                          {ip.riskIndicators.map((ind, j) => (
                            <div key={j} style={{ color: ind.severity === 'critical' ? 'var(--danger)' : ind.severity === 'high' ? 'var(--danger)' : 'var(--warning)', fontSize: '0.78rem', marginBottom: '2px' }}>
                              • {ind.description}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">🌍</div>
              <div className="empty-title">No IPs to show</div>
              <div className="empty-desc">Enter an IP address or scan an email to see location data here.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, value }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{label}:</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textAlign: 'right', maxWidth: '65%', wordBreak: 'break-all' }}>
        {value || 'N/A'}
      </span>
    </div>
  );
}
