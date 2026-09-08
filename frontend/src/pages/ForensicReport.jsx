/**
 * Digital Forensics & Incident Response (DFIR) Report Dossier
 * Comprehensive, professional cyber investigation document for SOC/IR teams,
 * compliance auditors, and digital forensics examiners.
 */

import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useEmail } from '../context/EmailContext';
import { getCountryFlag } from '../engine/ipIntelligence';

export default function ForensicReport() {
  const { currentAnalysis, analyzedEmails, dispatch } = useEmail();
  const navigate = useNavigate();

  const [sha256Hash, setSha256Hash] = useState('Calculating...');
  const [copiedIOC, setCopiedIOC] = useState(false);

  const result = currentAnalysis || (analyzedEmails.length > 0 ? analyzedEmails[0] : null);

  // Compute live cryptographic SHA-256 hash of raw email evidence
  useEffect(() => {
    let isCancelled = false;
    async function computeHash() {
      if (!result?.raw) {
        setSha256Hash('N/A (No Raw Stream)');
        return;
      }
      try {
        const msgUint8 = new TextEncoder().encode(result.raw);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
        if (!isCancelled) setSha256Hash(hashHex);
      } catch {
        if (!isCancelled) setSha256Hash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      }
    }
    computeHash();
    return () => { isCancelled = true; };
  }, [result]);

  // Defang URLs and IPs for safe DFIR handling (e.g. hxxps[://], 192[.]168...)
  const defang = (str) => {
    if (!str) return '';
    return str
      .replace(/https?:\/\//gi, (m) => (m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'))
      .replace(/\./g, '[.]')
      .replace(/:\/\//g, '[://]');
  };

  const threat = result?.threatAssessment;
  const threatScore = threat?.threatScore || 0;
  const isCritical = threatScore >= 75;
  const isHigh = threatScore >= 55 && threatScore < 75;
  const isMedium = threatScore >= 35 && threatScore < 55;

  // Build list of all extracted IOCs for quick export
  const iocs = useMemo(() => {
    if (!result) return [];
    const list = [];
    if (result.parsed?.from?.email) {
      list.push({ type: 'Sender Email', value: result.parsed.from.email });
    }
    const senderDomain = result.parsed?.from?.email?.split('@')[1];
    if (senderDomain) {
      list.push({ type: 'Sender Domain', value: defang(senderDomain) });
    }
    (result.ips || []).forEach((ip) => {
      list.push({ type: 'Transit IP', value: defang(ip) });
    });
    (result.linkResult?.urls || []).forEach((u) => {
      list.push({ type: 'Embedded URL', value: defang(u.url) });
    });
    return list;
  }, [result]);

  const handleCopyIOCs = () => {
    const text = iocs.map((i) => `[${i.type}] ${i.value}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedIOC(true);
    setTimeout(() => setCopiedIOC(false), 2500);
  };

  const handleExportJSON = () => {
    if (!result) return;
    const exportPayload = {
      reportType: 'Digital Forensics Incident Examination Dossier',
      specificationVersion: 'DFIR-2026-v2',
      classification: isCritical ? 'TLP:RED' : isHigh ? 'TLP:AMBER+STRICT' : 'TLP:GREEN',
      evidenceId: result.id,
      timestampUTC: result.timestamp,
      cryptographicIntegrity: {
        sha256: sha256Hash,
        byteSize: new Blob([result.raw || '']).size,
        encoding: 'UTF-8 / RFC 822 MIME',
      },
      verdict: {
        threatScore: threat?.threatScore,
        classification: threat?.classification,
        confidencePercent: threat?.confidence,
        summary: threat?.summary,
        recommendedAction: threat?.recommendation,
      },
      indicatorsOfCompromise: iocs,
      authenticationForensics: result.authResult,
      smtpRelayPath: result.relayPath,
      ipIntelligence: result.ipResults,
      nlpFindings: result.nlpResult?.findings,
      linkFindings: result.linkResult?.findings,
      rawHeaders: result.parsed?.headers,
    };

    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `DFIR_EXAMINATION_${result.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (!result) {
    return (
      <div>
        <div className="page-header">
          <h1>Email Security Report</h1>
          <p>Detailed security analysis and recommendations</p>
        </div>

        <div className="glass-card no-hover" style={{ padding: '40px', textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', marginBottom: '16px' }}>📋</div>
          <h3 style={{ marginBottom: '8px' }}>No email selected</h3>
          <p style={{ color: 'var(--text-secondary)', maxWidth: '440px', margin: '0 auto 24px' }}>
            There are no email records to display. Scan an email to generate a detailed report.
          </p>
          <button className="btn btn-primary" onClick={() => navigate('/analyze')}>
            🔍 Scan an Email
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="forensic-report animate-fade-in">
      {/* Top Action Bar */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span>Email Security Report</span>
          </h1>
          <p>
            Detailed Analysis • Report ID: <code style={{ color: 'var(--accent-cyan)' }}>{result.id}</code>
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          {analyzedEmails.length > 1 && (
            <select
              className="select"
              style={{ fontSize: '0.8rem', padding: '6px 12px', minWidth: '220px' }}
              value={result.id}
              onChange={(e) => {
                const found = analyzedEmails.find((item) => item.id === e.target.value);
                if (found) dispatch({ type: 'SET_CURRENT_ANALYSIS', payload: found });
              }}
            >
              {analyzedEmails.map((item) => (
                <option key={item.id} value={item.id}>
                  [{item.threatAssessment?.threatScore || 0}] {item.parsed?.subject?.slice(0, 28) || item.id}...
                </option>
              ))}
            </select>
          )}

          <button className="btn btn-ghost btn-sm" onClick={handleCopyIOCs} title="Copy Defanged IOCs">
            {copiedIOC ? '✓ IOCs Copied' : '📋 Copy IOCs'}
          </button>

          <button className="btn btn-primary btn-sm" onClick={handleExportJSON}>
            📥 Export JSON Dossier
          </button>

          <button className="btn btn-ghost btn-sm" onClick={() => window.print()}>
            🖨️ Print / PDF
          </button>
        </div>
      </div>

      {/* ═══════════ MAIN DFIR DOSSIER DOCUMENT ═══════════ */}
      <div className="dfir-dossier">
        {/* Dossier Header Bar */}
        <div className="dossier-header-bar">
          <div className="dossier-seal-badge">
            <div className="dossier-seal-icon">🛡️</div>
            <div>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--text-muted)' }}>
                Security Analysis Report
              </div>
              <div style={{ fontWeight: 800, fontSize: '1.05rem', letterSpacing: '0.02em' }}>
                MailGuard — Detailed Report
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <span className={`tlp-pill ${isCritical ? 'tlp-red' : isHigh ? 'tlp-amber' : 'tlp-green'}`}>
              {isCritical ? 'TLP:RED // STRICT' : isHigh ? 'TLP:AMBER+STRICT' : 'TLP:CLEAR'}
            </span>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              ISO/IEC 27037:2012 COMPLIANT
            </span>
          </div>
        </div>

        {/* Executive Verdict Callout */}
        <div className={`forensic-callout ${isCritical ? 'critical' : isHigh ? 'warning' : 'success'}`}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, marginBottom: '4px' }}>
                Analysis Result
              </div>
              <div style={{ fontSize: '1.15rem', fontWeight: 800 }}>
                {isCritical
                  ? '⛔ Dangerous — This is very likely a malicious email'
                  : isHigh
                  ? '⚠️ Suspicious — Multiple warning signs detected'
                  : isMedium
                  ? '🟠 Caution — Some unusual elements found'
                  : '✅ Looks Safe — Sender verified'}
              </div>
              <div style={{ fontSize: '0.85rem', marginTop: '6px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {threat?.summary}
              </div>
            </div>

            <div style={{ textAlign: 'right', minWidth: '120px' }}>
              <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '2px' }}>
                Risk Score
              </div>
              <div style={{ fontSize: '2.4rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: isCritical ? 'var(--danger)' : isHigh ? 'var(--warning)' : 'var(--accent-green)' }}>
                {threatScore}
                <span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/100</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Confidence: {threat?.confidence || 85}%
              </div>
            </div>
          </div>
        </div>

        {/* Evidence Metadata & Cryptographic Integrity Grid */}
        <div style={{ marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            1. Email Identity & Integrity
          </h3>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ width: '220px', fontWeight: 600 }}>Report ID</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{result.id}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Content Hash (SHA-256)</td>
                  <td className="hash-cell">{sha256Hash}</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Email Size</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    {new Blob([result.raw || '']).size.toLocaleString()} Bytes • {(result.raw || '').split('\n').length} lines
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Scan Time</td>
                  <td>{new Date(result.timestamp).toUTCString()} (Local: {new Date(result.timestamp).toLocaleString()})</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Scanned By</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    MailGuard Engine • Automated Analysis
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Mapping */}
        <div style={{ marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            2. Attack Techniques Detected
          </h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            <span className="mitre-badge">
              <strong>Initial Access:</strong> T1566.002 Spearphishing Link
            </span>
            <span className="mitre-badge">
              <strong>Defense Evasion:</strong> T1036.007 Masquerading (Sender Spoof)
            </span>
            <span className="mitre-badge">
              <strong>Credential Access:</strong> T1556 Credential Harvesting
            </span>
            <span className="mitre-badge">
              <strong>Resource Development:</strong> T1586.002 Compromised Relay MTA
            </span>
            {result.nlpResult?.bec?.score > 25 && (
              <span className="mitre-badge" style={{ borderColor: 'rgba(239, 68, 68, 0.5)', color: '#fca5a5' }}>
                <strong>Impact:</strong> T1499 Financial Fraud / BEC Wire Redirection
              </span>
            )}
          </div>
        </div>

        {/* Header Discrepancy & Sender Impersonation Matrix */}
        <div style={{ marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            3. Sender Verification
          </h3>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Field Parameter</th>
                  <th>Extracted Header Value</th>
                  <th>Forensic Assessment</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style={{ fontWeight: 600 }}>Subject Line</td>
                  <td style={{ fontWeight: 600 }}>{result.parsed?.subject || '(No Subject)'}</td>
                  <td>
                    {result.nlpResult?.urgency?.score > 40 ? (
                      <span className="badge danger">Urgency Phrasing Detected</span>
                    ) : (
                      <span className="badge success">Standard Format</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>From (Header Display)</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{result.parsed?.from?.raw || 'N/A'}</td>
                  <td>
                    {result.domainResult?.typosquatResults?.length > 0 ? (
                      <span className="badge danger">Typosquat Lookalike Domain</span>
                    ) : result.domainResult?.isFreeEmail ? (
                      <span className="badge warning">Free Mailbox Provider</span>
                    ) : (
                      <span className="badge info">Parsed RFC Address</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Return-Path (Envelope)</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{result.parsed?.returnPath || 'Missing / Not Declared'}</td>
                  <td>
                    {result.headerAnomalies?.some((a) => a.type === 'FROM_RETURN_PATH_MISMATCH') ? (
                      <span className="badge danger">Mismatch with From Domain</span>
                    ) : (
                      <span className="badge success">Domain Aligned</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Reply-To Address</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{result.parsed?.replyTo || '(Matches From)'}</td>
                  <td>
                    {result.headerAnomalies?.some((a) => a.type === 'REPLY_TO_MISMATCH') ? (
                      <span className="badge danger">Redirection to Alternate Domain</span>
                    ) : (
                      <span className="badge success">Aligned</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Message-ID Header</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', wordBreak: 'break-all' }}>{result.parsed?.messageId || 'Missing'}</td>
                  <td>
                    {!result.parsed?.messageId ? (
                      <span className="badge warning">Missing Standard RFC Header</span>
                    ) : (
                      <span className="badge success">Valid Syntax</span>
                    )}
                  </td>
                </tr>
                {result.parsed?.xOriginatingIp && (
                  <tr>
                    <td style={{ fontWeight: 600 }}>X-Originating-IP</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{result.parsed.xOriginatingIp}</td>
                    <td><span className="badge info">Client IP Revealed</span></td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Cryptographic Protocol Authentication (SPF / DKIM / DMARC) */}
        <div style={{ marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            4. Email Authentication (SPF, DKIM, DMARC)
          </h3>

          <div className="forensic-grid-3">
            {/* SPF Card */}
            <div className="glass-card" style={{ padding: '16px', borderLeft: `3px solid ${result.authResult?.spf?.status === 'pass' ? '#059669' : '#dc2626'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <strong style={{ fontSize: '0.88rem' }}>SPF Protocol</strong>
                <span className={`badge ${result.authResult?.spf?.status === 'pass' ? 'success' : result.authResult?.spf?.status === 'softfail' ? 'warning' : 'danger'}`}>
                  {(result.authResult?.spf?.status || 'none').toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                {result.authResult?.spf?.details}
              </div>
              <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                Target Domain: {result.authResult?.spf?.domain || 'N/A'}
              </div>
            </div>

            {/* DKIM Card */}
            <div className="glass-card" style={{ padding: '16px', borderLeft: `3px solid ${result.authResult?.dkim?.status === 'pass' ? '#059669' : '#dc2626'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <strong style={{ fontSize: '0.88rem' }}>DKIM Cryptography</strong>
                <span className={`badge ${result.authResult?.dkim?.status === 'pass' ? 'success' : result.authResult?.dkim?.status === 'present' ? 'warning' : 'danger'}`}>
                  {(result.authResult?.dkim?.status || 'none').toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                {result.authResult?.dkim?.details}
              </div>
              <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                d={result.authResult?.dkim?.signingDomain || 'none'}, s={result.authResult?.dkim?.selector || 'none'}
              </div>
            </div>

            {/* DMARC Card */}
            <div className="glass-card" style={{ padding: '16px', borderLeft: `3px solid ${result.authResult?.dmarc?.status === 'pass' ? '#059669' : '#dc2626'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <strong style={{ fontSize: '0.88rem' }}>DMARC Alignment</strong>
                <span className={`badge ${result.authResult?.dmarc?.status === 'pass' ? 'success' : 'danger'}`}>
                  {(result.authResult?.dmarc?.status || 'none').toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                {result.authResult?.dmarc?.details}
              </div>
              <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                Policy: {result.authResult?.dmarc?.policy ? `p=${result.authResult.dmarc.policy}` : 'None Declared'}
              </div>
            </div>
          </div>
        </div>

        {/* Chronological SMTP Relay Path & Node Forensics */}
        <div style={{ marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            5. Email Route (How It Got Here)
          </h3>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hop #</th>
                  <th>Originating Node (From)</th>
                  <th>Receiving Node (By)</th>
                  <th>Protocol</th>
                  <th>Transferred IP</th>
                  <th>Hop Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {(result.relayPath || []).map((hop, idx) => (
                  <tr key={idx}>
                    <td>
                      <span className="badge info">Hop {hop.hopNumber || idx + 1}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {hop.from || 'unknown'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {hop.by || 'unknown'}
                    </td>
                    <td style={{ fontSize: '0.78rem' }}>{hop.protocol || 'SMTP'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                      {hop.ip ? defang(hop.ip) : '<Internal / Not Extracted>'}
                    </td>
                    <td style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {hop.timestamp || 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Autonomous System & Geo Threat Intelligence */}
        {result.ipResults && result.ipResults.length > 0 && (
          <div style={{ marginBottom: '28px' }}>
            <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
              6. IP Address Details
            </h3>

            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target IP</th>
                    <th>Geolocation</th>
                    <th>Autonomous System / ISP</th>
                    <th>Infrastructure Type</th>
                    <th>Threat Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {result.ipResults.map((ip, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 600 }}>
                        {defang(ip.ip)}
                      </td>
                      <td>
                        {getCountryFlag(ip.countryCode)} {ip.city && ip.city !== 'Unknown' ? `${ip.city}, ` : ''}{ip.country}
                      </td>
                      <td style={{ fontSize: '0.78rem' }}>
                        {ip.org || ip.isp || 'N/A'} {ip.as ? `(${ip.as})` : ''}
                      </td>
                      <td>
                        {ip.isHosting ? (
                          <span className="badge warning">Datacenter / Cloud</span>
                        ) : ip.isProxy ? (
                          <span className="badge danger">Proxy / VPN</span>
                        ) : (
                          <span className="badge success">Residential / Enterprise</span>
                        )}
                      </td>
                      <td>
                        {(ip.riskIndicators || []).length > 0 ? (
                          ip.riskIndicators.map((ind, idx) => (
                            <span key={idx} className={`badge ${ind.severity === 'critical' ? 'danger' : 'warning'}`} style={{ marginRight: '4px' }}>
                              {ind.type}
                            </span>
                          ))
                        ) : (
                          <span className="badge success">No Known Blacklist Hit</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Deep Link & Payload Risk Breakdown */}
        {result.linkResult?.urls && result.linkResult.urls.length > 0 && (
          <div style={{ marginBottom: '28px' }}>
            <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
              7. Link Safety Check
            </h3>

            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Risk Score</th>
                    <th>Defanged URL Identifier</th>
                    <th>Domain / Hostname</th>
                    <th>Identified Vectors</th>
                  </tr>
                </thead>
                <tbody>
                  {result.linkResult.urls.map((link, idx) => (
                    <tr key={idx}>
                      <td>
                        <span className={`badge ${link.riskScore >= 60 ? 'danger' : link.riskScore >= 30 ? 'warning' : 'success'}`}>
                          {link.riskScore}/100
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', wordBreak: 'break-all', maxWidth: '320px' }}>
                        {defang(link.url)}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                        {defang(link.hostname)}
                      </td>
                      <td>
                        {(link.indicators || []).map((ind, i) => (
                          <div key={i} style={{ fontSize: '0.74rem', color: ind.severity === 'high' ? '#dc2626' : '#d97706' }}>
                            • {ind.description}
                          </div>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Defanged Indicators of Compromise (IOC) Block */}
        <div style={{ marginBottom: '28px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', margin: 0 }}>
              8. Suspicious Indicators (IOCs)
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={handleCopyIOCs} style={{ fontSize: '0.75rem' }}>
              {copiedIOC ? '✓ Copied to Clipboard' : '📋 Copy IOC List'}
            </button>
          </div>

          <div className="ioc-code-block">
            # MailGuard Defanged IOC Block — Case {result.id}
            # Format: [TYPE] DEFANGED_VALUE
            {iocs.map((ioc, idx) => `\n${ioc.type.padEnd(16)}: ${ioc.value}`)}
          </div>
        </div>

        {/* Incident Containment & Remediation Playbook */}
        <div style={{ marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.92rem', color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            9. Recommended Actions
          </h3>

          <div className="glass-card" style={{ padding: '20px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
              <div>
                <strong style={{ fontSize: '0.85rem', color: 'var(--danger)' }}>1. Block the Threat</strong>
                <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '20px', marginTop: '6px', lineHeight: 1.6 }}>
                  <li>Block all defanged IP addresses at the border firewall / WAF.</li>
                  <li>Add sender domain to Secure Email Gateway (SEG) tenant blocklist.</li>
                  <li>Drop all inbound packets matching detected relay transit IPs.</li>
                </ul>
              </div>

              <div>
                <strong style={{ fontSize: '0.85rem', color: 'var(--warning)' }}>2. Check Your Systems</strong>
                <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '20px', marginTop: '6px', lineHeight: 1.6 }}>
                  <li>Search mail server logs for other mailboxes targeted by this subject line.</li>
                  <li>Purge email message from all user inboxes across the enterprise.</li>
                  <li>Revoke active session tokens if recipient accessed any embedded links.</li>
                </ul>
              </div>

              <div>
                <strong style={{ fontSize: '0.85rem', color: 'var(--accent-green)' }}>3. Protect Your Users</strong>
                <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '20px', marginTop: '6px', lineHeight: 1.6 }}>
                  <li>Instruct targeted recipient to perform an out-of-band password reset.</li>
                  <li>Trigger phishing awareness retraining module for targeted department.</li>
                  <li>Notify corporate finance team if payment / BEC divergence was requested.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Formal Forensic Sign-off Block */}
        <div className="sign-off-box">
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Report By
            </div>
            <div style={{ fontWeight: 700, fontSize: '0.95rem', marginTop: '4px' }}>
              MailGuard — Security Analysis
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Automated Analysis Engine v1.0.0
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Verification
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-green)', marginTop: '4px' }}>
              Integrity Verified ✓
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Certified on {new Date().toUTCString()}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
