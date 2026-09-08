/**
 * Threat Scorer
 * Aggregates all analysis modules into a unified threat assessment.
 */

/**
 * Calculate comprehensive threat score and classification
 */
export function calculateThreatScore(analysisResults) {
  const {
    headerAnomalies = [],
    authResult = {},
    nlpResult = {},
    linkResult = {},
    ipResults = [],
    domainResult = {},
  } = analysisResults;

  // Weight each analysis component
  const scores = {
    authentication: 100 - (authResult.overallScore || 50),   // Invert: low auth = high threat
    nlp: nlpResult.nlpScore || 0,
    links: linkResult.overallScore || 0,
    headerAnomalies: Math.min(100, headerAnomalies.length * 20),
    ipRisk: calculateAggregateIPRisk(ipResults),
    domainRisk: 100 - (domainResult?.reputationScore || 50),  // Invert
  };

  const weights = {
    authentication: 0.20,
    nlp: 0.30,
    links: 0.15,
    headerAnomalies: 0.15,
    ipRisk: 0.10,
    domainRisk: 0.10,
  };

  let weightedScore = 0;
  for (const [key, weight] of Object.entries(weights)) {
    weightedScore += (scores[key] || 0) * weight;
  }

  const threatScore = Math.round(Math.min(100, weightedScore));

  // Determine classification
  const classification = classifyThreat(threatScore, analysisResults);

  // Generate summary
  const summary = generateThreatSummary(threatScore, classification, scores, analysisResults);

  // Collect all findings
  const allFindings = collectFindings(analysisResults);

  return {
    threatScore,
    classification,
    confidence: calculateConfidence(scores),
    scores,
    summary,
    findings: allFindings,
    riskLevel: getRiskLevel(threatScore),
    recommendation: getRecommendation(threatScore, classification),
  };
}

/**
 * Calculate aggregate IP risk from all IP results
 */
function calculateAggregateIPRisk(ipResults) {
  if (!ipResults || ipResults.length === 0) return 20;

  let maxRisk = 0;
  for (const ip of ipResults) {
    let risk = 0;
    if (ip.isProxy) risk += 40;
    if (ip.isHosting) risk += 20;
    for (const indicator of (ip.riskIndicators || [])) {
      switch (indicator.severity) {
        case 'critical': risk += 40; break;
        case 'high': risk += 25; break;
        case 'medium': risk += 10; break;
      }
    }
    maxRisk = Math.max(maxRisk, Math.min(100, risk));
  }

  return maxRisk;
}

/**
 * Classify the threat type
 */
function classifyThreat(score, results) {
  const nlp = results.nlpResult || {};
  const hasBEC = nlp.bec?.score > 30;
  const hasImpersonation = nlp.impersonation?.score > 30;
  const hasPhishing = nlp.phishing?.score > 40;

  if (hasBEC && score > 35) return 'fraud';
  if (hasImpersonation && score > 30) return 'impersonation';
  if (hasPhishing && score > 35) return 'phishing';
  if (score >= 65) return 'phishing';
  if (score >= 40) return 'suspicious';
  if (score >= 20) return 'suspicious';
  return 'legitimate';
}

/**
 * Get risk level string
 */
function getRiskLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 35) return 'medium';
  if (score >= 15) return 'low';
  return 'minimal';
}

/**
 * Calculate confidence percentage
 */
function calculateConfidence(scores) {
  // Higher confidence when multiple signals agree
  const signals = Object.values(scores);
  const highSignals = signals.filter(s => s > 50).length;
  const lowSignals = signals.filter(s => s < 20).length;

  if (highSignals >= 4) return 95;
  if (highSignals >= 3) return 85;
  if (lowSignals >= 4) return 90; // Confident it's safe
  if (highSignals >= 2) return 75;

  return 65;
}

/**
 * Generate human-readable threat summary
 */
function generateThreatSummary(score, classification, scores, results) {
  const parts = [];

  switch (classification) {
    case 'fraud':
      parts.push('⚠️ This email exhibits strong indicators of Business Email Compromise (BEC) or financial fraud.');
      break;
    case 'impersonation':
      parts.push('🎭 This email shows signs of sender impersonation — the claimed identity does not match the actual sender infrastructure.');
      break;
    case 'phishing':
      parts.push('🎣 This email contains multiple phishing indicators including deceptive content and suspicious links.');
      break;
    case 'suspicious':
      parts.push('🔍 This email has some suspicious characteristics that warrant further investigation.');
      break;
    case 'legitimate':
      parts.push('✅ This email appears legitimate based on available indicators.');
      break;
  }

  // Add specific insights
  if (scores.authentication > 60) {
    parts.push('Email authentication (SPF/DKIM/DMARC) is failing or absent.');
  }

  if (scores.nlp > 50) {
    parts.push('Content analysis detected social engineering language patterns.');
  }

  if (scores.links > 40) {
    parts.push('Embedded links show high-risk characteristics.');
  }

  if (scores.headerAnomalies > 30) {
    parts.push('Header analysis revealed routing anomalies.');
  }

  return parts.join(' ');
}

/**
 * Collect all findings from all analysis modules
 */
function collectFindings(results) {
  const findings = [];

  // Header anomalies
  const anomalies = results.headerAnomalies || [];
  for (const anomaly of anomalies) {
    findings.push({
      category: 'Header Anomaly',
      severity: anomaly.severity === 'high' ? 'danger' : anomaly.severity === 'medium' ? 'warning' : 'info',
      description: anomaly.description,
      details: anomaly.details ? [JSON.stringify(anomaly.details)] : [],
    });
  }

  // NLP findings
  if (results.nlpResult?.findings) {
    findings.push(...results.nlpResult.findings);
  }

  // Link findings
  if (results.linkResult?.findings) {
    findings.push(...results.linkResult.findings);
  }

  // Domain findings
  if (results.domainResult?.findings) {
    findings.push(...results.domainResult.findings);
  }

  // IP findings
  for (const ip of (results.ipResults || [])) {
    for (const indicator of (ip.riskIndicators || [])) {
      findings.push({
        category: 'IP Intelligence',
        severity: indicator.severity === 'critical' ? 'danger' : indicator.severity === 'high' ? 'danger' : 'warning',
        description: `${ip.ip}: ${indicator.description}`,
        details: [`Location: ${ip.city}, ${ip.country}`, `ISP: ${ip.isp}`],
      });
    }
  }

  // Sort by severity
  const severityOrder = { danger: 0, warning: 1, info: 2 };
  findings.sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

  return findings;
}

/**
 * Get recommendation based on threat assessment
 */
function getRecommendation(score, classification) {
  if (score >= 75) {
    return {
      action: 'BLOCK',
      urgency: 'immediate',
      text: 'Immediately quarantine this email. Do not allow user interaction. Initiate incident response procedures and preserve evidence for forensic analysis.',
      color: 'danger',
    };
  }

  if (score >= 55) {
    return {
      action: 'QUARANTINE',
      urgency: 'high',
      text: 'Quarantine this email and flag for analyst review. Do not deliver to end user until investigation is complete.',
      color: 'warning',
    };
  }

  if (score >= 35) {
    return {
      action: 'REVIEW',
      urgency: 'medium',
      text: 'Flag this email for manual review. Some indicators suggest suspicious activity but confidence is moderate.',
      color: 'warning',
    };
  }

  if (score >= 15) {
    return {
      action: 'MONITOR',
      urgency: 'low',
      text: 'Minor suspicious indicators detected. Allow delivery but log for future reference and correlation.',
      color: 'info',
    };
  }

  return {
    action: 'ALLOW',
    urgency: 'none',
    text: 'Email appears legitimate. No immediate action required.',
    color: 'success',
  };
}
