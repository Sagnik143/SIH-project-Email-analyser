/**
 * AegisMail Canonical Investigation Engine (Phase 4)
 * 
 * Central orchestration layer for email forensic investigations.
 * Enforces a single, deterministic, evidence-first pipeline:
 * 
 * .EML
 *   ↓
 * Preserve original bytes & compute SHA-256 / MD5
 *   ↓
 * Parse email (body, headers, attachments)
 *   ↓
 * Collect deterministic evidence (headers, body, auth, relay, IoCs)
 *   ↓
 * Validate authentication claims (reported vs verified)
 *   ↓
 * Trace observable relay infrastructure & hop anomalies
 *   ↓
 * Extract URLs / attachments / domains / IPs
 *   ↓
 * Run deterministic forensic rules (Evidence -> Findings)
 *   ↓
 * Calculate explainable heuristic risk score (0-100)
 *   ↓
 * Correlate identity & graph relationships (attribution hypotheses)
 *   ↓
 * Optional AI explanation layer (AI does NOT discover forensic truth)
 *   ↓
 * Assemble final unified dossier with trust boundaries
 */

import crypto from 'crypto';
import { parseEmail } from './emailParser.js';
import { traceRelayHops } from './relayTracer.js';
import { lookupIP, calculateDistanceKm } from './geoService.js';
import { validateAuthentication } from './authValidator.js';
import { extractIoCs } from './iocExtractor.js';
import { generateForensicFindings } from './evidenceFindingService.js';
import { analyzeAttributionAndGraph } from './attributionEngine.js';
import { analyzeEmailThreatWithAI } from './aiThreatEngine.js';

/**
 * Calculates a deterministic, explainable heuristic risk score (0-100).
 * Strictly derived from deterministic forensic signals.
 */
export function calculateHeuristicRisk(findings = [], authData = {}, relayAnalysis = {}, iocData = {}) {
  let score = 10;
  const contributingSignals = [];

  // Authentication & impersonation signals
  if (authData?.displayNameAnalysis?.isSpoofed) {
    score += 35;
    contributingSignals.push('Display-name spoofing detected');
  }
  if (authData?.domainAnalysis?.isLookalike) {
    score += 40;
    const targetBrand = authData.domainAnalysis.targetBrand;
    contributingSignals.push(targetBrand ? `Lookalike / typosquatting domain targeting ${targetBrand}` : 'Lookalike / typosquatting domain detected');
  }
  if (authData?.alignmentAnalysis?.hasReplyToDiscrepancy) {
    score += 25;
    contributingSignals.push('Reply-To / From address routing mismatch');
  }

  // IoC & payload signals
  if (iocData?.dangerousAttachmentsCount > 0) {
    score += 40;
    contributingSignals.push(`Dangerous attachment file type detected (${iocData.dangerousAttachmentsCount} file(s))`);
  }
  if (iocData?.suspiciousUrlsCount > 0) {
    score += 30;
    contributingSignals.push(`Suspicious URL domain or IP-based link detected (${iocData.suspiciousUrlsCount} URL(s))`);
  }

  // Reported authentication header signals
  const spfStatus = (authData?.spf?.status || '').toLowerCase();
  if (spfStatus === 'fail' || spfStatus === 'softfail') {
    score += 20;
    contributingSignals.push(`Reported SPF authentication anomaly: ${authData.spf.status}`);
  }
  const dkimStatus = (authData?.dkim?.status || '').toLowerCase();
  if (dkimStatus === 'fail') {
    score += 20;
    contributingSignals.push('Reported DKIM signature verification failure');
  }
  const dmarcStatus = (authData?.dmarc?.status || '').toLowerCase();
  if (dmarcStatus === 'fail') {
    score += 25;
    contributingSignals.push('Reported DMARC policy violation (fail)');
  }

  // Infrastructure & routing signals
  if (relayAnalysis?.hopAnomalies?.length > 0) {
    score += 15;
    contributingSignals.push('Relay timing / routing inconsistency across intermediate hops');
  }
  if (relayAnalysis?.originatingIPStatus === 'UNVERIFIED' && relayAnalysis?.isUnverifiedHeaderClaim) {
    score += 10;
    contributingSignals.push('Unverified claimed origin header present (X-Originating-IP)');
  }

  score = Math.min(100, Math.max(0, score));

  let level = 'LOW';
  if (score >= 75) level = 'CRITICAL';
  else if (score >= 50) level = 'HIGH';
  else if (score >= 25) level = 'MEDIUM';

  return {
    score,
    level,
    scoreLabel: `Heuristic Risk Score: ${score}/100`,
    contributingSignals: contributingSignals.length > 0 ? contributingSignals : ['Baseline legitimate communication patterns observed'],
    disclaimer: 'The risk score is an analytical heuristic derived from deterministic signals, not a statistical probability of malicious intent.'
  };
}

/**
 * Executes the canonical email investigation pipeline.
 * 
 * @param {string|Buffer} rawInput - Original email string or buffer
 * @param {Object} options - Pipeline options (e.g. skipAi, timestamp)
 * @returns {Promise<Object>} Unified Forensic Dossier
 */
export async function analyzeEmail(rawInput, options = {}) {
  if (!rawInput) {
    throw new Error('Email content cannot be empty');
  }

  // 1. Preserve original bytes / content
  const rawString = typeof rawInput === 'string' ? rawInput : rawInput.toString('utf-8');
  if (rawString.trim().length === 0) {
    throw new Error('Email content cannot be empty');
  }

  // 2. Cryptographic hashes from original raw bytes (Chain of Custody)
  const sha256 = crypto.createHash('sha256').update(rawString, 'utf-8').digest('hex');
  const md5 = crypto.createHash('md5').update(rawString, 'utf-8').digest('hex');
  const byteLength = Buffer.byteLength(rawString, 'utf-8');

  // 3. Parse email structure
  let parsedEmail;
  try {
    parsedEmail = await parseEmail(rawString);
  } catch (parseErr) {
    console.warn('[InvestigationEngine] Email parser error, using emergency fallback:', parseErr);
    parsedEmail = {
      envelope: { from: { address: 'unknown@sender.invalid' }, subject: '(Parsing Error)' },
      body: { text: rawString, html: '', snippet: rawString.slice(0, 300) },
      headers: {},
      headerLines: [],
      attachments: [],
      integrity: { sha256, md5, byteLength }
    };
  }

  // Guarantee integrity hashes match the original raw bytes
  parsedEmail.integrity = {
    sha256,
    md5,
    byteLength
  };

  // 4. Trace observable relay infrastructure
  let relayData;
  try {
    relayData = traceRelayHops(parsedEmail.headers, parsedEmail.headerLines);
  } catch (relayErr) {
    console.warn('[InvestigationEngine] Relay tracer error, using safe fallback:', relayErr);
    relayData = {
      totalHops: 0,
      originatingIP: 'Unknown',
      claimedOriginatingIP: 'Unknown',
      originatingIPStatus: 'UNVERIFIED',
      originatingIPLabel: 'Claimed Earlier Origin (UNVERIFIED)',
      earliestTrustworthySendingInfrastructure: 'Unknown',
      hops: [],
      totalTransitTimeSeconds: 0
    };
  }

  // 5. Geolocation & IP resolution for each observed hop
  let enrichedHops = [];
  let originGeo;
  try {
    enrichedHops = (relayData.hops || []).map(hop => {
      try {
        const geo = lookupIP(hop.ip);
        return { ...hop, geo };
      } catch (hopGeoErr) {
        return {
          ...hop,
          geo: {
            ip: hop.ip,
            resolved: false,
            status: 'unavailable',
            reason: 'Geolocation service is currently unavailable.',
            country: 'Unknown',
            city: 'Unknown',
            isp: 'Unknown',
            disclaimer: 'IP geolocation describes network infrastructure and does not establish physical sender identity.'
          }
        };
      }
    });

    const originatingIP = relayData.originatingIP;
    originGeo = lookupIP(originatingIP);
  } catch (geoErr) {
    console.warn('[InvestigationEngine] Geolocation lookup error, using safe fallback:', geoErr);
    originGeo = {
      ip: relayData.originatingIP || 'Unknown',
      resolved: false,
      status: 'unavailable',
      reason: 'Geolocation service is currently unavailable.',
      country: 'Unknown',
      city: 'Unknown',
      isp: 'Unknown',
      asn: 'Unknown',
      threatFlags: [],
      disclaimer: 'IP geolocation describes network infrastructure and does not establish physical sender identity.'
    };
  }

  // 6. Trace route trajectory and calculate hop anomalies (Relay timing/routing inconsistencies)
  const trajectory = [];
  const hopAnomalies = [];

  for (let i = 0; i < enrichedHops.length; i++) {
    const hop = enrichedHops[i];
    if (hop.geo && hop.geo.resolved && hop.geo.latitude !== 0) {
      trajectory.push({
        hopNumber: hop.hopNumber,
        ip: hop.ip,
        hostname: hop.fromHost,
        city: hop.geo.city,
        country: hop.geo.country,
        countryCode: hop.geo.countryCode,
        lat: hop.geo.latitude,
        lon: hop.geo.longitude,
        delaySeconds: hop.transitDelaySeconds,
        isOrigin: hop.isOriginHop || hop.ip === relayData.originatingIP
      });
    }

    if (i > 0) {
      const prev = enrichedHops[i - 1];
      const curr = enrichedHops[i];
      if (prev.geo?.latitude && curr.geo?.latitude) {
        const distKm = calculateDistanceKm(prev.geo.latitude, prev.geo.longitude, curr.geo.latitude, curr.geo.longitude);
        const delaySec = curr.transitDelaySeconds || 0;
        if (distKm > 1000 && delaySec >= 0 && delaySec < 5) {
          hopAnomalies.push({
            fromHop: prev.hopNumber,
            toHop: curr.hopNumber,
            distanceKm: distKm,
            delaySeconds: delaySec,
            speedKmPerSec: Math.round(distKm / Math.max(1, delaySec)),
            alert: `Timestamp / routing inconsistency: ${distKm}km infrastructure distance with only ${delaySec}s recorded delta between ${prev.geo.city} and ${curr.geo.city}`
          });
        }
      }
    }
  }

  const relayAnalysis = {
    ...relayData,
    hops: enrichedHops,
    originGeo,
    trajectory,
    hopAnomalies
  };

  // 7. Validate Authentication (Reported vs Verified)
  let authData;
  try {
    authData = validateAuthentication({
      ...parsedEmail,
      relay: relayAnalysis
    });
  } catch (authErr) {
    console.warn('[InvestigationEngine] Auth validation error, using safe fallback:', authErr);
    authData = {
      status: 'unavailable',
      reason: 'Authentication evaluation is currently unavailable.',
      spf: { status: 'none', details: 'Unable to evaluate SPF' },
      dkim: { status: 'none', details: 'Unable to evaluate DKIM' },
      dmarc: { status: 'none', details: 'Unable to evaluate DMARC' },
      displayNameAnalysis: { isSpoofed: false, flags: [] },
      domainAnalysis: { isLookalike: false, flags: [] },
      alignmentAnalysis: { hasReplyToDiscrepancy: false, flags: [] },
      authRiskScore: 0,
      evaluationContext: {
        mode: 'unavailable',
        source: 'Reported by receiving system',
        currentValidation: 'insufficient_evidence',
        independentValidationPerformed: false,
        disclaimer: 'Authentication evaluation is currently unavailable.'
      }
    };
  }

  // 8. Extract IoCs (URLs, Attachments, Domains, IPs)
  let iocData;
  try {
    iocData = extractIoCs({
      ...parsedEmail,
      relay: relayAnalysis
    });
  } catch (iocErr) {
    console.warn('[InvestigationEngine] IoC extraction error, using safe fallback:', iocErr);
    iocData = {
      status: 'unavailable',
      reason: 'Indicators of compromise extraction is currently unavailable.',
      totalUrls: 0,
      urls: [],
      attachments: [],
      dangerousAttachmentsCount: 0,
      suspiciousUrlsCount: 0
    };
  }

  // 9. Generate Deterministic Evidence and Findings (Evidence is registered BEFORE findings)
  let forensicEvidenceFindings = { evidence: [], findings: [], stats: {} };
  try {
    forensicEvidenceFindings = generateForensicFindings(
      parsedEmail,
      relayAnalysis,
      authData,
      iocData,
      originGeo
    );
  } catch (efErr) {
    console.warn('[InvestigationEngine] Evidence & Findings generation error, using safe fallback:', efErr);
    forensicEvidenceFindings = { evidence: [], findings: [], stats: {} };
  }

  // 10. Calculate Deterministic Heuristic Risk Score
  const riskData = calculateHeuristicRisk(
    forensicEvidenceFindings.findings,
    authData,
    relayAnalysis,
    iocData
  );

  // 11. Correlate Identity & Graph Relationships (Attribution Hypotheses)
  let attributionAndGraph;
  try {
    attributionAndGraph = analyzeAttributionAndGraph(
      parsedEmail,
      relayAnalysis,
      authData,
      iocData,
      originGeo,
      { threatLevel: riskData.level, riskScore: riskData.score }
    );
  } catch (attrErr) {
    console.warn('[InvestigationEngine] Attribution engine error, using safe fallback:', attrErr);
    attributionAndGraph = {
      status: 'unavailable',
      reason: 'Attribution analysis is currently unavailable.',
      attributionClassification: {
        infrastructureType: 'Unverified Infrastructure',
        probableActorType: 'Investigative Profile: Pattern analysis unavailable',
        campaignCluster: 'Unclustered',
        confidenceScore: 50
      },
      graphCorrelation: { nodesCount: 0, edgesCount: 0, nodes: [], edges: [] },
      earliestReliableSendingNode: relayAnalysis.originatingIP || 'Unknown'
    };
  }

  // 12. Optional AI Threat Intelligence & Explanation Layer
  let aiAssessment;
  if (options.skipAi) {
    aiAssessment = {
      available: false,
      status: 'skipped',
      reason: 'AI explanation skipped per request options.',
      threatClassification: riskData.level === 'CRITICAL' ? 'Impersonation / Fraud Lure' : (riskData.level === 'HIGH' ? 'Phishing / Suspicious' : 'Standard Delivery'),
      threatLevel: riskData.level,
      priorityAssessment: riskData.level,
      riskScore: riskData.score,
      confidenceScore: 90,
      executiveSummary: `Automated forensic evaluation calculated a heuristic risk score of ${riskData.score}/100 based on ${forensicEvidenceFindings.findings.length} deterministic findings.`,
      investigativeHypothesis: 'Forensic evaluation based on observable technical headers and transmission telemetry.',
      observedTactics: riskData.contributingSignals,
      keyObservations: riskData.contributingSignals,
      explanationByFinding: (forensicEvidenceFindings.findings || []).slice(0, 5).map(f => ({ findingId: f.id, explanation: f.summary })),
      investigativeHypotheses: [
        {
          hypothesis: 'Forensic evaluation based on observable technical headers and transmission telemetry.',
          supportingFindingIds: (forensicEvidenceFindings.findings || []).slice(0, 3).map(f => f.id),
          confidence: 'medium'
        }
      ],
      recommendedNextSteps: [
        'Inspect extracted URLs and attachments manually in an isolated sandbox.',
        'Review Received: headers for routing inconsistencies.'
      ],
      recommendedActions: [
        'Inspect extracted URLs and attachments manually in an isolated sandbox.',
        'Review Received: headers for routing inconsistencies.'
      ],
      attribution: {
        status: 'Attribution not established',
        disclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.'
      },
      limitations: [
        'AI explanation was skipped; deterministic findings and evidence remain fully authoritative.'
      ],
      attributionDisclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign. IP geolocation describes network infrastructure.',
      engineSource: 'HEURISTIC_DFIR_ASSISTANT'
    };
  } else {
    try {
      aiAssessment = await analyzeEmailThreatWithAI(
        parsedEmail,
        relayAnalysis,
        authData,
        iocData,
        originGeo,
        forensicEvidenceFindings.findings || [],
        riskData
      );
    } catch (aiErr) {
      console.warn('[InvestigationEngine] External AI assessment unavailable:', aiErr);
      aiAssessment = {
        status: 'unavailable',
        reason: 'AI-assisted analysis is currently unavailable.',
        threatClassification: 'Analysis Incomplete (AI Service Unavailable)',
        threatLevel: riskData.level,
        riskScore: riskData.score,
        confidenceScore: 50,
        attribution: {
          infrastructureClassification: 'Unverified Infrastructure',
          probableActorPersona: 'Investigative Profile: Pattern analysis unavailable',
          campaignCluster: 'Unclustered',
          attributionConfidence: 0
        },
        socialEngineeringTactics: riskData.contributingSignals,
        observedTactics: riskData.contributingSignals,
        executiveSummary: 'External AI explanation service was temporarily unavailable. Deterministic header, routing, and IoC telemetry are provided below.',
        forensicHypothesis: 'External AI service unavailable. Available email evidence does not establish actor identity.',
        investigativeHypothesis: 'External AI service unavailable. Available email evidence does not establish actor identity.',
        threatActorPersona: 'Investigative Profile: Unavailable',
        recommendedActions: [
          'Inspect extracted URLs and attachments manually in an isolated sandbox.',
          'Review Received: headers for routing inconsistencies.'
        ],
        attributionDisclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign. IP geolocation describes network infrastructure.'
      };
    }
  }

  // 13. Assemble Final Unified Dossier
  const dossierId = `DFIR-AICTE-26106-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  const timestamp = options.timestamp || new Date().toISOString();

  // Aggregate limitations from findings, geolocation, authentication, and relay
  const accumulatedLimitations = [
    'Email headers and reported authentication results represent claims recorded by sending or intermediate mail agents.',
    'IP geolocation describes network infrastructure and does not establish physical sender identity or location.',
    'Heuristic risk scores reflect deterministic static indicators and do not represent statistical probabilities.',
    ...(forensicEvidenceFindings.findings || []).flatMap(f => f.limitations || [])
  ].filter((item, idx, arr) => item && arr.indexOf(item) === idx);

  const unifiedDossier = {
    // -------------------------------------------------------------
    // Canonical Phase 4 Structure
    // -------------------------------------------------------------
    metadata: {
      dossierId,
      timestamp,
      engine: 'AegisMail Canonical Investigation Engine v4.0',
      problemStatementId: 26106,
      integrity: {
        sha256,
        md5,
        byteLength
      }
    },
    summary: {
      threatClassification: aiAssessment.threatClassification || 'Analysis Complete',
      threatLevel: aiAssessment.threatLevel || riskData.level,
      heuristicRiskScore: riskData.score,
      riskLevel: riskData.level,
      totalHops: relayAnalysis.totalHops,
      totalEvidence: forensicEvidenceFindings.evidence.length,
      totalFindings: forensicEvidenceFindings.findings.length,
      criticalFindings: (forensicEvidenceFindings.findings || []).filter(f => f.severity === 'critical').length,
      highFindings: (forensicEvidenceFindings.findings || []).filter(f => f.severity === 'high').length
    },
    authentication: authData,
    relay: relayAnalysis,
    geolocation: originGeo,
    indicators: iocData,
    evidence: forensicEvidenceFindings.evidence || [],
    findings: forensicEvidenceFindings.findings || [],
    risk: riskData,
    aiExplanation: {
      available: aiAssessment.available !== false,
      status: aiAssessment.status || 'available',
      threatClassification: aiAssessment.threatClassification,
      threatLevel: aiAssessment.threatLevel,
      priorityAssessment: aiAssessment.priorityAssessment || aiAssessment.threatLevel,
      riskScore: riskData.score,
      executiveSummary: aiAssessment.executiveSummary,
      keyObservations: aiAssessment.keyObservations || aiAssessment.observedTactics || [],
      explanationByFinding: aiAssessment.explanationByFinding || [],
      investigativeHypotheses: aiAssessment.investigativeHypotheses || [],
      recommendedNextSteps: aiAssessment.recommendedNextSteps || aiAssessment.recommendedActions || [],
      investigativeHypothesis: aiAssessment.investigativeHypothesis || aiAssessment.forensicHypothesis,
      observedTactics: aiAssessment.observedTactics || aiAssessment.socialEngineeringTactics || [],
      recommendedActions: aiAssessment.recommendedActions || aiAssessment.recommendedNextSteps || [],
      attribution: aiAssessment.attribution || {
        status: 'Attribution not established',
        disclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.'
      },
      limitations: aiAssessment.limitations || [
        'AI provides investigative hypotheses and natural-language summaries based on deterministic evidence and findings.',
        'AI does not discover forensic facts, establish attacker identity, or confirm campaign attribution.'
      ],
      engineSource: aiAssessment.engineSource,
      disclaimer: 'AI provides investigative hypotheses and natural-language summaries based on deterministic evidence and findings. AI does not discover forensic truth or identify human attackers.'
    },
    limitations: accumulatedLimitations,

    // Phase 4 Trust Boundary Model (foundation for Phase 8 UI)
    trustBoundary: {
      claimedByEmail: {
        from: parsedEmail.envelope?.from,
        replyTo: parsedEmail.envelope?.replyTo,
        subject: parsedEmail.envelope?.subject,
        claimedOriginIP: relayAnalysis.originatingIP,
        claimedOriginStatus: relayAnalysis.originatingIPStatus || 'UNVERIFIED',
        reportedAuthentication: {
          spf: authData.spf,
          dkim: authData.dkim,
          dmarc: authData.dmarc,
          source: authData.evaluationContext?.source || 'Reported by receiving system'
        }
      },
      observableInfrastructure: {
        observableRelays: relayAnalysis.hops,
        earliestObservablePublicRelay: relayAnalysis.earliestTrustworthySendingInfrastructure || relayAnalysis.originatingIP,
        infrastructureGeolocation: {
          ...originGeo,
          disclaimer: 'IP geolocation describes network infrastructure and does not establish physical sender identity.'
        },
        relayTimingAnomalies: relayAnalysis.hopAnomalies || []
      },
      deterministicFindings: {
        totalFindings: forensicEvidenceFindings.findings.length,
        summaryList: (forensicEvidenceFindings.findings || []).map(f => ({
          id: f.id,
          type: f.type,
          title: f.title,
          severity: f.severity,
          evidenceIds: f.evidenceIds
        }))
      }
    },

    // -------------------------------------------------------------
    // Backward Compatibility Fields (Preserved for existing UI & tests)
    // -------------------------------------------------------------
    dossierId,
    problemStatementId: 26106,
    timestamp,
    integrity: {
      sha256,
      md5,
      byteLength
    },
    envelope: parsedEmail.envelope,
    bodySnippet: parsedEmail.body?.snippet || '',
    bodyText: parsedEmail.body?.text || '',
    bodyHtml: parsedEmail.body?.html || '',
    attachments: parsedEmail.attachments || [],
    originGeo,
    iocs: iocData,
    aiThreatIntelligence: aiAssessment,
    attributionAndGraph,
    findingStats: forensicEvidenceFindings.stats || {},
    rawEmail: rawString,
    rawHeaders: parsedEmail.headers || {},
    headerLines: parsedEmail.headerLines || []
  };

  return unifiedDossier;
}
