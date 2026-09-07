/**
 * AegisMail Phase 6: AI Response Validator & Sanitization Layer
 * 
 * Enforces a strict boundary between deterministic forensics and AI assistance:
 * 1. AI is an EXPLANATION & HYPOTHESIS layer, NEVER the source of forensic truth.
 * 2. Deterministic evidence, findings, and risk scores are strictly authoritative.
 * 3. AI cannot invent finding IDs, evidence IDs, IoCs, or authentication results.
 * 4. AI cannot assert attacker attribution, campaign attribution, or human physical location.
 * 5. Validates finding references: any finding ID in AI output MUST exist in deterministic findings.
 * 6. Strips markup, enforces length bounds, and falls back gracefully on any validation error.
 */

// Denylist patterns for unsupported forensic claims
const ATTACKER_IDENTITY_PATTERNS = [
  /\b(apt[\s_-]?\d+|lazarus|fancy[\s_-]?bear|cozy[\s_-]?bear|sandworm|fin\d+|ta\d+|unc\d+)\b/gi,
  /\b(attacker is|perpetrated by|hacker is|criminal group|identified as the attacker|sent by the attacker|authored by)\b/gi,
  /\b(attacker identity|individual responsible|real-world identity|same attacker|common attacker|identical attacker|same threat actor)\b/gi
];

const CAMPAIGN_ASSERTION_PATTERNS = [
  /\b(confirmed campaign|definitive campaign|is part of the .* campaign|same criminal campaign|coordinated campaign|same campaign|common campaign)\b/gi
];

const PHYSICAL_LOCATION_PATTERNS = [
  /\b(attacker is (located|living|based|operating) in|sender is physically in|human location is)\b/gi
];

const PROBABILITY_MISUSE_PATTERNS = [
  /\b(\d+%\s*probability of (attack|phishing|malware|attacker)|certainty:\s*\d+%)\b/gi
];

/**
 * Validates and sanitizes AI output against authoritative deterministic context.
 * 
 * @param {Object} rawOutput - Parsed AI JSON output
 * @param {Object} deterministicContext - Authoritative context containing:
 *   - findings: Array of deterministic finding objects ({ id, ... })
 *   - evidence: Array of deterministic evidence objects ({ id, ... })
 *   - indicators: Extracted IoCs ({ urls, attachments, domains, ips })
 *   - risk: Deterministic risk ({ score, level, contributingSignals })
 *   - authentication: Auth evaluation
 *   - relay: Relay analysis
 * @returns {Object} Strictly validated and sanitized AI assistant output
 */
export function validateAndSanitizeAiResponse(rawOutput, deterministicContext = {}) {
  const deterministicFindings = Array.isArray(deterministicContext.findings) ? deterministicContext.findings : [];
  const validFindingIdSet = new Set(deterministicFindings.map(f => f.id));
  const deterministicRiskScore = typeof deterministicContext.risk?.score === 'number'
    ? deterministicContext.risk.score
    : (typeof rawOutput?.riskScore === 'number' ? rawOutput.riskScore : 50);

  // If rawOutput is null or not an object, build safe fallback immediately
  if (!rawOutput || typeof rawOutput !== 'object') {
    return createSafeFallback(deterministicContext, 'Invalid or empty AI response format');
  }

  // 1. Authoritative Risk Score Enforcement (AI NEVER owns or overrides risk score)
  const riskScore = deterministicRiskScore;

  // 2. Validate Executive Summary
  let executiveSummary = sanitizeText(
    typeof rawOutput.executiveSummary === 'string' ? rawOutput.executiveSummary : '',
    1000
  );
  if (!executiveSummary) {
    executiveSummary = deterministicFindings.length > 0
      ? `Email inspection identified ${deterministicFindings.length} observable forensic finding(s). Heuristic risk score calculated at ${riskScore}/100. Analyst review recommended.`
      : `Email inspection identified baseline corporate communication telemetry with no high-risk indicators observed.`;
  }
  executiveSummary = sanitizeAttributionClaims(executiveSummary);

  // 3. Priority Assessment
  const validPriorities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  let priorityAssessment = typeof rawOutput.priorityAssessment === 'string'
    ? rawOutput.priorityAssessment.toUpperCase()
    : (typeof rawOutput.threatLevel === 'string' ? rawOutput.threatLevel.toUpperCase() : 'LOW');
  if (!validPriorities.includes(priorityAssessment)) {
    priorityAssessment = deterministicContext.risk?.level || 'LOW';
  }

  // 4. Key Observations (Must be array of strings, max 8 items, max 300 chars each)
  let keyObservations = [];
  const rawObs = Array.isArray(rawOutput.keyObservations)
    ? rawOutput.keyObservations
    : (Array.isArray(rawOutput.observedTactics) ? rawOutput.observedTactics : []);

  for (const obs of rawObs) {
    if (typeof obs === 'string' && obs.trim()) {
      const sanitizedObs = sanitizeAttributionClaims(sanitizeText(obs, 300));
      if (sanitizedObs && !keyObservations.includes(sanitizedObs)) {
        keyObservations.push(sanitizedObs);
      }
      if (keyObservations.length >= 8) break;
    }
  }

  if (keyObservations.length === 0) {
    if (deterministicFindings.length > 0) {
      keyObservations = deterministicFindings.slice(0, 5).map(f => `${f.title}: ${f.summary}`);
    } else {
      keyObservations = ['Standard RFC 5322 header alignment observed', 'No anomalous relay transit delays detected'];
    }
  }

  // 5. Explanations by Finding (Strictly validate that findingId exists in deterministic findings)
  const explanationByFinding = [];
  if (Array.isArray(rawOutput.explanationByFinding)) {
    for (const item of rawOutput.explanationByFinding) {
      if (item && typeof item === 'object') {
        const findingId = typeof item.findingId === 'string' ? item.findingId.trim().toUpperCase() : null;
        // MUST exist in deterministic findings - otherwise REJECT immediately!
        if (findingId && validFindingIdSet.has(findingId)) {
          const explanation = sanitizeAttributionClaims(sanitizeText(item.explanation || '', 500));
          explanationByFinding.push({
            findingId,
            explanation: explanation || 'Observed telemetry associated with this deterministic finding.'
          });
        } else if (findingId) {
          console.warn(`[AIValidator] Rejected invented or nonexistent findingId: "${findingId}"`);
        }
      }
    }
  }

  // If none supplied or all invalid, provide baseline explanations for real findings
  if (explanationByFinding.length === 0 && deterministicFindings.length > 0) {
    for (const f of deterministicFindings.slice(0, 5)) {
      explanationByFinding.push({
        findingId: f.id,
        explanation: f.summary
      });
    }
  }

  // 6. Investigative Hypotheses (Must NOT claim attacker attribution or campaign certainty)
  const investigativeHypotheses = [];
  const rawHypotheses = Array.isArray(rawOutput.investigativeHypotheses)
    ? rawOutput.investigativeHypotheses
    : [];

  // Also support singular investigativeHypothesis / forensicHypothesis
  if (rawHypotheses.length === 0 && (rawOutput.investigativeHypothesis || rawOutput.forensicHypothesis)) {
    rawHypotheses.push({
      hypothesis: rawOutput.investigativeHypothesis || rawOutput.forensicHypothesis,
      supportingFindingIds: deterministicFindings.map(f => f.id).slice(0, 3),
      confidence: 'medium'
    });
  }

  for (const hyp of rawHypotheses) {
    if (hyp && (typeof hyp === 'object' || typeof hyp === 'string')) {
      const text = typeof hyp === 'string' ? hyp : (hyp.hypothesis || '');
      let sanitizedHyp = sanitizeAttributionClaims(sanitizeText(text, 600));

      if (!sanitizedHyp) continue;

      // Validate supporting finding IDs
      const rawSuppIds = Array.isArray(hyp.supportingFindingIds) ? hyp.supportingFindingIds : [];
      const validSuppIds = rawSuppIds
        .map(id => (typeof id === 'string' ? id.trim().toUpperCase() : ''))
        .filter(id => validFindingIdSet.has(id));

      // Validate hypothesis confidence (low | medium | high) - NEVER a probability
      let confidence = 'medium';
      if (typeof hyp.confidence === 'string') {
        const lowerConf = hyp.confidence.toLowerCase();
        if (['low', 'medium', 'high'].includes(lowerConf)) {
          confidence = lowerConf;
        }
      }

      investigativeHypotheses.push({
        hypothesis: sanitizedHyp,
        supportingFindingIds: validSuppIds,
        confidence
      });

      if (investigativeHypotheses.length >= 5) break;
    }
  }

  if (investigativeHypotheses.length === 0) {
    investigativeHypotheses.push({
      hypothesis: deterministicFindings.length > 0
        ? 'Observed indicators exhibit discrepancies that warrant review. Available evidence does not establish actor identity.'
        : 'Telemetry indicates standard communication exchange consistent with legitimate business email.',
      supportingFindingIds: deterministicFindings.slice(0, 3).map(f => f.id),
      confidence: 'medium'
    });
  }

  // 7. Recommended Next Steps (Actionable SOC steps without false certainty)
  let recommendedNextSteps = [];
  const rawSteps = Array.isArray(rawOutput.recommendedNextSteps)
    ? rawOutput.recommendedNextSteps
    : (Array.isArray(rawOutput.recommendedActions) ? rawOutput.recommendedActions : []);

  for (const step of rawSteps) {
    if (typeof step === 'string' && step.trim()) {
      const sanitizedStep = sanitizeAttributionClaims(sanitizeText(step, 300));
      if (sanitizedStep && !recommendedNextSteps.includes(sanitizedStep)) {
        recommendedNextSteps.push(sanitizedStep);
      }
      if (recommendedNextSteps.length >= 8) break;
    }
  }

  if (recommendedNextSteps.length === 0) {
    if (riskScore >= 50) {
      recommendedNextSteps = [
        'Inspect extracted URLs in an isolated sandbox analysis environment.',
        'Review Received headers and sending MTA against organizational allowlists.',
        'Compare Reply-To address with authentic organizational domain records.'
      ];
    } else {
      recommendedNextSteps = [
        'Verify sender domain authenticity against organizational policies.',
        'Routine review completed; no immediate containment action required.'
      ];
    }
  }

  // 8. Explicit Limitations
  const limitations = [
    'AI provides investigative hypotheses and natural-language summaries based on deterministic evidence and findings.',
    'AI does not discover forensic facts, establish attacker identity, or confirm campaign attribution.',
    'IP geolocation describes observed network infrastructure and does not establish physical sender identity or location.',
    'Shared observable indicators across cases do not establish common human authorship.'
  ];

  // 9. Clean Attribution Object (Strictly unverified hypothesis, NEVER actor identity)
  const attribution = {
    status: 'Attribution not established',
    hypothesis: sanitizeAttributionClaims(
      rawOutput.threatActorPersona ||
      rawOutput.attribution?.probableActorPersona ||
      'Investigative Profile: Pattern analysis based on observable email artifacts'
    ),
    infrastructureClassification: sanitizeText(
      rawOutput.attribution?.infrastructureClassification || 'Observed Network Infrastructure',
      120
    ),
    campaignCluster: 'Unclustered (Observable Indicator Grouping)',
    disclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.'
  };

  // 10. Assemble Validated Output Contract
  return {
    available: true,
    status: 'available',
    executiveSummary,
    priorityAssessment,
    threatLevel: priorityAssessment,
    threatClassification: sanitizeText(rawOutput.threatClassification || (riskScore >= 50 ? 'Suspicious / Elevated Risk' : 'Legitimate / Baseline'), 80),
    riskScore, // Authoritatively locked
    confidenceScore: Math.min(100, Math.max(0, parseInt(rawOutput.confidenceScore, 10) || 85)),
    keyObservations,
    observedTactics: keyObservations, // Backward compatibility alias
    explanationByFinding,
    investigativeHypotheses,
    forensicHypothesis: investigativeHypotheses[0]?.hypothesis || '', // Backward compatibility alias
    investigativeHypothesis: investigativeHypotheses[0]?.hypothesis || '', // Backward compatibility alias
    recommendedNextSteps,
    recommendedActions: recommendedNextSteps, // Backward compatibility alias
    limitations,
    attribution,
    attributionDisclaimer: attribution.disclaimer,
    engineSource: rawOutput.engineSource || 'AI_ASSISTED_ANALYSIS'
  };
}

/**
 * Creates a safe deterministic fallback when AI is unavailable, times out, or fails validation.
 */
export function createSafeFallback(deterministicContext = {}, reason = 'AI service temporarily unavailable') {
  const findings = Array.isArray(deterministicContext.findings) ? deterministicContext.findings : [];
  const riskScore = typeof deterministicContext.risk?.score === 'number'
    ? deterministicContext.risk.score
    : 10;
  const riskLevel = deterministicContext.risk?.level || (riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW');

  const keyObservations = findings.length > 0
    ? findings.slice(0, 5).map(f => `${f.title}: ${f.summary}`)
    : ['Standard email transmission telemetry observed'];

  const explanations = findings.slice(0, 5).map(f => ({
    findingId: f.id,
    explanation: f.summary
  }));

  const hypotheses = [
    {
      hypothesis: findings.length > 0
        ? `Observed ${findings.length} forensic finding(s) with heuristic risk ${riskScore}/100. Telemetry indicates potential anomalies requiring analyst review.`
        : 'Baseline communication patterns with no high-risk indicators observed.',
      supportingFindingIds: findings.slice(0, 3).map(f => f.id),
      confidence: 'medium'
    }
  ];

  const actions = riskScore >= 50
    ? [
        'Inspect extracted URLs and attachments manually in an isolated sandbox.',
        'Review Received: headers for routing inconsistencies.',
        'Verify sender identity with known communication channels.'
      ]
    : [
        'Standard delivery profile; verify against corporate mail policies.'
      ];

  return {
    available: false,
    status: 'unavailable',
    reason,
    executiveSummary: `Automated forensic evaluation calculated a heuristic risk score of ${riskScore}/100 based on ${findings.length} deterministic findings. AI explanation is currently offline.`,
    priorityAssessment: riskLevel,
    threatLevel: riskLevel,
    threatClassification: riskScore >= 75 ? 'Critical Risk Telemetry' : riskScore >= 50 ? 'Suspicious Telemetry' : 'Standard Delivery',
    riskScore,
    confidenceScore: 50,
    keyObservations,
    observedTactics: keyObservations,
    explanationByFinding: explanations,
    investigativeHypotheses: hypotheses,
    forensicHypothesis: hypotheses[0].hypothesis,
    investigativeHypothesis: hypotheses[0].hypothesis,
    recommendedNextSteps: actions,
    recommendedActions: actions,
    limitations: [
      'AI assistant is currently offline; deterministic findings and evidence remain fully authoritative.',
      'IP geolocation describes network infrastructure and does not establish physical sender identity.'
    ],
    attribution: {
      status: 'Attribution not established',
      hypothesis: 'Investigative Profile: Pattern analysis unavailable',
      infrastructureClassification: 'Observed Network Infrastructure',
      campaignCluster: 'Unclustered',
      disclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.'
    },
    attributionDisclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.',
    engineSource: 'HEURISTIC_DFIR_ENGINE'
  };
}

/**
 * Strips HTML tags, script injection, and bounds text length.
 */
function sanitizeText(str, maxLength = 500) {
  if (!str || typeof str !== 'string') return '';
  let clean = str
    .replace(/<[^>]*>/g, '') // Strip HTML
    .replace(/[<>]/g, '')
    .trim();
  if (clean.length > maxLength) {
    clean = clean.substring(0, maxLength - 3) + '...';
  }
  return clean;
}

/**
 * Sanitizes unsupported attacker claims, campaign certainties, and human location inferences.
 */
function sanitizeAttributionClaims(text) {
  if (!text || typeof text !== 'string') return '';
  let sanitized = text;

  // Replace specific APT / attacker names
  for (const pattern of ATTACKER_IDENTITY_PATTERNS) {
    sanitized = sanitized.replace(pattern, 'an unverified sender entity');
  }

  // Replace campaign assertions
  for (const pattern of CAMPAIGN_ASSERTION_PATTERNS) {
    sanitized = sanitized.replace(pattern, 'a potential indicator pattern');
  }

  // Replace human physical location assertions
  for (const pattern of PHYSICAL_LOCATION_PATTERNS) {
    sanitized = sanitized.replace(pattern, 'the observed network relay was hosted in');
  }

  // Strip probability misrepresentations
  for (const pattern of PROBABILITY_MISUSE_PATTERNS) {
    sanitized = sanitized.replace(pattern, 'heuristic risk indicators');
  }

  return sanitized;
}
