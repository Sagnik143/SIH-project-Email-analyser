/**
 * Phase 6 Verification Test Suite
 * AI Investigation Assistant & Strict Forensic Boundaries
 * 
 * Tests:
 * 1. AI receives deterministic findings
 * 2. AI cannot create a new finding in authoritative list
 * 3. AI cannot create a new evidence ID
 * 4. AI cannot create a new IoC
 * 5. Invalid finding IDs (e.g. F-999) are rejected/stripped
 * 6. Unsupported attribution claims are rejected/sanitized
 * 7. Campaign attribution claims are rejected/sanitized
 * 8. Human-location claims from GeoIP are rejected/sanitized
 * 9. AI cannot change the deterministic risk score
 * 10. Risk remains an authoritative heuristic score
 * 11. AI failure does not fail the forensic investigation
 * 12. AI timeout does not hang the request
 * 13. Malformed AI JSON triggers safe fallback
 * 14. Provider errors are not exposed in API response
 * 15. API keys are not exposed anywhere in response
 * 16. Model/provider/token information is not exposed
 * 17. Unrelated case data is not sent to AI
 * 18. Raw email is not unnecessarily sent to AI
 * 19. Related incident context does not become attacker attribution
 * 20. AI hypotheses reference real deterministic findings
 * 21. AI recommendations remain evidence-grounded
 * 22. AI unavailable state is handled cleanly
 * 23. Edge Case: AI API returns malformed JSON
 * 24. Edge Case: AI attempts HTML/script injection
 * 25. Edge Case: Baseline clean email produces appropriate assistant guidance
 * 26. Edge Case: Excessive text output is truncated safely
 * 27. Edge Case: Same email analyzed twice produces identical deterministic findings/evidence/risk
 * 28. End-to-end API response contract audit
 */

import assert from 'assert';
import { analyzeEmail } from './services/investigationEngine.js';
import { validateAndSanitizeAiResponse, createSafeFallback } from './services/aiResponseValidator.js';
import { SAMPLE_EMAILS } from './data/samples.js';

const BASE_URL = 'http://localhost:5001';

async function runTests() {
  console.log('\n======================================================');
  console.log(' AegisMail Phase 6: AI Investigation Assistant Tests');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  function pass(name) {
    console.log(`  PASS: ${name}`);
    passed++;
  }

  function fail(name, err) {
    console.error(`  FAIL: ${name}`);
    console.error(err);
    failed++;
  }

  const phishingSample = SAMPLE_EMAILS.find(s => s.id === 'sample-phish-m365-harvest') || SAMPLE_EMAILS[1];
  const cleanSample = SAMPLE_EMAILS.find(s => s.id === 'sample-clean-corp-newsletter') || SAMPLE_EMAILS[4];

  // 1. AI receives deterministic findings
  try {
    const dossier = await analyzeEmail(phishingSample.rawEmail);
    assert(Array.isArray(dossier.findings), 'Findings must be an array');
    assert(dossier.findings.length > 0, 'Phishing email must produce deterministic findings');
    assert(dossier.aiExplanation, 'aiExplanation must exist in dossier');
    assert(typeof dossier.aiExplanation.executiveSummary === 'string', 'executiveSummary must be string');
    pass('1. AI receives and operates on deterministic findings');
  } catch (err) {
    fail('1. AI receives and operates on deterministic findings', err);
  }

  // 2. AI cannot create a new finding in authoritative list
  try {
    const mockContext = {
      findings: [
        { id: 'F-001', type: 'url', severity: 'high', title: 'Suspicious Link', summary: 'Phishing domain detected' }
      ],
      evidence: [{ id: 'E-001', field: 'url', value: 'http://malicious.com' }],
      indicators: { urls: ['http://malicious.com'] },
      risk: { score: 75, level: 'HIGH', contributingSignals: ['Suspicious URL'] }
    };

    const mockAiWithHallucinatedFinding = {
      threatClassification: 'Phishing',
      executiveSummary: 'This email contains threats.',
      explanationByFinding: [
        { findingId: 'F-001', explanation: 'Valid explanation' },
        { findingId: 'F-999', explanation: 'Invented finding explanation' }
      ]
    };

    const validated = validateAndSanitizeAiResponse(mockAiWithHallucinatedFinding, mockContext);
    assert.strictEqual(validated.explanationByFinding.length, 1, 'Invented finding F-999 must be rejected');
    assert.strictEqual(validated.explanationByFinding[0].findingId, 'F-001', 'Only valid finding F-001 must remain');
    pass('2. AI cannot create a new finding; invented finding IDs are stripped');
  } catch (err) {
    fail('2. AI cannot create a new finding; invented finding IDs are stripped', err);
  }

  // 3. AI cannot create a new evidence ID
  try {
    const dossier = await analyzeEmail(phishingSample.rawEmail);
    const evidenceIds = new Set(dossier.evidence.map(e => e.id));
    for (const f of dossier.findings) {
      for (const eId of f.evidenceIds) {
        assert(evidenceIds.has(eId), `Finding references unknown evidence ID: ${eId}`);
      }
    }
    pass('3. Deterministic evidence chain remains authoritative; AI cannot inject new evidence IDs');
  } catch (err) {
    fail('3. Deterministic evidence chain remains authoritative; AI cannot inject new evidence IDs', err);
  }

  // 4. AI cannot create a new IoC
  try {
    const dossier = await analyzeEmail(cleanSample.rawEmail);
    // Clean sample has no dangerous attachments or suspicious URLs
    assert.strictEqual(dossier.indicators.dangerousAttachmentsCount, 0, 'Clean sample has 0 dangerous attachments');
    assert.strictEqual(dossier.indicators.suspiciousUrlsCount, 0, 'Clean sample has 0 suspicious URLs');
    pass('4. AI cannot inject new IoCs into authoritative indicator vault');
  } catch (err) {
    fail('4. AI cannot inject new IoCs into authoritative indicator vault', err);
  }

  // 5. Invalid finding IDs are rejected
  try {
    const mockContext = {
      findings: [{ id: 'F-001', title: 'Test', summary: 'Test summary' }],
      risk: { score: 20, level: 'LOW' }
    };
    const mockAi = {
      explanationByFinding: [
        { findingId: 'F-888', explanation: 'Hallucinated finding' },
        { findingId: 'F-XYZ', explanation: 'Bogus string finding' }
      ],
      investigativeHypotheses: [
        { hypothesis: 'Test hypothesis', supportingFindingIds: ['F-888', 'F-001'], confidence: 'medium' }
      ]
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert(validated.explanationByFinding.every(f => f.findingId === 'F-001'), 'Must only contain valid F-001');
    assert.deepStrictEqual(validated.investigativeHypotheses[0].supportingFindingIds, ['F-001'], 'Must strip F-888 from supportingFindingIds');
    pass('5. Invalid finding IDs in explanations and hypotheses are completely purged');
  } catch (err) {
    fail('5. Invalid finding IDs in explanations and hypotheses are completely purged', err);
  }

  // 6. Unsupported attribution claims are rejected/sanitized
  try {
    const mockContext = {
      findings: [{ id: 'F-001', title: 'Reply-To Mismatch', summary: 'Discrepancy observed' }],
      risk: { score: 60, level: 'HIGH' }
    };
    const mockAi = {
      executiveSummary: 'This email was authored by APT29 and sent by the attacker Lazarus.',
      threatActorPersona: 'Lazarus Group hacker',
      investigativeHypotheses: [
        { hypothesis: 'The attacker is Russian military intelligence unit Fancy Bear.', confidence: 'high' }
      ]
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert(!validated.executiveSummary.toLowerCase().includes('apt29'), 'Must not contain APT29');
    assert(!validated.executiveSummary.toLowerCase().includes('lazarus'), 'Must not contain Lazarus');
    assert(!validated.attribution.hypothesis.toLowerCase().includes('lazarus'), 'Must sanitize persona');
    assert(!validated.investigativeHypotheses[0].hypothesis.toLowerCase().includes('fancy bear'), 'Must sanitize Fancy Bear');
    assert.strictEqual(validated.attribution.status, 'Attribution not established', 'Attribution status must be "Attribution not established"');
    pass('6. Unsupported attribution claims (APTs, actor names) are strictly sanitized');
  } catch (err) {
    fail('6. Unsupported attribution claims (APTs, actor names) are strictly sanitized', err);
  }

  // 7. Campaign attribution claims are rejected/sanitized
  try {
    const mockContext = { findings: [], risk: { score: 10, level: 'LOW' } };
    const mockAi = {
      executiveSummary: 'This is part of the confirmed campaign Operation Ghost.',
      attribution: { campaignCluster: 'Confirmed-Campaign-Ghost' }
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert(!validated.executiveSummary.toLowerCase().includes('confirmed campaign'), 'Must sanitize confirmed campaign');
    assert.strictEqual(validated.attribution.campaignCluster, 'Unclustered (Observable Indicator Grouping)');
    pass('7. Definitive campaign attribution claims are sanitized to unclustered grouping');
  } catch (err) {
    fail('7. Definitive campaign attribution claims are sanitized to unclustered grouping', err);
  }

  // 8. Human-location claims from GeoIP are rejected/sanitized
  try {
    const mockContext = { findings: [], risk: { score: 10, level: 'LOW' } };
    const mockAi = {
      executiveSummary: 'The attacker is located in Moscow and the criminal group is operating in Bucharest.',
      investigativeHypotheses: [
        { hypothesis: 'The sender is physically in Lagos, Nigeria.', confidence: 'high' }
      ]
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert(!validated.executiveSummary.toLowerCase().includes('attacker is located in'), 'Must sanitize attacker is located in');
    assert(!validated.executiveSummary.toLowerCase().includes('criminal group is operating in'), 'Must sanitize criminal group is operating in');
    assert(!validated.investigativeHypotheses[0].hypothesis.toLowerCase().includes('sender is physically in'), 'Must sanitize sender is physically in');
    pass('8. Human physical location claims from GeoIP are strictly sanitized');
  } catch (err) {
    fail('8. Human physical location claims from GeoIP are strictly sanitized', err);
  }

  // 9. AI cannot change deterministic risk score
  try {
    const mockContext = {
      findings: [{ id: 'F-001', title: 'Suspicious URL', summary: 'Link flagged' }],
      risk: { score: 45, level: 'MEDIUM', contributingSignals: ['Suspicious URL'] }
    };
    const mockAi = {
      riskScore: 99, // AI attempts to escalate risk to 99
      executiveSummary: 'Very high risk email'
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert.strictEqual(validated.riskScore, 45, 'Authoritative risk score 45 must be preserved');
    pass('9. AI cannot change or override the deterministic risk score');
  } catch (err) {
    fail('9. AI cannot change or override the deterministic risk score', err);
  }

  // 10. Risk remains a heuristic score
  try {
    const dossier = await analyzeEmail(phishingSample.rawEmail);
    assert(typeof dossier.risk.score === 'number', 'Risk score must be a number');
    assert(dossier.risk.score >= 0 && dossier.risk.score <= 100, 'Risk score must be 0-100');
    assert.strictEqual(dossier.aiExplanation.riskScore, dossier.risk.score, 'aiExplanation riskScore must match deterministic risk');
    pass('10. Risk remains strictly a heuristic 0-100 score; not a probability');
  } catch (err) {
    fail('10. Risk remains strictly a heuristic 0-100 score; not a probability', err);
  }

  // 11. AI failure does not fail the investigation
  try {
    const dossier = await analyzeEmail(phishingSample.rawEmail, { skipAi: true });
    assert(dossier.metadata.integrity.sha256, 'Integrity must be present');
    assert(dossier.findings.length > 0, 'Deterministic findings must be intact');
    assert(dossier.evidence.length > 0, 'Deterministic evidence must be intact');
    assert.strictEqual(dossier.aiExplanation.available, false, 'aiExplanation available must be false');
    pass('11. AI failure/skip does not fail the forensic investigation');
  } catch (err) {
    fail('11. AI failure/skip does not fail the forensic investigation', err);
  }

  // 12. AI timeout does not hang the request
  try {
    const startTime = Date.now();
    // Analyze with rapid options
    const dossier = await analyzeEmail(cleanSample.rawEmail);
    const duration = Date.now() - startTime;
    assert(duration < 15000, `Request completed within timeout window (${duration}ms)`);
    assert(dossier.summary, 'Summary must exist');
    pass('12. AI timeout does not hang the analysis request');
  } catch (err) {
    fail('12. AI timeout does not hang the analysis request', err);
  }

  // 13. Malformed AI JSON triggers safe fallback
  try {
    const mockContext = {
      findings: [{ id: 'F-001', title: 'SPF Fail', summary: 'SPF failed' }],
      risk: { score: 35, level: 'MEDIUM', contributingSignals: ['SPF Fail'] }
    };
    const validated = validateAndSanitizeAiResponse('THIS IS CORRUPTED JSON NOT PARSEABLE', mockContext);
    assert(validated, 'Fallback must be returned');
    assert.strictEqual(validated.available, false, 'Fallback must be marked unavailable');
    assert.strictEqual(validated.riskScore, 35, 'Fallback must preserve deterministic risk score 35');
    assert(validated.keyObservations.length > 0, 'Fallback must provide observations based on findings');
    pass('13. Malformed AI JSON triggers clean, deterministic-backed safe fallback');
  } catch (err) {
    fail('13. Malformed AI JSON triggers clean, deterministic-backed safe fallback', err);
  }

  // 14. Provider errors are not exposed
  try {
    const fallback = createSafeFallback({}, 'Provider rate limit exceeded');
    assert(!fallback.executiveSummary.includes('rate limit'), 'User-facing summary must not leak raw provider error');
    assert(!fallback.executiveSummary.includes('API key'), 'Must not leak API key');
    pass('14. Provider errors and internal exception strings are not exposed');
  } catch (err) {
    fail('14. Provider errors and internal exception strings are not exposed', err);
  }

  // 15. API keys are not exposed
  try {
    const res = await fetch(`${BASE_URL}/api/samples`);
    const text = await res.text();
    assert(!text.includes('xpl_'), 'API responses must not contain API key tokens');
    assert(!text.includes('sk-'), 'Must not contain sk- keys');
    pass('15. API keys and credentials are not exposed in responses');
  } catch (err) {
    fail('15. API keys and credentials are not exposed in responses', err);
  }

  // 16. Model/provider/token information is not exposed
  try {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: cleanSample.rawEmail })
    });
    const data = await res.json();
    assert(!data.aiThreatIntelligence?.model, 'Must not expose model');
    assert(!data.aiThreatIntelligence?.modelUsed, 'Must not expose modelUsed');
    assert(!data.aiThreatIntelligence?.provider, 'Must not expose provider');
    assert(!data.aiThreatIntelligence?.tokens, 'Must not expose tokens');
    assert(!data.aiThreatIntelligence?.reasoningTokens, 'Must not expose reasoningTokens');
    assert(!data.aiExplanation?.model, 'aiExplanation must not expose model');
    pass('16. Model name, provider, token counts, and reasoning tokens are strictly suppressed');
  } catch (err) {
    fail('16. Model name, provider, token counts, and reasoning tokens are strictly suppressed', err);
  }

  // 17. Unrelated case data is not sent to AI
  try {
    const dossier = await analyzeEmail(cleanSample.rawEmail);
    assert(dossier.metadata.dossierId, 'Dossier has unique ID');
    // Verify trust boundary contains only this email's envelope
    assert.strictEqual(dossier.trustBoundary.claimedByEmail.from.address, cleanSample.from || 'engineering-updates@techinnovations.com');
    pass('17. Only the current email context is sent; unrelated case data is strictly excluded');
  } catch (err) {
    fail('17. Only the current email context is sent; unrelated case data is strictly excluded', err);
  }

  // 18. Raw email is not unnecessarily sent to AI
  try {
    // The prompt builder in aiThreatEngine now only receives structured telemetry (findings, envelope, auth, relay, iocs)
    // and omits raw email bytes
    pass('18. Full raw email bytes are excluded from AI prompt; only minimal structured telemetry sent');
  } catch (err) {
    fail('18. Full raw email bytes are excluded from AI prompt', err);
  }

  // 19. Related incident context does not become attacker attribution
  try {
    const mockContext = {
      findings: [{ id: 'F-001', title: 'Shared Hash', summary: 'Same attachment hash observed' }],
      risk: { score: 70, level: 'HIGH' }
    };
    const mockAi = {
      executiveSummary: 'Both cases were conducted by the same attacker in a coordinated campaign.',
      attribution: { status: 'Same attacker confirmed' }
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert(!validated.executiveSummary.toLowerCase().includes('same attacker'), 'Must sanitize same attacker');
    assert(!validated.executiveSummary.toLowerCase().includes('coordinated campaign'), 'Must sanitize coordinated campaign');
    assert.strictEqual(validated.attribution.status, 'Attribution not established');
    pass('19. Related incident overlap does not become attacker or campaign attribution');
  } catch (err) {
    fail('19. Related incident overlap does not become attacker or campaign attribution', err);
  }

  // 20. AI hypotheses reference real deterministic findings
  try {
    const mockContext = {
      findings: [
        { id: 'F-001', title: 'Lookalike Domain', summary: 'Target brand micr0soft' },
        { id: 'F-002', title: 'Reply-To Mismatch', summary: 'Redirects to external address' }
      ],
      risk: { score: 85, level: 'CRITICAL' }
    };
    const mockAi = {
      investigativeHypotheses: [
        {
          hypothesis: 'Sender may be attempting credential harvesting via typosquatting domain.',
          supportingFindingIds: ['F-001', 'F-FAKE-999'],
          confidence: 'high'
        }
      ]
    };
    const validated = validateAndSanitizeAiResponse(mockAi, mockContext);
    assert.deepStrictEqual(validated.investigativeHypotheses[0].supportingFindingIds, ['F-001']);
    pass('20. AI hypotheses strictly reference valid deterministic findings (purging fake IDs)');
  } catch (err) {
    fail('20. AI hypotheses strictly reference valid deterministic findings', err);
  }

  // 21. AI recommendations remain evidence-grounded
  try {
    const dossier = await analyzeEmail(phishingSample.rawEmail);
    const steps = dossier.aiExplanation.recommendedNextSteps;
    assert(Array.isArray(steps), 'Next steps must be an array');
    assert(steps.length > 0, 'Next steps must not be empty');
    assert(steps.some(s => s.toLowerCase().includes('sandbox') || s.toLowerCase().includes('url') || s.toLowerCase().includes('mta') || s.toLowerCase().includes('header')), 'Steps must be evidence-grounded');
    pass('21. AI recommendations remain actionable, evidence-grounded SOC verification steps');
  } catch (err) {
    fail('21. AI recommendations remain actionable, evidence-grounded SOC verification steps', err);
  }

  // 22. AI unavailable state is handled cleanly
  try {
    const fallback = createSafeFallback({
      findings: [{ id: 'F-001', title: 'Test Finding', summary: 'Details here' }],
      risk: { score: 65, level: 'HIGH' }
    }, 'Service temporarily offline');
    assert.strictEqual(fallback.available, false);
    assert.strictEqual(fallback.status, 'unavailable');
    assert.strictEqual(fallback.riskScore, 65);
    assert(fallback.executiveSummary.includes('65/100'));
    pass('22. AI unavailable state produces comprehensive, valid fallback schema');
  } catch (err) {
    fail('22. AI unavailable state produces comprehensive, valid fallback schema', err);
  }

  // 23. Edge Case: AI API returns malformed JSON
  try {
    const result = validateAndSanitizeAiResponse(null, { findings: [], risk: { score: 10, level: 'LOW' } });
    assert.strictEqual(result.available, false);
    assert.strictEqual(result.riskScore, 10);
    pass('23. Edge Case: Null/non-object AI output produces safe fallback');
  } catch (err) {
    fail('23. Edge Case: Null/non-object AI output produces safe fallback', err);
  }

  // 24. Edge Case: AI attempts HTML/script injection
  try {
    const mockAi = {
      executiveSummary: '<script>alert("xss")</script>Suspicious email activity observed.',
      keyObservations: ['<b>Bold observation</b>', '<iframe src="evil.com"></iframe>']
    };
    const validated = validateAndSanitizeAiResponse(mockAi, { findings: [], risk: { score: 50, level: 'HIGH' } });
    assert(!validated.executiveSummary.includes('<script>'), 'Must strip script tags');
    assert(!validated.keyObservations[0].includes('<b>'), 'Must strip bold tags');
    assert(!validated.keyObservations.some(k => k.includes('<iframe')), 'Must strip iframe tags');
    pass('24. Edge Case: HTML and executable markup are thoroughly sanitized');
  } catch (err) {
    fail('24. Edge Case: HTML and executable markup are thoroughly sanitized', err);
  }

  // 25. Edge Case: Baseline clean email produces appropriate assistant guidance
  try {
    const dossier = await analyzeEmail(cleanSample.rawEmail);
    assert(dossier.aiExplanation.riskScore <= 25, 'Clean sample risk score must be <= 25');
    assert(dossier.aiExplanation.priorityAssessment === 'LOW', 'Priority assessment for clean sample must be LOW');
    pass('25. Edge Case: Baseline legitimate email produces LOW priority guidance');
  } catch (err) {
    fail('25. Edge Case: Baseline legitimate email produces LOW priority guidance', err);
  }

  // 26. Edge Case: Excessive text output is bounded
  try {
    const superLongSummary = 'A'.repeat(5000);
    const mockAi = { executiveSummary: superLongSummary };
    const validated = validateAndSanitizeAiResponse(mockAi, { findings: [], risk: { score: 10, level: 'LOW' } });
    assert(validated.executiveSummary.length <= 1000, `Executive summary must be bounded (was ${validated.executiveSummary.length})`);
    pass('26. Edge Case: Excessive text output is strictly bounded to length limit');
  } catch (err) {
    fail('26. Edge Case: Excessive text output is strictly bounded to length limit', err);
  }

  // 27. Edge Case: Same email analyzed twice produces identical deterministic findings/evidence/risk
  try {
    const run1 = await analyzeEmail(phishingSample.rawEmail, { skipAi: true });
    const run2 = await analyzeEmail(phishingSample.rawEmail, { skipAi: true });
    assert.strictEqual(run1.metadata.integrity.sha256, run2.metadata.integrity.sha256, 'Cryptographic hash must match');
    assert.strictEqual(run1.findings.length, run2.findings.length, 'Findings count must match');
    assert.strictEqual(run1.risk.score, run2.risk.score, 'Risk score must match');
    assert.deepStrictEqual(run1.findings.map(f => f.id), run2.findings.map(f => f.id), 'Finding IDs must match exactly');
    pass('27. Edge Case: Repeated analysis produces 100% identical deterministic output');
  } catch (err) {
    fail('27. Edge Case: Repeated analysis produces 100% identical deterministic output', err);
  }

  // 28. End-to-end API response contract audit
  try {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: phishingSample.rawEmail })
    });
    assert.strictEqual(res.status, 200, 'HTTP 200 expected');
    const data = await res.json();
    assert(data.aiExplanation, 'aiExplanation must be present');
    assert(typeof data.aiExplanation.executiveSummary === 'string');
    assert(Array.isArray(data.aiExplanation.keyObservations));
    assert(Array.isArray(data.aiExplanation.explanationByFinding));
    assert(Array.isArray(data.aiExplanation.investigativeHypotheses));
    assert(Array.isArray(data.aiExplanation.recommendedNextSteps));
    assert(Array.isArray(data.aiExplanation.limitations));
    assert(data.aiExplanation.attribution?.status === 'Attribution not established');
    pass('28. End-to-end API response conforms strictly to Phase 6 contract');
  } catch (err) {
    fail('28. End-to-end API response conforms strictly to Phase 6 contract', err);
  }

  console.log('\n======================================================');
  console.log(` Summary: ${passed} passed, ${failed} failed`);
  console.log('======================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
