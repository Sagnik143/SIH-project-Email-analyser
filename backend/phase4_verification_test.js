/**
 * Phase 4 Verification Test Suite
 * Canonical Investigation Pipeline & Unified Engine Architecture
 *
 * Tests:
 * 1. /api/analyze uses the central investigation engine
 * 2. /api/cases/:id/emails uses the same engine
 * 3. Identical email produces consistent deterministic evidence/findings
 * 4. Evidence exists before findings (proper sequence & ID mapping)
 * 5. Every finding references valid evidence IDs
 * 6. Raw email hash is calculated directly from original content
 * 7. Authentication reported vs independently verified distinction
 * 8. Claimed origin is not labeled attacker IP or criminal location
 * 9. GeoIP is not represented as human location
 * 10. Relay timing anomaly uses defensible terminology (no "impossible travel")
 * 11. Attribution does not make unsupported actor/campaign claims
 * 12. AI cannot add unsupported findings (authoritative deterministic findings)
 * 13. AI/external service failure does not destroy deterministic analysis
 * 14. Risk score remains heuristic 0-100 with contributing signals
 * 15. Existing /api/analyze backward compatibility remains intact
 * 16. Case-based analysis persists the same evidence/findings as stateless analysis
 * 17. No secrets/model branding/internal errors leak into response
 * 18. Verification of Phase 1 invariants
 * 19. Verification of Phase 2 invariants
 * 20. Verification of Phase 3 invariants
 */

import http from 'http';
import crypto from 'crypto';
import { SAMPLE_EMAILS } from './data/samples.js';
import { analyzeEmail, calculateHeuristicRisk } from './services/investigationEngine.js';
import { createCase, getCaseById } from './db/caseRepository.js';

const API_HOST = 'localhost';
const API_PORT = 5001;

function makeRequest(path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const options = {
      hostname: API_HOST,
      port: API_PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {})
      },
      timeout: 30000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, raw: data });
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    if (postData) req.write(postData);
    req.end();
  });
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion Failed: ${message}`);
  }
}

let passedCount = 0;
let failedCount = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    passedCount++;
  } catch (err) {
    console.error(`  FAIL: ${name}`);
    console.error(`        ${err.message}`);
    failedCount++;
  }
}

async function runPhase4Verification() {
  console.log('\n======================================================');
  console.log(' AegisMail Phase 4: Canonical Investigation Engine Tests');
  console.log('======================================================\n');

  const becSample = SAMPLE_EMAILS.find(s => s.id === 'sample-bec-ceo-fraud') || SAMPLE_EMAILS[0];
  const legitimateSample = SAMPLE_EMAILS.find(s => s.id === 'sample-clean-corp-newsletter') || SAMPLE_EMAILS[4];
  const routingSample = SAMPLE_EMAILS.find(s => s.id === 'sample-apt-impossible-travel') || SAMPLE_EMAILS[3];

  // 1. /api/analyze uses the central investigation engine
  await test('1. /api/analyze uses the central investigation engine', async () => {
    const res = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    assert(res.data.metadata && res.data.metadata.engine.includes('Canonical Investigation Engine'), 'Response metadata must indicate Canonical Investigation Engine');
    assert(res.data.trustBoundary !== undefined, 'Response must include Phase 4 trustBoundary');
    assert(res.data.risk !== undefined && typeof res.data.risk.score === 'number', 'Response must include canonical risk structure');
  });

  // 2. /api/cases/:id/emails uses the same engine
  await test('2. /api/cases/:id/emails uses the same engine', async () => {
    const caseRes = await makeRequest('/api/cases', 'POST', { title: 'Phase 4 Engine Equivalence Case' });
    assert(caseRes.status === 201, 'Case creation must succeed');
    const caseId = caseRes.data.id;

    const attachRes = await makeRequest(`/api/cases/${caseId}/emails`, 'POST', {
      rawEmail: becSample.rawEmail,
      filename: 'bec_email.eml'
    });
    assert(attachRes.status === 201, `Expected 201, got ${attachRes.status}`);
    const dossier = attachRes.data.dossier;
    assert(dossier.metadata && dossier.metadata.engine.includes('Canonical Investigation Engine'), 'Case analysis must use canonical investigation engine');
    assert(dossier.trustBoundary !== undefined, 'Case analysis must produce trustBoundary');
    assert(dossier.risk && typeof dossier.risk.score === 'number', 'Case analysis must produce risk data');
  });

  // 3. Identical email produces consistent deterministic evidence/findings
  await test('3. Identical email produces consistent deterministic evidence/findings', async () => {
    const analysis1 = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    const analysis2 = await analyzeEmail(becSample.rawEmail, { skipAi: true });

    assert(analysis1.evidence.length === analysis2.evidence.length, 'Evidence count must be strictly deterministic');
    assert(analysis1.findings.length === analysis2.findings.length, 'Finding count must be strictly deterministic');
    assert(analysis1.risk.score === analysis2.risk.score, 'Risk score must be identical across runs');

    for (let i = 0; i < analysis1.findings.length; i++) {
      assert(analysis1.findings[i].id === analysis2.findings[i].id, `Finding ID mismatch at index ${i}`);
      assert(analysis1.findings[i].type === analysis2.findings[i].type, `Finding type mismatch at index ${i}`);
      assert(analysis1.findings[i].severity === analysis2.findings[i].severity, `Finding severity mismatch at index ${i}`);
    }
  });

  // 4. Evidence exists before findings (proper sequence & ID mapping)
  await test('4. Evidence exists before findings', async () => {
    const analysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    assert(analysis.evidence.length > 0, 'Evidence must be collected');
    assert(analysis.findings.length > 0, 'Findings must be generated');

    // Verify evidence IDs follow E-001..
    assert(analysis.evidence[0].id === 'E-001', 'First evidence must be E-001');
    assert(analysis.findings[0].id === 'F-001', 'First finding must be F-001');
  });

  // 5. Every finding references valid evidence IDs
  await test('5. Every finding references valid evidence IDs', async () => {
    const analysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    const evidenceIdSet = new Set(analysis.evidence.map(e => e.id));

    for (const finding of analysis.findings) {
      assert(Array.isArray(finding.evidenceIds) && finding.evidenceIds.length >= 1, `Finding ${finding.id} has no evidence references`);
      for (const evId of finding.evidenceIds) {
        assert(evidenceIdSet.has(evId), `Finding ${finding.id} references unregistered evidence ${evId}`);
      }
    }
  });

  // 6. Raw email hash is calculated directly from original content
  await test('6. Raw email hash is calculated directly from original content', async () => {
    const raw = becSample.rawEmail;
    const expectedSha256 = crypto.createHash('sha256').update(raw, 'utf-8').digest('hex');
    const expectedMd5 = crypto.createHash('md5').update(raw, 'utf-8').digest('hex');

    const analysis = await analyzeEmail(raw, { skipAi: true });
    assert(analysis.integrity.sha256 === expectedSha256, 'integrity.sha256 must match raw content SHA-256');
    assert(analysis.integrity.md5 === expectedMd5, 'integrity.md5 must match raw content MD5');
    assert(analysis.metadata.integrity.sha256 === expectedSha256, 'metadata.integrity.sha256 must match raw content SHA-256');
  });

  // 7. Authentication reported vs independently verified distinction
  await test('7. Authentication reported vs independently verified distinction', async () => {
    const analysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    const auth = analysis.authentication;

    assert(auth.spf.source === 'Reported by receiving system' || auth.evaluationContext?.source === 'Reported by receiving system', 'Must label authentication as reported by receiving system');
    assert(auth.spf.independentValidationPerformed === false, 'Must not claim SPF was independently validated');
    assert(auth.evaluationContext?.independentValidationPerformed === false, 'Must acknowledge independent validation was not performed');
  });

  // 8. Claimed origin is not labeled attacker IP or criminal location
  await test('8. Claimed origin is not labeled attacker IP or criminal location', async () => {
    const analysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    const relay = analysis.relay;

    const strToCheck = JSON.stringify({
      originatingIPLabel: relay.originatingIPLabel,
      originatingIPStatus: relay.originatingIPStatus,
      originGeo: analysis.originGeo
    }).toLowerCase();

    assert(!strToCheck.includes('attacker ip'), 'Must not label IP as "attacker IP"');
    assert(!strToCheck.includes('attacker location'), 'Must not label origin as "attacker location"');
    assert(!strToCheck.includes('criminal location'), 'Must not label origin as "criminal location"');
    assert(relay.originatingIPStatus === 'UNVERIFIED', 'Claimed origin must be labeled UNVERIFIED');
  });

  // 9. GeoIP is not represented as human location
  await test('9. GeoIP is not represented as human location', async () => {
    const analysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    const geo = analysis.geolocation;

    assert(geo.disclaimer && geo.disclaimer.includes('network infrastructure'), 'GeoIP must include network infrastructure disclaimer');
    assert(geo.disclaimer.includes('physical'), 'GeoIP disclaimer must explain it does not establish physical identity/location');
  });

  // 10. Relay timing anomaly uses defensible terminology (no "impossible travel")
  await test('10. Relay timing anomaly uses defensible terminology', async () => {
    const analysis = await analyzeEmail(routingSample.rawEmail, { skipAi: true });
    const anomalies = analysis.relay.hopAnomalies || [];
    assert(anomalies.length > 0, 'Multi-hop sample must trigger hop anomalies');

    for (const anom of anomalies) {
      assert(!anom.alert.toLowerCase().includes('impossible travel'), 'Must NOT use "impossible travel" in alert');
      assert(!anom.alert.toLowerCase().includes('impossible physical'), 'Must NOT use "impossible physical travel"');
      assert(anom.alert.includes('Timestamp / routing inconsistency') || anom.alert.includes('inconsistency'), 'Must use defensible inconsistency terminology');
    }
  });

  // 11. Attribution does not make unsupported actor/campaign claims
  await test('11. Attribution does not make unsupported actor/campaign claims', async () => {
    const analysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    const graphNodes = analysis.attributionAndGraph?.graphCorrelation?.nodes || [];

    for (const node of graphNodes) {
      assert(node.type !== 'ATTACKER_IP', 'Attribution graph node must NOT be ATTACKER_IP');
      assert(node.type !== 'HIGH_RISK_ATTACKER', 'Attribution graph node must NOT be HIGH_RISK_ATTACKER');
    }

    const attr = analysis.attributionAndGraph?.attributionClassification;
    if (attr?.probableActorType) {
      assert(attr.probableActorType.toLowerCase().includes('profile') || attr.probableActorType.toLowerCase().includes('pattern') || attr.probableActorType.toLowerCase().includes('unverified'), 'Actor attribution must be framed as hypothesis/profile');
    }
  });

  // 12. AI cannot add unsupported findings (authoritative deterministic findings)
  await test('12. AI cannot add unsupported findings', async () => {
    const deterministicFindings = (await analyzeEmail(becSample.rawEmail, { skipAi: true })).findings;
    const fullAnalysis = await analyzeEmail(becSample.rawEmail, { skipAi: false });

    assert(fullAnalysis.findings.length === deterministicFindings.length, 'AI must not invent or append extra findings to findings array');
    for (let i = 0; i < deterministicFindings.length; i++) {
      assert(fullAnalysis.findings[i].id === deterministicFindings[i].id, 'Findings must remain authoritative and deterministic');
    }
  });

  // 13. AI/external service failure does not destroy deterministic analysis
  await test('13. AI/external service failure does not destroy deterministic analysis', async () => {
    const result = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    assert(result.evidence.length > 0, 'Evidence must be present when AI is skipped');
    assert(result.findings.length > 0, 'Findings must be present when AI is skipped');
    assert(result.risk.score > 70, 'Heuristic risk score must be accurately calculated without AI');
    assert(result.aiExplanation.status === 'skipped', 'AI explanation should report skipped status');
  });

  // 14. Risk score remains heuristic 0-100 with contributing signals
  await test('14. Risk score remains heuristic 0-100 with contributing signals', async () => {
    const becAnalysis = await analyzeEmail(becSample.rawEmail, { skipAi: true });
    assert(becAnalysis.risk.score >= 0 && becAnalysis.risk.score <= 100, 'Risk score must be in range 0-100');
    assert(becAnalysis.risk.contributingSignals.length > 0, 'Must expose contributing signals');
    assert(becAnalysis.risk.disclaimer.includes('analytical heuristic'), 'Must explain score is an analytical heuristic');

    const cleanAnalysis = await analyzeEmail(legitimateSample.rawEmail, { skipAi: true });
    assert(cleanAnalysis.risk.score <= 35, 'Legitimate email must have low risk score');
  });

  // 15. Existing /api/analyze backward compatibility remains intact
  await test('15. Existing /api/analyze backward compatibility remains intact', async () => {
    const res = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
    assert(res.status === 200, 'Endpoint must return 200');
    const d = res.data;

    assert(d.dossierId !== undefined, 'dossierId required');
    assert(d.integrity?.sha256 !== undefined, 'integrity.sha256 required');
    assert(d.envelope?.from !== undefined, 'envelope.from required');
    assert(d.relay?.hops !== undefined, 'relay.hops required');
    assert(d.originGeo?.city !== undefined, 'originGeo.city required');
    assert(d.authentication?.spf !== undefined, 'authentication.spf required');
    assert(d.iocs?.urls !== undefined, 'iocs.urls required');
    assert(d.aiThreatIntelligence?.threatClassification !== undefined, 'aiThreatIntelligence.threatClassification required');
    assert(d.attributionAndGraph !== undefined, 'attributionAndGraph required');
    assert(Array.isArray(d.evidence), 'evidence array required');
    assert(Array.isArray(d.findings), 'findings array required');
    assert(d.rawEmail !== undefined, 'rawEmail required');
  });

  // 16. Case-based analysis persists the same evidence/findings as stateless analysis
  await test('16. Case-based analysis persists the same evidence/findings as stateless analysis', async () => {
    const statelessRes = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
    const statelessDossier = statelessRes.data;

    const caseRes = await makeRequest('/api/cases', 'POST', { title: 'Comparison Case' });
    const caseId = caseRes.data.id;

    const caseEmailRes = await makeRequest(`/api/cases/${caseId}/emails`, 'POST', {
      rawEmail: becSample.rawEmail,
      filename: 'stateless_vs_case.eml'
    });
    const caseDossier = caseEmailRes.data.dossier;

    assert(statelessDossier.integrity.sha256 === caseDossier.integrity.sha256, 'SHA-256 must match exactly');
    assert(statelessDossier.evidence.length === caseDossier.evidence.length, 'Evidence count must match');
    assert(statelessDossier.findings.length === caseDossier.findings.length, 'Finding count must match');
    assert(statelessDossier.risk.score === caseDossier.risk.score, 'Risk score must match');

    // Also check retrieved case from database
    const fetchedCase = getCaseById(caseId);
    assert(fetchedCase.evidence.length === statelessDossier.evidence.length, 'Persisted DB evidence count must match stateless evidence count');
    assert(fetchedCase.findings.length === statelessDossier.findings.length, 'Persisted DB finding count must match stateless finding count');
  });

  // 17. No secrets/model branding/internal errors leak into response
  await test('17. No secrets/model branding/internal errors leak into response', async () => {
    const res = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
    const jsonString = JSON.stringify(res.data);

    assert(!jsonString.includes('xpl_e9fa4d3a82375b6433af107e476239849eb972d2'), 'API key must not leak');
    assert(res.data.aiThreatIntelligence?.modelUsed === undefined, 'modelUsed must not be exposed');
    assert(res.data.aiThreatIntelligence?.reasoningTokens === undefined, 'reasoningTokens must not be exposed');
    assert(!jsonString.includes('SQLITE_ERROR'), 'SQL errors must not leak');
  });

  // 18. Verification of Phase 1 invariants
  await test('18. Verification of Phase 1 invariants', async () => {
    const res = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
    const d = res.data;
    assert(d.aiThreatIntelligence.attributionDisclaimer !== undefined, 'Phase 1 disclaimer must be present');
    assert(d.aiThreatIntelligence.investigativeHypothesis !== undefined, 'Phase 1 investigative hypothesis must be present');
  });

  // 19. Verification of Phase 2 invariants
  await test('19. Verification of Phase 2 invariants', async () => {
    const res = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
    assert(Array.isArray(res.data.evidence) && res.data.evidence.length > 0, 'Phase 2 evidence array must be populated');
    assert(Array.isArray(res.data.findings) && res.data.findings.length > 0, 'Phase 2 findings array must be populated');
    assert(res.data.evidence[0].id.startsWith('E-'), 'Evidence ID format must be E-xxx');
    assert(res.data.findings[0].id.startsWith('F-'), 'Finding ID format must be F-xxx');
  });

  // 20. Verification of Phase 3 invariants
  await test('20. Verification of Phase 3 invariants', async () => {
    const caseRes = await makeRequest('/api/cases', 'POST', { title: 'Phase 3 Invariant Check Case' });
    assert(caseRes.status === 201, 'Phase 3 case creation must work');
    const caseData = getCaseById(caseRes.data.id);
    assert(caseData.case.caseNumber.startsWith('CASE-'), 'Case number format must be preserved');
  });

  console.log('\n======================================================');
  console.log(` Summary: ${passedCount} passed, ${failedCount} failed`);
  console.log('======================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runPhase4Verification().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
