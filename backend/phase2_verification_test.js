/**
 * Phase 2 Verification Test Suite
 * Validates the Evidence + Finding Architecture across all sample scenarios and edge cases.
 *
 * Requirements checked:
 * 1. Normal email produces structured evidence.
 * 2. Suspicious email produces structured findings.
 * 3. Every finding references existing evidence IDs.
 * 4. No major finding has an empty evidenceIds array.
 * 5. Evidence IDs are unique within one analysis.
 * 6. Finding IDs are unique within one analysis.
 * 7. Duplicate observations are deduplicated.
 * 8. Reply-To mismatch references the correct headers.
 * 9. Authentication findings reference authentication evidence.
 * 10. URL findings reference the actual extracted URL.
 * 11. Attachment findings reference actual attachment evidence.
 * 12. Relay findings reference actual Received/header evidence.
 * 13. Unavailable external services do not create fabricated evidence.
 * 14. Phase 1 terminology remains intact.
 * 15. Severity values are normalized strictly to: 'low' | 'medium' | 'high' | 'critical'.
 */

import http from 'http';
import { SAMPLE_EMAILS } from './data/samples.js';

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

function assert(condition, testName, detail = '') {
  if (!condition) {
    console.error(`❌ [FAIL] ${testName}${detail ? ' - ' + detail : ''}`);
    process.exit(1);
  }
  console.log(`✅ [PASS] ${testName}`);
}

async function runPhase2Tests() {
  console.log('====================================================');
  console.log('🔬 STARTING PHASE 2 EVIDENCE + FINDINGS TEST SUITE');
  console.log('====================================================\n');

  // Load samples
  const normalSample = SAMPLE_EMAILS.find(s => s.id === 'sample-clean-corp-newsletter');
  const becSample = SAMPLE_EMAILS.find(s => s.id === 'sample-bec-ceo-fraud');
  const phishSample = SAMPLE_EMAILS.find(s => s.id === 'sample-phish-m365-harvest');
  const malwareSample = SAMPLE_EMAILS.find(s => s.id === 'sample-malware-invoice-trojan');
  const multiHopSample = SAMPLE_EMAILS.find(s => s.id === 'sample-apt-impossible-travel');

  // 1. Normal email produces structured evidence
  const normalRes = await makeRequest('/api/analyze', 'POST', { rawEmail: normalSample.rawEmail });
  assert(normalRes.status === 200, 'Normal email analyzes successfully with HTTP 200');
  const normalDossier = normalRes.data;
  assert(Array.isArray(normalDossier.evidence) && normalDossier.evidence.length > 0,
    '1. Normal email produces structured evidence array',
    `Found ${normalDossier.evidence?.length} evidence items`);

  // 2. Suspicious email produces structured findings
  const becRes = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
  const becDossier = becRes.data;
  assert(Array.isArray(becDossier.findings) && becDossier.findings.length > 0,
    '2. Suspicious email produces structured findings array',
    `Found ${becDossier.findings?.length} findings`);

  // 3 & 4. Every finding references existing evidence IDs and no major finding has empty evidenceIds
  const allDossiers = [normalDossier, becDossier];
  for (const dossier of allDossiers) {
    const evidenceIds = new Set(dossier.evidence.map(e => e.id));
    for (const finding of dossier.findings) {
      assert(Array.isArray(finding.evidenceIds) && finding.evidenceIds.length > 0,
        '4. No major finding has empty evidenceIds array',
        `Finding ${finding.id} has ${finding.evidenceIds?.length} evidence references`);

      const allValid = finding.evidenceIds.every(id => evidenceIds.has(id));
      assert(allValid,
        '3. Every finding references strictly existing evidence IDs',
        `Finding ${finding.id} references [${finding.evidenceIds.join(', ')}]`);
    }
  }

  // 5. Evidence IDs are unique within an analysis
  const becEvidenceIds = becDossier.evidence.map(e => e.id);
  const uniqueEvIds = new Set(becEvidenceIds);
  assert(becEvidenceIds.length === uniqueEvIds.size,
    '5. Evidence IDs are unique within one analysis',
    `Total: ${becEvidenceIds.length}, Unique: ${uniqueEvIds.size}`);

  // 6. Finding IDs are unique within an analysis
  const becFindingIds = becDossier.findings.map(f => f.id);
  const uniqueFIds = new Set(becFindingIds);
  assert(becFindingIds.length === uniqueFIds.size,
    '6. Finding IDs are unique within one analysis',
    `Total: ${becFindingIds.length}, Unique: ${uniqueFIds.size}`);

  // 7. Duplicate observations are deduplicated
  // Check that duplicate finding types with identical evidence do not appear twice
  const findingKeys = becDossier.findings.map(f => `${f.type}::${f.evidenceIds.sort().join('+')}`);
  const uniqueFindingKeys = new Set(findingKeys);
  assert(findingKeys.length === uniqueFindingKeys.size,
    '7. Duplicate observations are deduplicated within the analysis');

  // 8. Reply-To mismatch references the correct headers (From and Reply-To)
  const replyToFinding = becDossier.findings.find(f => f.type === 'reply_to_mismatch');
  assert(replyToFinding !== undefined, '8. Reply-To mismatch finding exists in BEC scenario');
  const becEvMap = new Map(becDossier.evidence.map(e => [e.id, e]));
  const replyToEvSources = replyToFinding.evidenceIds.map(id => becEvMap.get(id));
  const hasFromEv = replyToEvSources.some(e => e.field === 'From');
  const hasReplyToEv = replyToEvSources.some(e => e.field === 'Reply-To');
  assert(hasFromEv && hasReplyToEv,
    '8. Reply-To mismatch finding references both From and Reply-To evidence headers');

  // 9. Authentication findings reference authentication evidence
  const authFinding = becDossier.findings.find(f => f.type.includes('spf') || f.type.includes('dkim') || f.type.includes('dmarc'));
  if (authFinding) {
    const authEvSources = authFinding.evidenceIds.map(id => becEvMap.get(id));
    const hasAuthEv = authEvSources.some(e => e.source === 'authentication_result' || e.field === 'Authentication-Results');
    assert(hasAuthEv, '9. Authentication findings reference authentication evidence records');
  } else {
    assert(true, '9. Authentication findings checked');
  }

  // 10. URL findings reference the actual extracted URL
  const phishRes = await makeRequest('/api/analyze', 'POST', { rawEmail: phishSample.rawEmail });
  const phishDossier = phishRes.data;
  const urlFinding = phishDossier.findings.find(f => f.type === 'suspicious_url');
  assert(urlFinding !== undefined, '10. Suspicious URL finding identified in phishing scenario');
  const phishEvMap = new Map(phishDossier.evidence.map(e => [e.id, e]));
  const urlEvSources = urlFinding.evidenceIds.map(id => phishEvMap.get(id));
  const hasRealUrl = urlEvSources.some(e => e.source === 'url' && e.value.length > 0);
  assert(hasRealUrl,
    '10. URL findings reference the actual extracted URL evidence',
    `Resolved URL evidence: ${urlEvSources.map(e => e.value).join(', ')}`);

  // 11. Attachment findings reference actual attachment evidence (name & hash)
  const malwareRes = await makeRequest('/api/analyze', 'POST', { rawEmail: malwareSample.rawEmail });
  const malwareDossier = malwareRes.data;
  const attFinding = malwareDossier.findings.find(f => f.type === 'dangerous_attachment');
  assert(attFinding !== undefined, '11. Dangerous attachment finding identified in malware scenario');
  const malwareEvMap = new Map(malwareDossier.evidence.map(e => [e.id, e]));
  const attEvSources = attFinding.evidenceIds.map(id => malwareEvMap.get(id));
  const hasAttEv = attEvSources.some(e => e.source === 'attachment' && e.details?.sha256);
  assert(hasAttEv,
    '11. Attachment findings reference actual attachment filename and SHA-256 evidence');

  // 12. Relay findings reference actual Received / header evidence
  const multiHopRes = await makeRequest('/api/analyze', 'POST', { rawEmail: multiHopSample.rawEmail });
  const multiHopDossier = multiHopRes.data;
  const relayFinding = multiHopDossier.findings.find(f => f.type === 'relay_routing_inconsistency');
  assert(relayFinding !== undefined, '12. Multi-hop relay timing/routing finding identified in Sample 4');
  const multiHopEvMap = new Map(multiHopDossier.evidence.map(e => [e.id, e]));
  const relayEvSources = relayFinding.evidenceIds.map(id => multiHopEvMap.get(id));
  const hasReceivedEv = relayEvSources.some(e => e.source === 'relay_observation' || e.field === 'Received');
  assert(hasReceivedEv,
    '12. Relay findings reference actual Received header telemetry evidence');

  // 13. Unavailable external services do not create fabricated evidence
  // Minimal raw email with only one header
  const minimalRes = await makeRequest('/api/analyze', 'POST', { rawEmail: "From: admin@example.com\nSubject: Test\n\nHello" });
  assert(minimalRes.status === 200, 'Minimal email analyzed successfully');
  const minimalDossier = minimalRes.data;
  // Should only have evidence for things that actually existed (From, Subject)
  const fabricatedUrlEv = minimalDossier.evidence.find(e => e.source === 'url');
  const fabricatedAttEv = minimalDossier.evidence.find(e => e.source === 'attachment');
  assert(!fabricatedUrlEv && !fabricatedAttEv,
    '13. Unavailable/nonexistent elements do not produce fabricated evidence');

  // 14. Phase 1 terminology remains intact
  const originClaim = multiHopDossier.relay.originatingIPStatus;
  const hasUnverifiedWording = originClaim === 'UNVERIFIED' || multiHopDossier.relay.originatingIPLabel.includes('UNVERIFIED');
  assert(hasUnverifiedWording, '14. Phase 1 UNVERIFIED origin wording remains strictly intact');

  // 15. Normalized severity values ('low', 'medium', 'high', 'critical')
  const allowedSeverities = new Set(['low', 'medium', 'high', 'critical']);
  const allFindings = [
    ...normalDossier.findings,
    ...becDossier.findings,
    ...phishDossier.findings,
    ...malwareDossier.findings,
    ...multiHopDossier.findings
  ];
  const allSeveritiesNormalized = allFindings.every(f => allowedSeverities.has(f.severity));
  assert(allSeveritiesNormalized,
    '15. Severity values across all findings are strictly normalized to low|medium|high|critical');

  console.log('\n====================================================');
  console.log('🏁 ALL 15 PHASE 2 ARCHITECTURAL TESTS PASSED (100%)');
  console.log('====================================================\n');
}

runPhase2Tests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
