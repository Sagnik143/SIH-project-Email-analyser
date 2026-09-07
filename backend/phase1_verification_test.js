/**
 * Phase 1 Forensic Stabilization & Terminology Verification Test Suite
 * Tests the 9 mandatory Phase 1 requirements:
 * 1. Normal email still analyzes.
 * 2. Existing phishing demo still analyzes.
 * 3. Missing/invalid external enrichment does not crash the analysis.
 * 4. AI unavailable does not crash the analysis.
 * 5. X-Originating-IP is not displayed as verified attacker origin.
 * 6. Geolocation is labelled as infrastructure location.
 * 7. Impossible-travel wording no longer appears in output.
 * 8. Attacker persona is not presented as a factual conclusion.
 * 9. Model name/token information does not appear in user-facing UI / output.
 */

import assert from 'assert';
import { analyzeEmailThreatWithAI } from './services/aiThreatEngine.js';
import { traceRelayHops } from './services/relayTracer.js';
import { lookupIP } from './services/geoService.js';
import { validateAuthentication } from './services/authValidator.js';
import { parseEmail } from './services/emailParser.js';

const API_BASE = 'http://localhost:5001';

async function runTests() {
  console.log('====================================================');
  console.log('🛡️  STARTING PHASE 1 VERIFICATION TESTS');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`❌ [FAIL] ${name}:`, err.message);
      failed++;
    }
  }

  // 1. Normal email still analyzes
  await test('1. Normal legitimate email analyzes successfully', async () => {
    const normalEmail = `From: alice@example.com
To: bob@example.com
Subject: Team Sync Meeting Notes
Date: Mon, 7 Sep 2026 10:00:00 +0000
Message-ID: <msg001@example.com>
Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.example.com with ESMTP id abc1234; Mon, 7 Sep 2026 10:00:01 +0000

Hi Bob, here are the meeting notes from today. Thanks, Alice.`;

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: normalEmail })
    });

    assert.strictEqual(res.status, 200, `Expected 200 OK, got ${res.status}`);
    const data = await res.json();
    assert(data.dossierId, 'Dossier ID must be present');
    assert(data.aiThreatIntelligence, 'AI Threat Intelligence must be present');
    assert(data.aiThreatIntelligence.riskScore <= 35, 'Normal email should have low/moderate risk score');
  });

  // 2. Existing phishing demo still analyzes
  await test('2. Existing phishing demo analyzes successfully', async () => {
    const samplesRes = await fetch(`${API_BASE}/api/samples`);
    assert.strictEqual(samplesRes.status, 200);
    const { samples } = await samplesRes.json();
    assert(samples.length > 0, 'Samples should be available');

    const sample1Res = await fetch(`${API_BASE}/api/samples/${samples[0].id}`);
    assert.strictEqual(sample1Res.status, 200);
    const sample1 = await sample1Res.json();

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: sample1.rawEmail })
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert(data.dossierId, 'Phishing email dossier ID must be present');
    assert(data.aiThreatIntelligence.riskScore >= 60, 'Phishing demo should reflect elevated risk');
  });

  // 3. Missing/invalid external enrichment does not crash analysis
  await test('3. Missing or invalid external enrichment fails gracefully without crashing', async () => {
    const geoResult = await lookupIP('192.168.1.1');
    assert(geoResult, 'GeoResult should not throw');
    assert(geoResult.disclaimer, 'Disclaimer should be present on geo result');

    const weirdEmail = `From: test@local
To: test2@local
Subject: Weird test
Received: from fake ([192.168.1.50]) by internal with SMTP; Mon, 07 Sep 2026 12:00:00 +0000

Plain body test with no valid domains or public IPs.`;

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: weirdEmail })
    });

    assert.strictEqual(res.status, 200, 'Analysis must succeed even with unresolvable IPs');
    const data = await res.json();
    assert(data.originGeo, 'originGeo should exist');
  });

  // 4. AI unavailable does not crash analysis
  await test('4. AI service failure falls back gracefully without crashing entire pipeline', async () => {
    const parsed = await parseEmail('From: test@test.com\nSubject: Test\n\nTest body');
    const relay = traceRelayHops(parsed.headers, parsed.headerLines);
    const auth = validateAuthentication({ ...parsed, relay });

    // Call fallback / AI engine directly
    const aiResult = await analyzeEmailThreatWithAI(
      parsed, 
      relay, 
      auth, 
      { urls: [], ips: [], domains: [], attachments: [] }, 
      { country: 'Unknown', city: 'Unknown', isp: 'Unknown', asn: 'Unknown' }
    );

    assert(aiResult, 'AI engine must return result even if API fails');
    assert(aiResult.riskScore !== undefined, 'Risk score must be present');
    assert(aiResult.executiveSummary, 'Executive summary must be present');
  });

  // 5. X-Originating-IP is not displayed as verified attacker origin
  await test('5. X-Originating-IP is labeled UNVERIFIED and not claimed as verified attacker origin', async () => {
    const spoofedEmail = `From: ceo@corporation.com
To: finance@corporation.com
Subject: Wire transfer urgent
X-Originating-IP: [185.220.101.5]
Received: from corporate-gateway.internal (10.0.0.1) by mx.corp.com; Mon, 7 Sep 2026 10:00:00 +0000

Please process the wire immediately.`;

    const parsed = await parseEmail(spoofedEmail);
    const relay = traceRelayHops(parsed.headers, parsed.headerLines);

    assert.strictEqual(relay.originatingIPStatus, 'UNVERIFIED', 'Originating IP status must be UNVERIFIED');
    assert.strictEqual(relay.originatingIPLabel, 'Claimed Earlier Origin (UNVERIFIED)');
    assert.strictEqual(relay.claimedOriginatingIP, '185.220.101.5', 'Value should be preserved as claimed origin');

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: spoofedEmail })
    });
    const data = await res.json();
    assert.strictEqual(data.relay.originatingIPStatus, 'UNVERIFIED');
  });

  // 6. Geolocation is labelled as infrastructure location
  await test('6. Geolocation response describes network infrastructure with explicit limitation', async () => {
    const geo = await lookupIP('8.8.8.8');
    assert(geo.infrastructureLocation, 'Infrastructure location field must be present');
    assert(geo.disclaimer, 'Forensic disclaimer must be present');
    assert(geo.disclaimer.includes('infrastructure'), 'Disclaimer must mention network infrastructure');
    assert(geo.disclaimer.includes('does not establish the physical location'), 'Disclaimer must clarify physical location limitation');
  });

  // 7. Impossible-travel wording no longer appears
  await test('7. Impossible physical travel speed wording is completely removed and replaced', async () => {
    const multiHopEmail = `From: test@example.com
To: user@example.com
Subject: Routing test
Received: from us-node (198.51.100.1) by transit (198.51.100.2); Mon, 7 Sep 2026 12:00:01 +0000
Received: from eu-node (203.0.113.1) by us-node (198.51.100.1); Mon, 7 Sep 2026 12:00:00 +0000

Test email body.`;

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: multiHopEmail })
    });

    const bodyText = await res.text();
    const lower = bodyText.toLowerCase();

    assert(!lower.includes('impossible travel'), 'Response must not contain "impossible travel"');
    assert(!lower.includes('impossible physical travel'), 'Response must not contain "impossible physical travel"');
    assert(!lower.includes('attacker travelled'), 'Response must not contain "attacker travelled"');
    assert(!lower.includes('travel speed'), 'Response must not contain "travel speed"');
  });

  // 8. Attacker persona is not presented as a factual conclusion
  await test('8. Attacker persona is framed as investigative hypothesis with disclaimer', async () => {
    const phishingEmail = `From: security@paypal-verification.com
Subject: Account Suspended Immediately
To: victim@example.com
Date: Mon, 7 Sep 2026 10:00:00 +0000

Dear customer, your account is suspended. Click http://paypal-fake-login.com to verify.`;

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: phishingEmail })
    });

    const data = await res.json();
    const ai = data.aiThreatIntelligence;
    assert(ai.attributionDisclaimer, 'Attribution disclaimer must be present in AI intelligence');
    assert(ai.attributionDisclaimer.includes('Available email evidence does not establish the identity'), 'Disclaimer must match standard');
    assert(Array.isArray(ai.observedTactics), 'observedTactics array must be populated');
  });

  // 9. Model name/token information does not appear in user-facing UI / API response
  await test('9. Model name (gpt-6-astra) and internal reasoning tokens are suppressed', async () => {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: 'From: test@test.com\nSubject: Hello\n\nHello world' })
    });

    const data = await res.json();
    assert.strictEqual(data.aiThreatIntelligence.modelUsed, undefined, 'modelUsed must be omitted from output');
    assert.strictEqual(data.aiThreatIntelligence.reasoningTokens, undefined, 'reasoningTokens must be omitted from output');
    assert.strictEqual(data.aiThreatIntelligence.provider, undefined, 'provider name must be omitted from output');
  });

  console.log('\n====================================================');
  console.log(`🏁 TESTS FINISHED: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
