import axios from 'axios';
import FormData from 'form-data';

const BACKEND_URL = 'http://127.0.0.1:5001';
const FRONTEND_URL = 'http://127.0.0.1:5173';

const results = [];

function record(category, testName, passed, details = '') {
  results.push({ category, testName, passed, details });
  const badge = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`[${category}] ${badge} - ${testName} ${details ? `(${details})` : ''}`);
}

async function runAllTests() {
  console.log('===============================================================');
  console.log('🛡️ AEGISMAIL DFIR COMPREHENSIVE PLATFORM & EDGE CASE AUDIT');
  console.log('   AICTE Problem Statement: 26106 | Model: gpt-6-astra');
  console.log('===============================================================\n');

  // CATEGORY 1: System Health & Frontend Connectivity
  try {
    const health = await axios.get(`${BACKEND_URL}/api/health`);
    const h = health.data;
    const ok = h.status === 'online' && h.problemStatementId === 26106 && h.primaryModel === 'gpt-6-astra' && h.aiKeyConfigured === true;
    record('SYSTEM', 'Backend API Health & gpt-6-astra Configuration', ok, `Model: ${h.primaryModel}, KeyConfigured: ${h.aiKeyConfigured}`);
  } catch (err) {
    record('SYSTEM', 'Backend API Health & gpt-6-astra Configuration', false, err.message);
  }

  try {
    const fe = await axios.get(FRONTEND_URL);
    const ok = fe.status === 200 && fe.data.includes('<div id="root">');
    record('SYSTEM', 'Frontend UI Server Connectivity', ok, `HTTP ${fe.status}, HTML Root node verified`);
  } catch (err) {
    record('SYSTEM', 'Frontend UI Server Connectivity', false, err.message);
  }

  // CATEGORY 2: Sample Repository
  let sampleIds = [];
  try {
    const samplesRes = await axios.get(`${BACKEND_URL}/api/samples`);
    const list = samplesRes.data.samples || [];
    sampleIds = list.map(s => s.id);
    record('SAMPLES', 'Sample Scenario Listing', list.length >= 5, `${list.length} preloaded threat scenarios`);
  } catch (err) {
    record('SAMPLES', 'Sample Scenario Listing', false, err.message);
  }

  // CATEGORY 3: API Edge Cases
  // Edge Case 1: Null / Empty Object Payload
  try {
    await axios.post(`${BACKEND_URL}/api/analyze`, {});
    record('EDGE-CASE', 'Empty JSON Object Rejection', false, 'Expected 400 Bad Request');
  } catch (err) {
    record('EDGE-CASE', 'Empty JSON Object Rejection', err.response?.status === 400, `Returned HTTP ${err.response?.status}`);
  }

  // Edge Case 2: Whitespace Only Payload
  try {
    await axios.post(`${BACKEND_URL}/api/analyze`, { rawEmail: '   \n\t  \r\n   ' });
    record('EDGE-CASE', 'Whitespace String Rejection', false, 'Expected 400 Bad Request');
  } catch (err) {
    record('EDGE-CASE', 'Whitespace String Rejection', err.response?.status === 400, `Returned HTTP ${err.response?.status}`);
  }

  // Edge Case 3: Email with No Received Headers (Direct Input)
  try {
    const noHeadersEmail = `From: "Test" <test@example.com>
To: victim@example.com
Subject: Headerless Email

This email has no received headers at all.`;
    const res = await axios.post(`${BACKEND_URL}/api/analyze`, { rawEmail: noHeadersEmail });
    const ok = Boolean(res.data.dossierId && res.data.relay?.totalHops === 0);
    record('EDGE-CASE', 'Zero-Hop / Headerless Email Parsing', ok, `Total hops: ${res.data.relay?.totalHops}, Handled gracefully`);
  } catch (err) {
    record('EDGE-CASE', 'Zero-Hop / Headerless Email Parsing', false, err.message);
  }

  // Edge Case 4: Private RFC 1918 Internal IP Address Resolution
  try {
    const privateIpEmail = `From: internal@corp.local
To: sec@corp.local
Subject: RFC 1918 Diagnostic
Received: from router.internal ([10.0.1.254]) by mail.corp.local with ESMTP; Wed, 06 Sep 2026 10:00:00 +0000

Testing internal address.`;
    const res = await axios.post(`${BACKEND_URL}/api/analyze`, { rawEmail: privateIpEmail });
    const isRfc1918 = res.data.originGeo?.countryCode === 'LAN' && res.data.originGeo?.isp.includes('Private');
    record('EDGE-CASE', 'Private RFC 1918 IP Resolution', isRfc1918, `CountryCode: ${res.data.originGeo?.countryCode}, ISP: ${res.data.originGeo?.isp}`);
  } catch (err) {
    record('EDGE-CASE', 'Private RFC 1918 IP Resolution', false, err.message);
  }

  // Edge Case 5: Multipart .EML Form Upload via Multer
  try {
    const form = new FormData();
    const rawEml = `From: "Finance Auditor" <audit@external-verify.com>
To: cfo@targetcorp.com
Subject: Urgent Payment Audit
Date: Wed, 06 Sep 2026 14:00:00 +0000
Received: from mail.external-verify.com ([198.51.100.99]) by mx.targetcorp.com with ESMTP; Wed, 06 Sep 2026 14:01:00 +0000

Please review the attached ledger.`;
    form.append('emailFile', Buffer.from(rawEml), {
      filename: 'audit_invoice.eml',
      contentType: 'message/rfc822'
    });
    const res = await axios.post(`${BACKEND_URL}/api/analyze`, form, {
      headers: form.getHeaders()
    });
    const ok = res.data.dossierId && res.data.integrity?.sha256?.length === 64;
    record('EDGE-CASE', 'Multipart .EML File Upload via Multer', ok, `SHA-256: ${res.data.integrity?.sha256?.substring(0, 16)}...`);
  } catch (err) {
    record('EDGE-CASE', 'Multipart .EML File Upload via Multer', false, err.message);
  }

  // CATEGORY 4: Forensic Engine Specific Capabilities
  // Check IoC Defanging & Malicious URL detection
  try {
    const phishEmail = `From: "Microsoft 365 Security" <security-alerts@micros0ft.xyz>
To: user@target.com
Subject: Immediate Password Reset Required
Received: from relay.evil.net ([185.220.101.5]) by mx.target.com with ESMTP; Wed, 06 Sep 2026 12:00:00 +0000

Click here to login: https://micros0ft.xyz/login-session?auth=token123`;
    const res = await axios.post(`${BACKEND_URL}/api/analyze`, { rawEmail: phishEmail });
    const defanged = res.data.iocs?.urls?.some(u => u.defanged.includes('[.]'));
    const isLookalikeOrSpoofed = Boolean(res.data.authentication?.domainAnalysis?.isLookalike || res.data.authentication?.displayNameAnalysis?.isSpoofed);
    record('FORENSIC-ENGINE', 'URL Defanging & Brand Spoof / Lookalike Detection', defanged && isLookalikeOrSpoofed, `Defanged: ${defanged}, Lookalike/Spoof: ${isLookalikeOrSpoofed}`);
  } catch (err) {
    record('FORENSIC-ENGINE', 'URL Defanging & Brand Spoof / Lookalike Detection', false, err.message);
  }

  // CATEGORY 5: Live GPT-6 Astra AI Inference Verification
  try {
    const sample = await axios.get(`${BACKEND_URL}/api/samples/sample-bec-ceo-fraud`);
    const t0 = Date.now();
    const res = await axios.post(`${BACKEND_URL}/api/analyze`, { rawEmail: sample.data.rawEmail });
    const elapsed = Date.now() - t0;
    const ai = res.data.aiThreatIntelligence;
    const ok = ai.modelUsed === 'gpt-6-astra' && ai.engineSource === 'LLM_EXPERIENTIALLABS' && ai.riskScore > 80 && ai.threatClassification.includes('Impersonation');
    record('AI-ENGINE', 'Live GPT-6 Astra Forensic Inference (ExperientialLabs)', ok, `Model: ${ai.modelUsed}, Risk: ${ai.riskScore}/100, Class: ${ai.threatClassification}, Time: ${elapsed}ms`);
  } catch (err) {
    record('AI-ENGINE', 'Live GPT-6 Astra Forensic Inference (ExperientialLabs)', false, err.message);
  }

  // SUMMARY
  const total = results.length;
  const passed = results.filter(r => r.passed).length;
  const failed = total - passed;

  console.log('\n===============================================================');
  console.log(`📊 AUDIT SUMMARY: ${passed}/${total} TESTS PASSED (${Math.round((passed / total) * 100)}%)`);
  if (failed === 0) {
    console.log('🎉 ALL SYSTEM CHECKS, FORENSIC ENGINES & EDGE CASES VERIFIED!');
  } else {
    console.log(`⚠️ ${failed} TEST(S) ENCOUNTERED ISSUES`);
  }
  console.log('===============================================================\n');
}

runAllTests().catch(console.error);
