import axios from 'axios';
import FormData from 'form-data';

const BASE_URL = 'http://127.0.0.1:5001';

const results = [];

function recordTest(name, passed, details = '') {
  results.push({ name, passed, details });
  const icon = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`${icon}: ${name} ${details ? `(${details})` : ''}`);
}

async function runTestSuite() {
  console.log('====================================================');
  console.log('🧪 RUNNING COMPREHENSIVE DFIR & API TEST SUITE');
  console.log('   AICTE Problem Statement ID: 26106');
  console.log('====================================================\n');

  // Test 1: Health & Metadata Check
  try {
    const res = await axios.get(`${BASE_URL}/api/health`);
    const d = res.data;
    const isOk = d.status === 'online' && d.problemStatementId === 26106 && d.aiEngineStatus === 'active';
    recordTest('Health Check & PS 26106 Metadata', isOk, `Status: ${d.status}, PS ID: ${d.problemStatementId}`);
  } catch (err) {
    recordTest('Health Check & PS 26106 Metadata', false, err.message);
  }

  // Test 2: Sample Threat Emails Listing
  let sampleIds = [];
  try {
    const res = await axios.get(`${BASE_URL}/api/samples`);
    const samples = res.data.samples || [];
    sampleIds = samples.map(s => s.id);
    recordTest('Samples List Retrieval', samples.length >= 5, `Found ${samples.length} preloaded forensic scenarios`);
  } catch (err) {
    recordTest('Samples List Retrieval', false, err.message);
  }

  // Test 3: Individual Sample Data Retrieval
  for (const id of sampleIds) {
    try {
      const res = await axios.get(`${BASE_URL}/api/samples/${id}`);
      const hasEmail = typeof res.data.rawEmail === 'string' && res.data.rawEmail.length > 50;
      recordTest(`Sample Retrieval [${id}]`, hasEmail, `Length: ${res.data.rawEmail?.length} bytes`);
    } catch (err) {
      recordTest(`Sample Retrieval [${id}]`, false, err.message);
    }
  }

  // Test 4: Edge Case - Missing Email Content (400 Expected)
  try {
    await axios.post(`${BASE_URL}/api/analyze`, {});
    recordTest('Edge Case: Missing Payload', false, 'Expected 400 but succeeded');
  } catch (err) {
    recordTest('Edge Case: Missing Payload', err.response?.status === 400, `Returned HTTP ${err.response?.status}`);
  }

  // Test 5: Edge Case - Empty String / Whitespace (400 Expected)
  try {
    await axios.post(`${BASE_URL}/api/analyze`, { rawEmail: '     \n\t   ' });
    recordTest('Edge Case: Empty/Whitespace Email', false, 'Expected 400 but succeeded');
  } catch (err) {
    recordTest('Edge Case: Empty/Whitespace Email', err.response?.status === 400, `Returned HTTP ${err.response?.status}`);
  }

  // Test 6: Edge Case - Multipart .EML File Upload
  try {
    const form = new FormData();
    const fakeEml = `From: "Test Upload" <test@upload-scanner.org>
To: target@victim.com
Subject: Testing Multipart .EML Upload
Date: Wed, 06 Sep 2026 12:00:00 +0000
Message-ID: <test-file-upload@domain.com>
Received: from mail.upload.org ([198.51.100.45]) by mx.victim.com with ESMTP id abc123; Wed, 06 Sep 2026 12:01:00 +0000

Hello, this is a raw RFC 5322 .eml file upload test.`;
    form.append('emailFile', Buffer.from(fakeEml), {
      filename: 'sample_evidence.eml',
      contentType: 'message/rfc822'
    });

    const res = await axios.post(`${BASE_URL}/api/analyze`, form, {
      headers: form.getHeaders()
    });
    const d = res.data;
    const ok = d.dossierId && d.integrity?.sha256 && d.relay?.totalHops >= 1;
    recordTest('Edge Case: Multipart .EML File Upload via Multer', ok, `SHA-256: ${d.integrity?.sha256?.substring(0, 12)}...`);
  } catch (err) {
    recordTest('Edge Case: Multipart .EML File Upload via Multer', false, err.message);
  }

  // Test 7: Edge Case - Private IP RFC 1918 in Received Headers
  try {
    const privateIpEmail = `From: admin@internal.lan
To: user@internal.lan
Subject: Internal Gateway Relay Test
Received: from gateway.internal ([192.168.1.1]) by server.internal ([10.0.0.5]) with ESMTP; Wed, 06 Sep 2026 10:00:00 +0000

Internal ping test.`;
    const res = await axios.post(`${BASE_URL}/api/analyze`, { rawEmail: privateIpEmail });
    const isPrivateResolved = res.data.originGeo?.countryCode === 'LAN' || res.data.originGeo?.isp?.includes('Private');
    recordTest('Edge Case: Private RFC 1918 IP Resolution', isPrivateResolved, `Origin ISP: ${res.data.originGeo?.isp}`);
  } catch (err) {
    recordTest('Edge Case: Private RFC 1918 IP Resolution', false, err.message);
  }

  // Test 8: Deep Forensic Analysis on All Preloaded Threat Scenarios
  console.log('\n--- Testing Full End-to-End Scenarios ---');
  for (const id of sampleIds) {
    try {
      const sampleRes = await axios.get(`${BASE_URL}/api/samples/${id}`);
      const t0 = Date.now();
      const res = await axios.post(`${BASE_URL}/api/analyze`, { rawEmail: sampleRes.data.rawEmail });
      const elapsed = Date.now() - t0;
      const d = res.data;

      const checks = [
        d.dossierId.startsWith('DFIR-AICTE-26106'),
        d.integrity?.sha256?.length === 64,
        typeof d.aiThreatIntelligence?.riskScore === 'number',
        d.aiThreatIntelligence?.threatClassification,
        d.attributionAndGraph?.attributionClassification?.infrastructureType,
        d.attributionAndGraph?.graphCorrelation?.nodesCount > 0,
        Array.isArray(d.relay?.hops)
      ];
      const allPassed = checks.every(Boolean);

      recordTest(`Scenario Analysis: [${id}]`, allPassed, 
        `Risk: ${d.aiThreatIntelligence?.riskScore}/100, Class: ${d.aiThreatIntelligence?.threatClassification}, Model: ${d.aiThreatIntelligence?.modelUsed}, Time: ${elapsed}ms`
      );
    } catch (err) {
      recordTest(`Scenario Analysis: [${id}]`, false, err.message);
    }
  }

  // Summary
  const total = results.length;
  const passed = results.filter(r => r.passed).length;
  const failed = total - passed;
  console.log('\n====================================================');
  console.log(`📊 TEST SUITE SUMMARY: ${passed}/${total} PASSED (${Math.round((passed/total)*100)}%)`);
  if (failed === 0) {
    console.log('🎉 ALL BACKEND API & FORENSIC ENGINE TESTS PASSED!');
  } else {
    console.log(`⚠️ ${failed} TEST(S) FAILED`);
  }
  console.log('====================================================\n');
}

runTestSuite().catch(console.error);
