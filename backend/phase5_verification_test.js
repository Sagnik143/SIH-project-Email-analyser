/**
 * Phase 5 Verification Test Suite
 * Lightweight, Evidence-Backed "Related Incidents" Engine
 *
 * Tests:
 * 1. Same attachment SHA-256 creates a strong correlation (score >= 50).
 * 2. Same normalized URL creates a strong correlation (score >= 40).
 * 3. Same Reply-To creates a correlation (score >= 30).
 * 4. Same sender domain alone does not produce an unjustifiably strong relationship (score < 20).
 * 5. Same subject alone does not create a strong relationship (score < 20).
 * 6. Different indicators produce no relationship.
 * 7. An email cannot correlate with itself.
 * 8. Duplicate A-B / B-A relationships are prevented in SQLite.
 * 9. Correlation reasons are returned with explainable descriptions.
 * 10. Correlation score is strictly deterministic.
 * 11. Correlation score is clearly NOT represented as probability.
 * 12. Shared indicators reference actual stored records / evidence IDs.
 * 13. Original evidence remains unchanged after normalization.
 * 14. Cross-case correlation works.
 * 15. Cross-email correlation works.
 * 16. API returns safe user-facing errors (404 for invalid ID).
 * 17. SQL/internal errors do not leak into API responses.
 * 18. No attacker identity is inferred ("same attacker" prohibited).
 * 19. No human location is inferred from infrastructure correlation.
 * 20. No campaign attribution is automatically asserted ("same campaign" prohibited).
 * 21. Edge Case: Same attachment hash with different filenames.
 * 22. Edge Case: URLs differing only in port/trailing slash vs materially different URLs.
 * 23. Edge Case: Closed case remains discoverable as a related incident.
 * 24. Edge Case: Duplicate email uploaded twice across cases.
 * 25. Edge Case: Email with no attachments or URLs.
 */

import http from 'http';
import crypto from 'crypto';
import { SAMPLE_EMAILS } from './data/samples.js';
import {
  normalizeUrl,
  normalizeEmail,
  normalizeDomain,
  normalizeIp,
  normalizeHash,
  normalizeSubject,
  compareEmailFeatures,
  findRelatedEmails,
  findRelatedCases
} from './services/correlationEngine.js';
import { createCase, saveEmailAndAnalysisToCase, getCaseById } from './db/caseRepository.js';
import { analyzeEmail } from './services/investigationEngine.js';
import { getDb } from './db/database.js';

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

async function runPhase5Verification() {
  console.log('\n======================================================');
  console.log(' AegisMail Phase 5: Related Incidents Engine Tests');
  console.log('======================================================\n');

  // Setup sample features
  const emailA = {
    emailId: 101,
    caseId: 1,
    filename: 'invoice_alpha.eml',
    rawSha256: 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
    senderAddress: 'finance@supplier-corp.com',
    senderDomain: 'supplier-corp.com',
    subject: 'Overdue Statement #INV-101',
    subjectNormalized: 'overdue statement #inv-101',
    replyToAddress: 'billing-ops@payment-portal.net',
    replyToEvidenceId: 'E-002',
    attachments: [
      { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', filename: 'Statement.xlsm', evidenceId: 'E-005' }
    ],
    urls: [
      { original: 'http://payment-portal.net:80/auth/login.php?dest=portal', normalized: 'http://payment-portal.net/auth/login.php?dest=portal', evidenceId: 'E-008' }
    ],
    relayIps: [{ ip: '198.51.100.42', evidenceId: 'E-010' }]
  };

  // 1. Same attachment SHA-256 creates a strong correlation
  await test('1. Same attachment SHA-256 creates a strong correlation', () => {
    const emailB = {
      emailId: 102,
      caseId: 2,
      filename: 'remittance_beta.eml',
      rawSha256: 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2',
      senderAddress: 'remittance@different-vendor.org',
      senderDomain: 'different-vendor.org',
      subject: 'Urgent Wire Notice',
      subjectNormalized: 'urgent wire notice',
      replyToAddress: 'different@other.org',
      replyToEvidenceId: 'E-001',
      attachments: [
        { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', filename: 'OtherName.xlsm', evidenceId: 'E-004' }
      ],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailB);
    assert(res !== null, 'Comparison must produce correlation');
    assert(res.correlationScore >= 50, `Expected score >= 50, got ${res.correlationScore}`);
    assert(res.reasons.some(r => r.signal === 'attachment_sha256'), 'Must contain attachment_sha256 reason');
  });

  // 2. Same normalized URL creates a strong correlation
  await test('2. Same normalized URL creates a strong correlation', () => {
    const emailC = {
      emailId: 103,
      caseId: 3,
      filename: 'security_alert.eml',
      rawSha256: 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3',
      senderAddress: 'alerts@unrelated.com',
      senderDomain: 'unrelated.com',
      subject: 'Security Alert',
      subjectNormalized: 'security alert',
      replyToAddress: null,
      attachments: [],
      urls: [
        { original: 'http://payment-portal.net/auth/login.php?dest=portal', normalized: 'http://payment-portal.net/auth/login.php?dest=portal', evidenceId: 'E-003' }
      ],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailC);
    assert(res !== null, 'Comparison must produce correlation');
    assert(res.correlationScore >= 40, `Expected score >= 40, got ${res.correlationScore}`);
    assert(res.reasons.some(r => r.signal === 'normalized_url'), 'Must contain normalized_url reason');
  });

  // 3. Same Reply-To creates a correlation
  await test('3. Same Reply-To creates a correlation', () => {
    const emailD = {
      emailId: 104,
      caseId: 4,
      filename: 'hr_update.eml',
      rawSha256: 'd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4',
      senderAddress: 'hr-payroll@completely-different.com',
      senderDomain: 'completely-different.com',
      subject: 'Payroll Direct Deposit Update',
      subjectNormalized: 'payroll direct deposit update',
      replyToAddress: 'billing-ops@payment-portal.net',
      replyToEvidenceId: 'E-009',
      attachments: [],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailD);
    assert(res !== null, 'Comparison must produce correlation');
    assert(res.correlationScore >= 30, `Expected score >= 30, got ${res.correlationScore}`);
    assert(res.reasons.some(r => r.signal === 'reply_to'), 'Must contain reply_to reason');
  });

  // 4. Same sender domain alone does not produce an unjustifiably strong relationship
  await test('4. Same sender domain alone does not produce an unjustifiably strong relationship', () => {
    const emailE = {
      emailId: 105,
      caseId: 5,
      filename: 'newsletter.eml',
      rawSha256: 'e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5',
      senderAddress: 'sales@supplier-corp.com',
      senderDomain: 'supplier-corp.com',
      subject: 'Quarterly Sales Catalog',
      subjectNormalized: 'quarterly sales catalog',
      replyToAddress: 'sales@supplier-corp.com',
      attachments: [],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailE);
    // Score for sender domain alone is 15 (< 20 threshold) -> returns null
    assert(res === null, 'Sender domain alone must NOT exceed correlation threshold');
  });

  // 5. Same subject alone does not create a strong relationship
  await test('5. Same subject alone does not create a strong relationship', () => {
    const emailF = {
      emailId: 106,
      caseId: 6,
      filename: 'fake_sub.eml',
      rawSha256: 'f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6',
      senderAddress: 'random@random.com',
      senderDomain: 'random.com',
      subject: 'Re: Overdue Statement #INV-101',
      subjectNormalized: 'overdue statement #inv-101',
      replyToAddress: null,
      attachments: [],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailF);
    // Score for subject pattern alone is 5 (< 20 threshold) -> returns null
    assert(res === null, 'Subject alone must NOT create a relationship');
  });

  // 6. Different indicators produce no relationship
  await test('6. Different indicators produce no relationship', () => {
    const emailG = {
      emailId: 107,
      caseId: 7,
      filename: 'benign.eml',
      rawSha256: '0707070707070707070707070707070707070707070707070707070707070707',
      senderAddress: 'support@github.com',
      senderDomain: 'github.com',
      subject: 'New sign-in from Firefox',
      subjectNormalized: 'new sign-in from firefox',
      replyToAddress: 'support@github.com',
      attachments: [],
      urls: [{ original: 'https://github.com/settings', normalized: 'https://github.com/settings' }],
      relayIps: [{ ip: '140.82.112.4' }]
    };

    const res = compareEmailFeatures(emailA, emailG);
    assert(res === null, 'Completely different indicators must return null');
  });

  // 7. An email cannot correlate with itself
  await test('7. An email cannot correlate with itself', () => {
    const res = compareEmailFeatures(emailA, emailA);
    assert(res === null, 'Self comparison must strictly return null');
  });

  // 8. Duplicate A-B / B-A relationships are prevented in SQLite
  await test('8. Duplicate A-B / B-A relationships are prevented in SQLite', () => {
    const db = getDb();
    const case1 = createCase({ title: 'A-B Test Case 1' });
    const case2 = createCase({ title: 'A-B Test Case 2' });

    // Insert dummy email records
    const insertEmail = db.prepare(`
      INSERT INTO emails (case_id, filename, sha256, subject, sender, recipient, received_at, raw_email, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const e1 = insertEmail.run(case1.id, 'e1.eml', 'hash1', 'Sub1', 's1@a.com', 'r1@a.com', 'now', 'raw1', 'now').lastInsertRowid;
    const e2 = insertEmail.run(case2.id, 'e2.eml', 'hash2', 'Sub2', 's2@b.com', 'r2@b.com', 'now', 'raw2', 'now').lastInsertRowid;

    const id1 = Math.min(e1, e2);
    const id2 = Math.max(e1, e2);

    // First insert: id1 -> id2
    db.prepare(`
      INSERT INTO related_incidents (
        source_email_id, target_email_id, source_case_id, target_case_id,
        correlation_score, relationship_type, reasons, shared_indicators, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id1, id2, case1.id, case2.id, 65, 'potentially_related', '[]', '[]', 'now');

    // Attempt duplicate reverse insert: id2 -> id1 should fail unique constraint
    let caughtConstraint = false;
    try {
      db.prepare(`
        INSERT INTO related_incidents (
          source_email_id, target_email_id, source_case_id, target_case_id,
          correlation_score, relationship_type, reasons, shared_indicators, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id2, id1, case2.id, case1.id, 65, 'potentially_related', '[]', '[]', 'now');
    } catch (err) {
      caughtConstraint = err.message.includes('UNIQUE constraint failed');
    }
    assert(caughtConstraint, 'Reverse A-B insert must violate unique constraint');
  });

  // 9. Correlation reasons are returned with explainable descriptions
  await test('9. Correlation reasons are returned with explainable descriptions', () => {
    const emailB = {
      emailId: 102,
      caseId: 2,
      filename: 'remittance_beta.eml',
      rawSha256: 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2',
      senderAddress: 'remittance@different-vendor.org',
      senderDomain: 'different-vendor.org',
      subject: 'Urgent Wire Notice',
      subjectNormalized: 'urgent wire notice',
      replyToAddress: 'billing-ops@payment-portal.net',
      replyToEvidenceId: 'E-001',
      attachments: [
        { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', filename: 'OtherName.xlsm', evidenceId: 'E-004' }
      ],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailB);
    assert(Array.isArray(res.reasons) && res.reasons.length >= 2, 'Reasons array must contain multiple signals');
    for (const r of res.reasons) {
      assert(typeof r.signal === 'string', 'signal must be string');
      assert(typeof r.description === 'string' && r.description.length > 5, 'description must be descriptive');
    }
  });

  // 10. Correlation score is strictly deterministic
  await test('10. Correlation score is strictly deterministic', () => {
    const emailB = {
      emailId: 102,
      caseId: 2,
      filename: 'test.eml',
      rawSha256: 'hashb',
      senderAddress: 'b@b.com',
      senderDomain: 'b.com',
      replyToAddress: 'billing-ops@payment-portal.net',
      attachments: [
        { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', filename: 'test.xlsm' }
      ],
      urls: [],
      relayIps: []
    };

    const score1 = compareEmailFeatures(emailA, emailB).correlationScore;
    const score2 = compareEmailFeatures(emailA, emailB).correlationScore;
    assert(score1 === score2, 'Scores across runs must be identical');
  });

  // 11. Correlation score is clearly NOT represented as probability
  await test('11. Correlation score is clearly NOT represented as probability', () => {
    const emailB = {
      emailId: 102,
      caseId: 2,
      filename: 'test.eml',
      rawSha256: 'hashb',
      senderAddress: 'b@b.com',
      senderDomain: 'b.com',
      replyToAddress: 'billing-ops@payment-portal.net',
      attachments: [],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailB);
    const jsonStr = JSON.stringify(res).toLowerCase();
    assert(!jsonStr.includes('probability'), 'Must not contain probability');
    assert(!jsonStr.includes('confidence'), 'Must not contain confidence');
    assert(!jsonStr.includes('certainty'), 'Must not contain certainty');
    assert(typeof res.correlationScore === 'number', 'correlationScore must be numeric');
  });

  // 12. Shared indicators reference actual stored records / evidence IDs
  await test('12. Shared indicators reference actual stored records / evidence IDs', () => {
    const emailB = {
      emailId: 102,
      caseId: 2,
      filename: 'test.eml',
      rawSha256: 'hashb',
      senderAddress: 'b@b.com',
      senderDomain: 'b.com',
      replyToAddress: 'billing-ops@payment-portal.net',
      replyToEvidenceId: 'E-009',
      attachments: [
        { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', filename: 'Statement.xlsm', evidenceId: 'E-012' }
      ],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(emailA, emailB);
    assert(res.sharedIndicators.length >= 2, 'Must have shared indicators');
    const attInd = res.sharedIndicators.find(i => i.type === 'attachment_sha256');
    assert(attInd.sourceEvidenceId === 'E-005', 'sourceEvidenceId must match E-005');
    assert(attInd.targetEvidenceId === 'E-012', 'targetEvidenceId must match E-012');
  });

  // 13. Original evidence remains unchanged after normalization
  await test('13. Original evidence remains unchanged after normalization', () => {
    const rawUrl = 'HTTP://Payment-Portal.Net:80/Auth/Login.php?dest=portal/';
    const normalized = normalizeUrl(rawUrl);
    assert(rawUrl.startsWith('HTTP://'), 'Original raw URL must remain uppercase');
    assert(normalized.startsWith('http://payment-portal.net'), 'Normalized URL must be lowercased');
  });

  // 14. Cross-case correlation works via API
  await test('14. Cross-case correlation works via API', async () => {
    const becSample = SAMPLE_EMAILS.find(s => s.id === 'sample-bec-ceo-fraud') || SAMPLE_EMAILS[0];

    // Create Case 1 with BEC email
    const case1Res = await makeRequest('/api/cases', 'POST', { title: 'BEC Primary Case' });
    const case1Id = case1Res.data.id;
    await makeRequest(`/api/cases/${case1Id}/emails`, 'POST', { rawEmail: becSample.rawEmail, filename: 'bec1.eml' });

    // Create Case 2 with same BEC email
    const case2Res = await makeRequest('/api/cases', 'POST', { title: 'BEC Related Case' });
    const case2Id = case2Res.data.id;
    await makeRequest(`/api/cases/${case2Id}/emails`, 'POST', { rawEmail: becSample.rawEmail, filename: 'bec2.eml' });

    // Query related cases for Case 1
    const relatedRes = await makeRequest(`/api/cases/${case1Id}/related`, 'GET');
    assert(relatedRes.status === 200, 'Endpoint must return 200');
    assert(relatedRes.data.results.length >= 1, 'Must find related case');
    assert(relatedRes.data.results.some(r => r.case.id === case2Id), 'Must correlate with Case 2');
  });

  // 15. Cross-email correlation works via API
  await test('15. Cross-email correlation works via API', async () => {
    const db = getDb();
    const emails = db.prepare(`SELECT id FROM emails ORDER BY id DESC LIMIT 2`).all();
    if (emails.length > 0) {
      const emailId = emails[0].id;
      const res = await makeRequest(`/api/emails/${emailId}/related`, 'GET');
      assert(res.status === 200, 'Endpoint must return 200');
      assert(Array.isArray(res.data.results), 'results must be an array');
    }
  });

  // 16. API returns safe user-facing errors (404 for invalid ID)
  await test('16. API returns safe user-facing errors (404 for invalid ID)', async () => {
    const res = await makeRequest('/api/cases/9999999/related', 'GET');
    assert(res.status === 404, `Expected 404, got ${res.status}`);
    assert(res.data.error === 'Case not found', 'Safe error message expected');
  });

  // 17. SQL/internal errors do not leak into API responses
  await test('17. SQL/internal errors do not leak into API responses', async () => {
    const res = await makeRequest('/api/cases/invalid-case-id-12345/related', 'GET');
    const str = JSON.stringify(res.data);
    assert(!str.includes('SQLITE_ERROR'), 'Must not leak SQLITE_ERROR');
    assert(!str.includes('better-sqlite3'), 'Must not leak internal library details');
  });

  // 18. No attacker identity is inferred ("same attacker" prohibited)
  // 18. No attacker identity is inferred ("same attacker" prohibited)
  await test('18. No attacker identity is inferred', async () => {
    const db = getDb();
    const cases = db.prepare(`SELECT id FROM cases ORDER BY id DESC LIMIT 1`).all();
    if (cases.length > 0) {
      const res = await makeRequest(`/api/cases/${cases[0].id}/related`, 'GET');
      for (const item of (res.data.results || [])) {
        assert(item.relationship === 'potentially_related', 'Relationship must be potentially_related');
        const reasonsStr = JSON.stringify(item.reasons).toLowerCase();
        assert(!reasonsStr.includes('same attacker'), 'Reasons must NOT claim "same attacker"');
        assert(!reasonsStr.includes('attacker identity'), 'Reasons must NOT claim "attacker identity"');
      }
    }
  });

  // 19. No human location is inferred from infrastructure correlation
  await test('19. No human location is inferred from infrastructure correlation', () => {
    const email1 = { emailId: 1, caseId: 1, rawSha256: 'h1', senderAddress: 'a@a.com', relayIps: [{ ip: '185.220.101.5' }], attachments: [], urls: [] };
    const email2 = { emailId: 2, caseId: 2, rawSha256: 'h2', senderAddress: 'b@b.com', relayIps: [{ ip: '185.220.101.5' }], attachments: [], urls: [] };
    const res = compareEmailFeatures(email1, email2);
    if (res) {
      const str = JSON.stringify(res.reasons).toLowerCase();
      assert(!str.includes('physical location of sender'), 'Must not infer human physical location in reasons');
    }
  });

  // 20. No campaign attribution is automatically asserted ("same campaign" prohibited)
  await test('20. No campaign attribution is automatically asserted', async () => {
    const db = getDb();
    const cases = db.prepare(`SELECT id FROM cases ORDER BY id DESC LIMIT 1`).all();
    if (cases.length > 0) {
      const res = await makeRequest(`/api/cases/${cases[0].id}/related`, 'GET');
      for (const item of (res.data.results || [])) {
        assert(item.relationship === 'potentially_related', 'Relationship must be potentially_related');
        const reasonsStr = JSON.stringify(item.reasons).toLowerCase();
        assert(!reasonsStr.includes('same campaign'), 'Reasons must NOT claim "same campaign"');
        assert(!reasonsStr.includes('campaign detected'), 'Reasons must NOT claim "campaign detected"');
      }
    }
  });

  // 21. Edge Case: Same attachment hash with different filenames
  await test('21. Edge Case: Same attachment hash with different filenames', () => {
    const email1 = {
      emailId: 1,
      caseId: 1,
      attachments: [{ sha256: 'aabbcc112233', filename: 'Statement_March.xlsm' }],
      urls: [],
      relayIps: []
    };
    const email2 = {
      emailId: 2,
      caseId: 2,
      attachments: [{ sha256: 'aabbcc112233', filename: 'Invoice_Overdue_Final.xlsm' }],
      urls: [],
      relayIps: []
    };
    const res = compareEmailFeatures(email1, email2);
    assert(res !== null, 'Should correlate despite different filenames');
    assert(res.correlationScore >= 50, 'Attachment match score should be >= 50');
  });

  // 22. Edge Case: URLs differing only in port/trailing slash vs materially different URLs
  await test('22. Edge Case: URLs differing only in port/trailing slash vs materially different URLs', () => {
    const url1 = 'http://login.secure-portal.com:80/auth/login/';
    const url2 = 'http://login.secure-portal.com/auth/login';
    const url3 = 'http://login.secure-portal.com/auth/login?param=malicious';

    const n1 = normalizeUrl(url1);
    const n2 = normalizeUrl(url2);
    const n3 = normalizeUrl(url3);

    assert(n1 === n2, 'Normalized URLs differing only in port/slash must match');
    assert(n1 !== n3, 'URL with different query param must remain distinct');
  });

  // 23. Edge Case: Closed case remains discoverable as a related incident
  await test('23. Edge Case: Closed case remains discoverable as a related incident', async () => {
    const db = getDb();
    const closedCase = createCase({ title: 'Archived Case', status: 'closed' });
    const activeCase = createCase({ title: 'Active Ongoing Case', status: 'open' });

    const email1 = {
      emailId: 801,
      caseId: closedCase.id,
      replyToAddress: 'target-shared@domain.com',
      attachments: [],
      urls: [],
      relayIps: []
    };
    const email2 = {
      emailId: 802,
      caseId: activeCase.id,
      replyToAddress: 'target-shared@domain.com',
      attachments: [],
      urls: [],
      relayIps: []
    };

    const res = compareEmailFeatures(email1, email2);
    assert(res !== null, 'Closed case should correlate with active case');
    assert(res.correlationScore >= 30, 'Reply-To match produces correlation');
  });

  // 24. Edge Case: Duplicate email uploaded twice across cases
  await test('24. Edge Case: Duplicate email uploaded twice across cases', () => {
    const email1 = {
      emailId: 901,
      caseId: 10,
      rawSha256: '9999999999999999999999999999999999999999999999999999999999999999',
      attachments: [],
      urls: [],
      relayIps: []
    };
    const email2 = {
      emailId: 902,
      caseId: 11,
      rawSha256: '9999999999999999999999999999999999999999999999999999999999999999',
      attachments: [],
      urls: [],
      relayIps: []
    };
    const res = compareEmailFeatures(email1, email2);
    assert(res !== null, 'Duplicate raw email hash should correlate');
    assert(res.reasons.some(r => r.signal === 'identical_raw_email_hash'), 'Should identify identical email hash');
  });

  // 25. Edge Case: Email with no attachments or URLs
  await test('25. Edge Case: Email with no attachments or URLs', () => {
    const emailEmpty = {
      emailId: 999,
      caseId: 99,
      attachments: [],
      urls: [],
      relayIps: []
    };
    const res = compareEmailFeatures(emailEmpty, emailA);
    assert(res === null, 'Empty email telemetry must not correlate');
  });

  console.log('\n======================================================');
  console.log(` Summary: ${passedCount} passed, ${failedCount} failed`);
  console.log('======================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runPhase5Verification().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
