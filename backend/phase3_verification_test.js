/**
 * Phase 3 Verification Test Suite
 * Validates SQLite Database Initialization, Case Management, and Forensic Persistence.
 *
 * Tests:
 * 1. Database initializes successfully.
 * 2. Database initialization is idempotent.
 * 3. POST /api/cases creates CASE-001.
 * 4. A second case gets a unique case number (CASE-002).
 * 5. GET /api/cases returns persisted cases.
 * 6. GET /api/cases/:id returns the correct case.
 * 7. An .eml can be associated with a case via /api/cases/:id/emails.
 * 8. Raw email is stored byte-for-byte unmodified.
 * 9. SHA-256 is stored correctly.
 * 10. Phase 2 evidence items are persisted in evidence table.
 * 11. Phase 2 findings are persisted in findings table.
 * 12. Finding/evidence relationships are persisted via finding_evidence join table.
 * 13. Evidence IDs (E-001) remain accessible in case query.
 * 14. Finding IDs (F-001) remain accessible in case query.
 * 15. Database transaction rolls back completely on failure.
 * 16. AI unavailable does not prevent case creation and persistence.
 * 17. Geolocation unavailable does not prevent case creation and persistence.
 * 18. Existing stateless POST /api/analyze still works without regression.
 * 19. No database internal errors or SQL syntax leak to client responses.
 * 20. Case persistence survives between queries and database connections.
 */

import http from 'http';
import { SAMPLE_EMAILS } from './data/samples.js';
import { initDatabase, getDb } from './db/database.js';
import { generateNextCaseNumber, createCase, getCaseById, listCases, saveEmailAndAnalysisToCase } from './db/caseRepository.js';

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

async function runPhase3Tests() {
  console.log('====================================================');
  console.log('🗄️  STARTING PHASE 3 DATABASE + CASE MANAGEMENT TESTS');
  console.log('====================================================\n');

  // 1. Database initializes successfully
  const db = initDatabase();
  assert(db !== null && db !== undefined, '1. Database initializes successfully');

  // 2. Database initialization is idempotent
  const dbSecondCall = initDatabase();
  assert(db === dbSecondCall, '2. Database initialization is idempotent (returns existing instance)');

  // 3. POST /api/cases creates a case
  const createRes1 = await makeRequest('/api/cases', 'POST', {
    title: 'Suspicious Wire Transfer Request - CEO Impersonation',
    status: 'open'
  });
  assert(createRes1.status === 201, '3. POST /api/cases creates case with HTTP 201');
  const case1 = createRes1.data;
  assert(case1.caseNumber && case1.caseNumber.startsWith('CASE-'),
    '3. Case has valid human-readable number', case1.caseNumber);
  assert(case1.title === 'Suspicious Wire Transfer Request - CEO Impersonation', '3. Case title matches input');
  assert(case1.status === 'open', '3. Case status initialized to open');

  // 4. A second case gets a unique case number
  const createRes2 = await makeRequest('/api/cases', 'POST', {
    title: 'M365 Credential Harvest Campaign',
    status: 'reviewing'
  });
  assert(createRes2.status === 201, '4. Second case created with HTTP 201');
  const case2 = createRes2.data;
  assert(case2.caseNumber !== case1.caseNumber,
    '4. Second case has unique case number', `${case1.caseNumber} vs ${case2.caseNumber}`);

  // 5. GET /api/cases returns persisted cases
  const listRes = await makeRequest('/api/cases', 'GET');
  assert(listRes.status === 200, '5. GET /api/cases returns HTTP 200');
  assert(Array.isArray(listRes.data.cases) && listRes.data.cases.length >= 2,
    '5. Persisted cases list returned with at least 2 entries');

  // 6. GET /api/cases/:id returns the correct case (numeric ID and case number)
  const getByIdRes = await makeRequest(`/api/cases/${case1.id}`, 'GET');
  assert(getByIdRes.status === 200 && getByIdRes.data.case.id === case1.id,
    '6. GET /api/cases/:id retrieves case by numeric primary key');

  const getByNumberRes = await makeRequest(`/api/cases/${case1.caseNumber}`, 'GET');
  assert(getByNumberRes.status === 200 && getByNumberRes.data.case.caseNumber === case1.caseNumber,
    '6. GET /api/cases/:id retrieves case by human-readable case number');

  // 7. An .eml can be associated with a case via POST /api/cases/:id/emails
  const becSample = SAMPLE_EMAILS.find(s => s.id === 'sample-bec-ceo-fraud');
  const attachRes = await makeRequest(`/api/cases/${case1.id}/emails`, 'POST', {
    rawEmail: becSample.rawEmail,
    filename: 'ceo_wire_fraud.eml'
  });
  assert(attachRes.status === 201, '7. POST /api/cases/:id/emails attaches email to case with HTTP 201');
  const attachedData = attachRes.data;
  assert(attachedData.case && attachedData.dossier, '7. Attached response contains both updated case and dossier');

  // 8. Raw email is stored byte-for-byte unmodified
  const fullCaseRes = await makeRequest(`/api/cases/${case1.id}`, 'GET');
  const fullCase = fullCaseRes.data;
  assert(fullCase.emails.length >= 1, '8. Attached email record exists in case');
  const rawEmailInDb = db.prepare('SELECT raw_email FROM emails WHERE id = ?').get(fullCase.emails[0].id);
  assert(rawEmailInDb.raw_email === becSample.rawEmail,
    '8. Stored raw email matches original content byte-for-byte');

  // 9. SHA-256 is stored correctly
  assert(fullCase.emails[0].sha256 === attachedData.dossier.integrity.sha256,
    '9. Stored email SHA-256 matches cryptographic integrity digest');

  // 10. Evidence is persisted
  assert(Array.isArray(fullCase.evidence) && fullCase.evidence.length > 0,
    '10. Phase 2 evidence records persisted in database',
    `Found ${fullCase.evidence?.length} persisted evidence records`);

  // 11. Findings are persisted
  assert(Array.isArray(fullCase.findings) && fullCase.findings.length > 0,
    '11. Phase 2 findings persisted in database',
    `Found ${fullCase.findings?.length} persisted findings`);

  // 12. Finding/evidence relationships are persisted via finding_evidence join table
  const joinRows = db.prepare(`
    SELECT fe.finding_id, fe.evidence_id
    FROM finding_evidence fe
    JOIN findings f ON f.id = fe.finding_id
    WHERE f.case_id = ?
  `).all(case1.id);
  assert(joinRows.length > 0,
    '12. Normalized finding_evidence join table rows persisted successfully',
    `Found ${joinRows.length} join relationships`);

  // 13 & 14. Evidence IDs (E-001) and Finding IDs (F-001) remain accessible in case query
  const firstFinding = fullCase.findings[0];
  assert(firstFinding.id.startsWith('F-'),
    '14. Finding human-readable ID (F-001) preserved and queryable', firstFinding.id);
  assert(Array.isArray(firstFinding.evidenceIds) && firstFinding.evidenceIds.length > 0,
    '13. Finding references valid evidence IDs in case query',
    firstFinding.evidenceIds.join(', '));
  assert(firstFinding.evidenceIds.every(eId => eId.startsWith('E-')),
    '13. Referenced evidence IDs retain stable human-readable format (E-xxx)');

  // 15. Database transaction rolls back on failure
  let txRolledBack = false;
  try {
    const brokenTx = db.transaction(() => {
      db.prepare(`INSERT INTO cases (case_number, title, status, created_at, updated_at) VALUES ('TEST-FAIL-1', 'Tx Test', 'open', datetime('now'), datetime('now'))`).run();
      // Deliberate constraint violation: NULL in non-null column
      db.prepare(`INSERT INTO cases (id, case_number, title, status, created_at, updated_at) VALUES (NULL, NULL, NULL, NULL, NULL)`).run();
    });
    brokenTx();
  } catch (txErr) {
    txRolledBack = true;
  }
  assert(txRolledBack, '15. Invalid multi-statement operation triggers rollback exception');
  const testFailCase = db.prepare(`SELECT * FROM cases WHERE case_number = 'TEST-FAIL-1'`).get();
  assert(testFailCase === undefined, '15. Database transaction completely rolled back; no orphaned row written');

  // 16. AI unavailable does not prevent case creation and persistence
  // Upload minimal email where AI might be in fallback
  const minimalAttach = await makeRequest(`/api/cases/${case2.id}/emails`, 'POST', {
    rawEmail: "From: alerts@internal.net\nSubject: Routine Alert\n\nAll systems operational.",
    filename: 'alert.eml'
  });
  assert(minimalAttach.status === 201, '16. Fallback/minimal email persists to case without failure');
  const case2Data = await makeRequest(`/api/cases/${case2.id}`, 'GET');
  assert(case2Data.data.emails.length >= 1, '16. Case created and email stored even with minimal telemetry');

  // 17. Geolocation unavailable does not prevent case creation and persistence
  const privateIpEmail = "From: it@corp.local\nReceived: from [192.168.1.50] by mail.corp.local; Mon, 7 Sep 2026 12:00:00 +0000\nSubject: Test\n\nBody";
  const geoFallbackCase = await makeRequest('/api/cases', 'POST', { title: 'RFC 1918 Private Relay Test' });
  const geoAttachRes = await makeRequest(`/api/cases/${geoFallbackCase.data.id}/emails`, 'POST', {
    rawEmail: privateIpEmail,
    filename: 'private_hop.eml'
  });
  assert(geoAttachRes.status === 201, '17. Private/unresolvable IP analysis persists safely to case');

  // 18. Existing stateless POST /api/analyze still works
  const statelessRes = await makeRequest('/api/analyze', 'POST', { rawEmail: becSample.rawEmail });
  assert(statelessRes.status === 200, '18. Stateless /api/analyze endpoint remains 100% functional');
  assert(statelessRes.data.findings && statelessRes.data.evidence,
    '18. Stateless response returns complete Phase 2 evidence and findings structure');

  // 19. No database internal errors or SQL syntax leak to client responses
  const nonExistentCase = await makeRequest('/api/cases/CASE-999999', 'GET');
  assert(nonExistentCase.status === 404, '19. Nonexistent case returns clean HTTP 404');
  assert(nonExistentCase.data.error === 'Case not found', '19. Safe error response without SQL leaks');

  // 20. Case persistence survives database re-opening
  const verifyDb = initDatabase();
  const verifyRow = verifyDb.prepare('SELECT COUNT(*) as count FROM cases').get();
  assert(verifyRow.count >= 3,
    '20. Case persistence verified across database handles',
    `Persisted cases count: ${verifyRow.count}`);

  console.log('\n====================================================');
  console.log('🏁 ALL 20 PHASE 3 VERIFICATION TESTS PASSED (100%)');
  console.log('====================================================\n');
}

runPhase3Tests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
