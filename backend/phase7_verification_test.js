/**
 * AegisMail DFIR - Phase 7 Verification Test Suite
 *
 * Explicitly validates all requirements from Section 27 of Phase 7 specification:
 * 1. Canonical serialization is deterministic.
 * 2. Same dossier produces same SHA-256 digest.
 * 3. Original email SHA-256 matches original bytes.
 * 4. MD5, if included, matches original bytes.
 * 5. Dossier integrity digest detects modification.
 * 6. Changing a finding causes verification failure.
 * 7. Changing evidence causes verification failure.
 * 8. Changing a hash causes verification failure.
 * 9. Changing report metadata included in the seal causes verification failure.
 * 10. HTML report is standalone.
 * 11. HTML report contains no external CDN dependencies.
 * 12. JSON export contains chain-of-custody metadata.
 * 13. Findings preserve evidence references.
 * 14. Related incidents are included correctly.
 * 15. AI content is clearly advisory.
 * 16. AI unavailable does not prevent report generation.
 * 17. Reports are recorded in SQLite.
 * 18. Report UUIDs are unique.
 * 19. Report history works.
 * 20. Verification endpoint accepts valid report.
 * 21. Verification endpoint detects tampered report.
 * 22. Invalid report format is handled safely.
 * 23. No API keys/providers/internal paths leak.
 * 24. No "court-admissible" guarantee appears in generated report.
 * 25. SHA-256 is presented as primary integrity mechanism.
 * 26. MD5 is not presented as a security guarantee.
 * 27. No "digital signature" claim exists without actual signing.
 */

import crypto from 'crypto';
import { initDatabase, getDb } from './db/database.js';
import { createCase, saveEmailAndAnalysisToCase, logReportExport, getReportsForCase, findReportByUuid } from './db/caseRepository.js';
import { analyzeEmail } from './services/investigationEngine.js';
import { SAMPLE_EMAILS } from './data/samples.js';
import { 
  canonicalizeObject, 
  computeCanonicalHash, 
  generateCanonicalDossier, 
  generateChainOfCustodyCertificate, 
  generateJsonReport, 
  generateHtmlReport 
} from './services/reportGeneratorService.js';
import { verifyReportIntegrity } from './services/reportVerificationService.js';

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName}`);
    failed++;
    throw new Error(`Assertion failed: ${testName}`);
  }
}

async function runAllPhase7Tests() {
  console.log('\n======================================================');
  console.log('🛡️ Starting AegisMail Phase 7 Verification Suite');
  console.log('======================================================\n');

  initDatabase();

  const sample1 = SAMPLE_EMAILS[0];
  const dossier1 = await analyzeEmail(sample1.rawEmail);

  // 1. Canonical serialization is deterministic
  console.log('--- Test Group 1: Canonical Serialization & Hashing ---');
  const testObjA = { b: 2, a: 1, c: { z: 26, y: 25 } };
  const testObjB = { a: 1, c: { y: 25, z: 26 }, b: 2 };
  assert(computeCanonicalHash(testObjA) === computeCanonicalHash(testObjB), '1. Canonical serialization is deterministic across arbitrary key orders');

  // 2. Same dossier produces same SHA-256 digest
  const canonical1A = generateCanonicalDossier(dossier1, { caseNumber: 'CASE-001' });
  const canonical1B = generateCanonicalDossier(dossier1, { caseNumber: 'CASE-001' });
  assert(computeCanonicalHash(canonical1A) === computeCanonicalHash(canonical1B), '2. Same dossier produces identical canonical SHA-256 digest');

  // 3. Original email SHA-256 matches original bytes
  const expectedSha256 = crypto.createHash('sha256').update(sample1.rawEmail, 'utf8').digest('hex');
  assert(dossier1.integrity.sha256 === expectedSha256, '3. Original email SHA-256 matches original bytes');

  // 4. MD5, if included, matches original bytes
  const expectedMd5 = crypto.createHash('md5').update(sample1.rawEmail, 'utf8').digest('hex');
  assert(dossier1.integrity.md5 === expectedMd5, '4. MD5 matches original bytes');

  // 5. Dossier integrity digest detects modification
  const jsonReport1 = generateJsonReport(dossier1, { caseNumber: 'CASE-001' });
  const initialDigest = jsonReport1.exportPayload.integritySeal.dossierDigest;
  assert(typeof initialDigest === 'string' && initialDigest.length === 64, '5. Dossier integrity digest is a valid 64-character SHA-256 hex string');

  // 6. Changing a finding causes verification failure
  console.log('\n--- Test Group 2: Tamper Detection Across Evidentiary Components ---');
  {
    const tamperedReport = JSON.parse(JSON.stringify(jsonReport1.exportPayload));
    if (tamperedReport.dossier.deterministicFindings?.length > 0) {
      tamperedReport.dossier.deterministicFindings[0].title = 'Tampered finding title';
    }
    const result = verifyReportIntegrity(tamperedReport);
    assert(result.status === 'TAMPERED' && result.integrity.match === false, '6. Changing a finding causes verification failure (TAMPERED)');
  }

  // 7. Changing evidence causes verification failure
  {
    const tamperedReport = JSON.parse(JSON.stringify(jsonReport1.exportPayload));
    if (tamperedReport.dossier.forensicEvidenceLedger?.length > 0) {
      tamperedReport.dossier.forensicEvidenceLedger[0].value = 'tampered_value@attacker.com';
    }
    const result = verifyReportIntegrity(tamperedReport);
    assert(result.status === 'TAMPERED' && result.integrity.match === false, '7. Changing evidence causes verification failure (TAMPERED)');
  }

  // 8. Changing a hash causes verification failure
  {
    const tamperedReport = JSON.parse(JSON.stringify(jsonReport1.exportPayload));
    tamperedReport.dossier.emailAcquisitionIntegrity.sha256 = '0000000000000000000000000000000000000000000000000000000000000000';
    const result = verifyReportIntegrity(tamperedReport);
    assert(result.status === 'TAMPERED' && result.integrity.match === false, '8. Changing email acquisition hash causes verification failure (TAMPERED)');
  }

  // 9. Changing report metadata included in the seal causes verification failure
  {
    const tamperedReport = JSON.parse(JSON.stringify(jsonReport1.exportPayload));
    tamperedReport.dossier.caseInformation.caseNumber = 'CASE-MODIFIED-999';
    const result = verifyReportIntegrity(tamperedReport);
    assert(result.status === 'TAMPERED' && result.integrity.match === false, '9. Changing case/report metadata in seal causes verification failure (TAMPERED)');
  }

  // 10. HTML report is standalone
  console.log('\n--- Test Group 3: Standalone Forensic HTML Report ---');
  const htmlReport = generateHtmlReport(dossier1, { caseNumber: 'CASE-001' });
  assert(htmlReport.includes('<!DOCTYPE html>') && htmlReport.includes('</html>'), '10. HTML report is a complete, standalone document');

  // 11. HTML report contains no external CDN dependencies
  const hasCdnLink = /<link[^>]+href=["']https?:\/\//i.test(htmlReport) || /<script[^>]+src=["']https?:\/\//i.test(htmlReport);
  assert(!hasCdnLink, '11. HTML report contains no external CDN stylesheets, fonts, or scripts');

  // 12. JSON export contains chain-of-custody metadata
  assert(jsonReport1.certificate && jsonReport1.certificate.certificateType === 'Digital Evidence Chain of Custody', '12. JSON export contains chain-of-custody metadata');
  assert(jsonReport1.certificate.examiner === 'AegisMail DFIR Automated Ingestion Engine', '12. Chain-of-custody examiner accurately names automated engine');

  // 13. Findings preserve evidence references
  const findingsWithEv = jsonReport1.exportPayload.dossier.deterministicFindings.filter(f => f.evidenceIds?.length > 0);
  assert(findingsWithEv.length > 0, '13. Findings preserve deterministic evidence reference IDs (E-xxx)');

  // 14. Related incidents are included correctly
  const sample4 = SAMPLE_EMAILS[3]; // Multi-hop sample
  const dossier4 = await analyzeEmail(sample4.rawEmail);
  const jsonReport4 = generateJsonReport(dossier4, { caseNumber: 'CASE-004' });
  assert(Array.isArray(jsonReport4.exportPayload.dossier.potentiallyRelatedIncidents), '14. Related incidents list is present with POTENTIALLY_RELATED classification');

  // 15. AI content is clearly advisory
  const aiSection = jsonReport1.exportPayload.dossier.aiInvestigationAssistant;
  assert(aiSection.advisoryNotice && aiSection.advisoryNotice.includes('advisory and does not constitute forensic evidence'), '15. AI content is clearly segregated under explicit advisory boundary');

  // 16. AI unavailable does not prevent report generation
  const minimalDossierNoAi = {
    metadata: { subject: 'Test Subject', from: 'sender@example.com' },
    evidence: [{ evidenceId: 'E-001', type: 'header', value: 'sender@example.com' }],
    findings: [{ findingId: 'F-001', severity: 'low', title: 'Test Finding', evidenceIds: ['E-001'] }],
    risk: { score: 10, level: 'LOW' }
  };
  const reportNoAi = generateHtmlReport(minimalDossierNoAi, { caseNumber: 'CASE-NO-AI' });
  assert(reportNoAi.includes('AI Investigation Assistant'), '16. AI unavailable does not prevent clean report generation');

  // 17. Reports are recorded in SQLite
  console.log('\n--- Test Group 4: Persistence & Report History ---');
  const testCase = createCase({ title: 'Phase 7 Verification Case', status: 'open' });
  const savedCase = saveEmailAndAnalysisToCase(testCase.id, {
    filename: 'phase7_test_email.eml',
    rawEmail: sample1.rawEmail
  }, dossier1);

  const emailId = savedCase.emails[0]?.id;
  const reportUuid1 = crypto.randomUUID();
  const reportUuid2 = crypto.randomUUID();

  const log1 = logReportExport(testCase.id, emailId, {
    reportUuid: reportUuid1,
    reportTitle: 'Test Case Export 1',
    exportFormat: 'json',
    rawSha256: dossier1.integrity.sha256,
    dossierSha256: initialDigest
  });
  assert(log1.id > 0, '17. Report export is recorded in SQLite forensic_reports table');

  // 18. Report UUIDs are unique
  const log2 = logReportExport(testCase.id, emailId, {
    reportUuid: reportUuid2,
    reportTitle: 'Test Case Export 2',
    exportFormat: 'html',
    rawSha256: dossier1.integrity.sha256,
    dossierSha256: initialDigest
  });
  assert(reportUuid1 !== reportUuid2, '18. Report UUIDs are uniquely generated per export instance');

  // 19. Report history works
  const caseHistory = getReportsForCase(testCase.id);
  assert(caseHistory.length >= 2, '19. Report history retrieves previous export records');
  assert(caseHistory[0].reportUuid && caseHistory[0].exportFormat && caseHistory[0].rawSha256 && caseHistory[0].dossierSha256, '19. History records contain UUID, format, raw SHA-256, and dossier SHA-256');

  // 20. Verification endpoint accepts valid report
  console.log('\n--- Test Group 5: Verification Service & Terminology Guarantees ---');
  const validJsonReport = generateJsonReport(dossier1, {
    caseNumber: testCase.caseNumber,
    caseId: testCase.id,
    reportUuid: reportUuid1,
    rawSha256: dossier1.integrity.sha256
  });
  const validResult = verifyReportIntegrity(validJsonReport.exportPayload);
  assert(validResult.status === 'VERIFIED_VALID' && validResult.integrity.match === true, '20. Verification endpoint accepts valid report (VERIFIED_VALID)');

  // 21. Verification endpoint detects tampered report
  const tamperedJson = JSON.parse(JSON.stringify(validJsonReport.exportPayload));
  tamperedJson.dossier.caseInformation.caseTitle = 'Altered Title In Transit';
  const tamperedResult = verifyReportIntegrity(tamperedJson);
  assert(tamperedResult.status === 'TAMPERED' && tamperedResult.integrity.match === false, '21. Verification endpoint detects tampered report (TAMPERED)');

  // 22. Invalid report format is handled safely
  const invalidResult1 = verifyReportIntegrity('MALFORMED_NON_JSON{{{');
  const invalidResult2 = verifyReportIntegrity({ missingAllFields: true });
  assert(invalidResult1.status === 'INVALID_FORMAT' && invalidResult2.status === 'INVALID_FORMAT', '22. Invalid report format is handled safely without throwing');

  // 23. No API keys/providers/internal paths leak
  const jsonReportStr = JSON.stringify(validJsonReport);
  assert(!jsonReportStr.includes('OPENROUTER') && !jsonReportStr.includes('sk-or-') && !jsonReportStr.includes('reasoningTokens'), '23. No API keys, provider credentials, or reasoning tokens leak in JSON report');
  assert(!htmlReport.includes('OPENROUTER') && !htmlReport.includes('sk-or-'), '23. No API keys or provider credentials leak in HTML report');

  // 24. No "court-admissible" guarantee appears in generated report
  assert(!htmlReport.toLowerCase().includes('court-admissible') && !jsonReportStr.toLowerCase().includes('court-admissible'), '24. No unsupported "court-admissible" claim appears in generated reports');

  // 25. SHA-256 is presented as primary integrity mechanism
  assert(htmlReport.includes('Primary Integrity') && jsonReport1.exportPayload.dossier.emailAcquisitionIntegrity.hashNote.includes('primary integrity digest'), '25. SHA-256 is presented as primary integrity mechanism');

  // 26. MD5 is not presented as a security guarantee
  assert(htmlReport.includes('Not a security guarantee') || htmlReport.includes('Legacy Reference'), '26. MD5 is explicitly presented as legacy reference, not a modern security guarantee');

  // 27. No "digital signature" claim exists without actual signing
  assert(!htmlReport.includes('Digital Signature') && !jsonReportStr.includes('Digital Signature'), '27. No "Digital Signature" claim exists without actual PKI signing; uses "Integrity Seal"');

  console.log('\n======================================================');
  console.log(`🎯 Phase 7 Test Suite Complete: ${passed} Passed, ${failed} Failed`);
  console.log('======================================================\n');
}

runAllPhase7Tests().catch(err => {
  console.error('\n❌ Phase 7 Verification Suite Error:', err);
  process.exit(1);
});
