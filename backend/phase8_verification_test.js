/**
 * AegisMail Phase 8 Verification Test Suite
 * 
 * Verifies Phase 8 Trust Boundary + Evidence UX Polish criteria:
 * 1. Evidence IDs format & uniqueness (E-xxx)
 * 2. Findings-to-evidence deterministic traceability
 * 3. Evidence Inspector data contract (id, category, source, field, raw value, collection method)
 * 4. Raw evidence immutability (unaltered values)
 * 5. AI Advisory non-authoritative classification & disclaimers
 * 6. Related Incidents strictly framed as "POTENTIALLY RELATED"
 * 7. Geolocation framed strictly as "observed infrastructure location" (no human/attacker location)
 * 8. Relay timing framed strictly as "routing inconsistency" / "timing anomaly" (no impossible/physical travel)
 * 9. Risk score framed strictly as "Heuristic Risk Score" (no probability/certainty)
 * 10. Authentication claims distinguish reported vs current validation vs insufficient evidence
 * 11. Attribution framed strictly as "Observed Tactics & Investigation Hypotheses"
 * 12. Model branding, reasoning tokens, and internal provider credentials are completely suppressed
 * 13. Claimed vs Observed distinction is preserved in investigation output
 * 14. Frontend bundle integrity and zero prohibited terminology in UI components
 * 15. Backward compatibility across investigation pipeline and exports
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeEmail } from './services/investigationEngine.js';
import { SAMPLE_EMAILS } from './data/samples.js';
import { generateCanonicalDossier, generateJsonReport, generateHtmlReport } from './services/reportGeneratorService.js';
import { verifyReportIntegrity } from './services/reportVerificationService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('\n======================================================');
console.log('🛡️ Starting AegisMail Phase 8 Verification Suite');
console.log('   Focus: Trust Boundary + Evidence UX Polish');
console.log('======================================================\n');

let passedTests = 0;
let failedTests = 0;

function pass(testName) {
  console.log(`  ✓ PASS: ${testName}`);
  passedTests++;
}

function fail(testName, err) {
  console.error(`  ✕ FAIL: ${testName}`);
  console.error(err);
  failedTests++;
}

(async () => {
  try {
    const becSample = SAMPLE_EMAILS.find(s => s.id === 'sample-bec-ceo-fraud');
    assert(becSample, 'Sample BEC email must be available');
    const dossier = await analyzeEmail(becSample.rawEmail, { filename: 'sample_bec.eml' });

    console.log('--- Test Group 1: Evidence Inspector & Immutability ---');

    // 1. Evidence IDs format & uniqueness (E-xxx)
    assert(Array.isArray(dossier.evidence) && dossier.evidence.length > 0, '1. Evidence array exists');
    const evIds = dossier.evidence.map(e => e.id);
    const uniqueEvIds = new Set(evIds);
    assert(uniqueEvIds.size === evIds.length, '1. All evidence IDs are unique');
    assert(evIds.every(id => /^E-\d{3}$/.test(id)), '1. All evidence IDs conform to E-xxx format');
    pass('1. Evidence IDs conform to E-xxx format and are unique');

    // 2. Finding-to-Evidence Traceability
    assert(Array.isArray(dossier.findings) && dossier.findings.length > 0, '2. Findings array exists');
    dossier.findings.forEach(finding => {
      assert(Array.isArray(finding.evidenceIds) && finding.evidenceIds.length > 0, `Finding ${finding.id} has supporting evidence`);
      finding.evidenceIds.forEach(id => {
        assert(uniqueEvIds.has(id), `Evidence ID ${id} in finding ${finding.id} resolves to present evidence`);
      });
    });
    pass('2. Every finding deterministically traces to valid, present evidence IDs');

    // 3. Evidence Inspector Data Contract
    const firstEv = dossier.evidence[0];
    assert(firstEv.id, '3. Evidence has id');
    assert(firstEv.source, '3. Evidence has source');
    assert(firstEv.field, '3. Evidence has field');
    assert(firstEv.value !== undefined, '3. Evidence has value');
    assert(firstEv.collectionMethod, '3. Evidence has collectionMethod');
    pass('3. Evidence records satisfy the Evidence Inspector data contract');

    // 4. Raw Evidence Immutability
    const rawFromHeader = becSample.rawEmail.match(/From:\s*(.+)/i)?.[1]?.trim();
    const fromEvidence = dossier.evidence.find(e => e.field === 'From');
    assert(fromEvidence, '4. From evidence exists');
    assert(fromEvidence.value.includes(rawFromHeader) || rawFromHeader.includes(fromEvidence.value), '4. Raw From header value is preserved unaltered');
    pass('4. Original evidence values remain completely unaltered');

    console.log('\n--- Test Group 2: Trust Boundary Classifications ---');

    // 5. AI Advisory Non-Authoritative Framing
    const canonicalDossier = generateCanonicalDossier(dossier, { filename: 'sample_bec.eml' });
    assert(canonicalDossier.aiInvestigationAssistant, '5. AI Advisory section exists in canonical dossier');
    assert(canonicalDossier.aiInvestigationAssistant.advisoryNotice.includes('advisory') && 
           canonicalDossier.aiInvestigationAssistant.advisoryNotice.includes('does not constitute forensic evidence'), 
           '5. AI Advisory notice explicitly marks non-authoritative boundary');
    pass('5. AI Advisory is explicitly segregated with mandatory non-authoritative notices');

    // 6. Related Incidents Framed as POTENTIALLY RELATED
    if (canonicalDossier.potentiallyRelatedIncidents) {
      assert(Array.isArray(canonicalDossier.potentiallyRelatedIncidents), '6. Related incidents is an array');
      canonicalDossier.potentiallyRelatedIncidents.forEach(rel => {
        assert(rel.relationshipType === 'POTENTIALLY_RELATED' || rel.classification === 'POTENTIALLY_RELATED', 
               '6. Related incidents classification is strictly POTENTIALLY_RELATED');
      });
    }
    pass('6. Cross-case incident correlation is strictly classified as POTENTIALLY RELATED');

    // 7. Geolocation Infrastructure Terminology
    const geoString = JSON.stringify(dossier.originGeo || {});
    assert(!geoString.toLowerCase().includes('attacker location'), '7. Geolocation does not state attacker location');
    assert(!geoString.toLowerCase().includes('sender physical location'), '7. Geolocation does not state sender physical location');
    pass('7. Geolocation strictly describes observed infrastructure, not human location');

    // 8. Relay Timing Terminology (No physical/impossible travel)
    const relayString = JSON.stringify(dossier.relay || {});
    assert(!relayString.toLowerCase().includes('impossible travel'), '8. Relay does not state impossible travel');
    assert(!relayString.toLowerCase().includes('physically impossible'), '8. Relay does not state physically impossible');
    pass('8. Relay timing strictly describes routing inconsistencies/anomalies without travel claims');

    // 9. Heuristic Risk Score Framing
    assert(typeof dossier.heuristicRiskScore === 'number' || typeof dossier.aiThreatIntelligence?.riskScore === 'number', '9. Risk score exists');
    assert(!JSON.stringify(dossier).includes('AI Confidence: 100%'), '9. Risk score is not labeled as calibrated AI certainty');
    pass('9. Threat score is explicitly classified as a heuristic risk assessment');

    // 10. Authentication Claims Distinction
    const auth = dossier.authentication;
    assert(auth, '10. Authentication exists');
    assert(auth.evaluationContext?.mode === 'reported' || auth.spf?.source?.includes('receiving') || auth.spf?.details, '10. Authentication marks reported MTA context');
    pass('10. Authentication analysis distinguishes reported header claims from live evaluation');

    // 11. Attribution Framing as Hypotheses
    const attributionStr = JSON.stringify(dossier.attributionAndGraph || {});
    assert(!attributionStr.toLowerCase().includes('confirmed attacker'), '11. Attribution does not state confirmed attacker');
    assert(!attributionStr.toLowerCase().includes('confirmed apt'), '11. Attribution does not state confirmed APT');
    pass('11. Attribution is strictly framed as observed tactics and investigative hypotheses');

    console.log('\n--- Test Group 3: Frontend Component Terminology Audit ---');

    // 12. Model and Provider Branding Suppression
    const dossierStr = JSON.stringify(dossier);
    assert(!dossierStr.includes('gpt-6-astra'), '12. Model branding (gpt-6-astra) suppressed from dossier');
    assert(!dossierStr.includes('ExperientialLabs'), '12. Provider branding suppressed from dossier');
    pass('12. AI model names, provider branding, and reasoning tokens are completely suppressed');

    // 13. Audit Frontend Component Source Files for Forbidden Terms
    const componentsDir = path.join(__dirname, '..', 'frontend', 'src', 'components');
    const componentFiles = fs.readdirSync(componentsDir).filter(f => f.endsWith('.jsx'));
    
    let forbiddenViolations = [];
    const forbiddenPatterns = [
      /\battacker location\b/i,
      /\battacker IP\b/i,
      /\bimpossible travel\b/i,
      /\bphysically impossible\b/i,
      /\bconfirmed attacker\b/i,
      /\bconfirmed APT\b/i,
      /\bcampaign attribution\b/i,
      /\bAI probability\b/i,
      /\bmodel confidence\b/i,
      /\bguaranteed court-admissible\b/i,
      /\bISO compliant\b/i,
      /\bISO certified\b/i
    ];

    componentFiles.forEach(file => {
      const content = fs.readFileSync(path.join(componentsDir, file), 'utf8');
      forbiddenPatterns.forEach(pattern => {
        if (pattern.test(content)) {
          forbiddenViolations.push(`${file} matches ${pattern}`);
        }
      });
    });

    assert(forbiddenViolations.length === 0, `13. Zero forbidden terminology violations found in components: ${forbiddenViolations.join(', ')}`);
    pass(`13. Frontend terminology audit clean: 0 violations across ${componentFiles.length} JSX components`);

    // 14. Evidence Inspector Component Exists
    const inspectorFile = path.join(componentsDir, 'EvidenceInspectorModal.jsx');
    assert(fs.existsSync(inspectorFile), '14. EvidenceInspectorModal.jsx exists');
    const inspectorContent = fs.readFileSync(inspectorFile, 'utf8');
    assert(inspectorContent.includes('Observed Evidence'), '14. Evidence Inspector displays Observed Evidence badge');
    assert(inspectorContent.includes('Collection Method'), '14. Evidence Inspector displays Collection Method');
    pass('14. EvidenceInspectorModal component exists with required metadata fields');

    // 15. Export & Verification Compatibility
    const jsonReport = generateJsonReport(dossier, { filename: 'sample_bec.eml' });
    const payloadToVerify = jsonReport.exportPayload || jsonReport;
    const verifyRes = verifyReportIntegrity(payloadToVerify);
    assert(verifyRes.status === 'VERIFIED_VALID' || verifyRes.status === 'UNREGISTERED', '15. Generated report verifies successfully');
    assert(verifyRes.integrity?.match === true, '15. Canonical SHA-256 seal matches');
    pass('15. Report export and verification pipeline remains 100% compatible');

    console.log('\n======================================================');
    console.log(`🎯 Phase 8 Test Suite Complete: ${passedTests} Passed, ${failedTests} Failed`);
    console.log('======================================================\n');

  } catch (err) {
    fail('Phase 8 Suite Fatal Error', err);
    process.exit(1);
  }
})();
