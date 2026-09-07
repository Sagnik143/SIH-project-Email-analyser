import crypto from 'crypto';

/**
 * Deterministically sorts all object keys alphabetically, recursing into sub-objects.
 * For arrays that do not have strict sequential meaning, ensures stable ordering.
 */
export function canonicalizeObject(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(canonicalizeObject);
  }
  const sortedKeys = Object.keys(obj).sort();
  const result = {};
  for (const key of sortedKeys) {
    // Exclude transient envelope fields or self-referential seal digests from the hash payload
    if (key === 'integritySeal' || key === 'dossierDigest' || key === 'reportMetadata') {
      continue;
    }
    result[key] = canonicalizeObject(obj[key]);
  }
  return result;
}

/**
 * Computes a deterministic SHA-256 digest over the canonicalized JSON representation of an object.
 */
export function computeCanonicalHash(obj) {
  const canonical = canonicalizeObject(obj);
  const jsonString = JSON.stringify(canonical);
  return crypto.createHash('sha256').update(jsonString, 'utf8').digest('hex');
}

/**
 * Normalizes and extracts evidence records into a stable, sorted array.
 */
function extractCanonicalEvidence(evidenceList = []) {
  return (evidenceList || []).map(e => ({
    evidenceId: e.evidenceId || e.id || 'E-000',
    type: e.type || 'UNKNOWN',
    field: e.field || '',
    value: e.value || '',
    source: e.source || 'RFC 5322 Ingestion',
    location: e.location || e.collectionMethod || ''
  })).sort((a, b) => a.evidenceId.localeCompare(b.evidenceId));
}

/**
 * Normalizes and extracts findings into a stable, sorted array with sorted evidence references.
 */
function extractCanonicalFindings(findingsList = []) {
  return (findingsList || []).map(f => ({
    findingId: f.findingId || f.id || 'F-000',
    severity: String(f.severity || 'low').toLowerCase(),
    title: f.title || '',
    summary: f.summary || f.description || '',
    evidenceIds: Array.isArray(f.evidenceIds) ? [...f.evidenceIds].sort() : [],
    limitations: Array.isArray(f.limitations) ? f.limitations : (f.limitations ? [f.limitations] : []),
    recommendedAction: f.recommendedAction || f.recommendation || ''
  })).sort((a, b) => a.findingId.localeCompare(b.findingId));
}

/**
 * Generates the canonical authoritative investigation dossier representation.
 * Every field included here contributes to the deterministic SHA-256 integrity seal.
 */
export function generateCanonicalDossier(dossier, options = {}) {
  const metadata = dossier.metadata || dossier.parsed || {};
  const envelope = dossier.envelope || {};
  const auth = dossier.authenticationContext || dossier.authAnalysis || {};
  const relay = dossier.relayAnalysis || dossier.relay || {};
  const risk = dossier.risk || { score: 0, level: 'LOW', confidence: 'LOW' };
  const originGeo = dossier.originGeo || {};
  const iocs = dossier.iocs || {};

  const rawSha256 = options.rawSha256 || 
    dossier.integrity?.sha256 || 
    dossier.hashes?.sha256 || 
    dossier.emailHashes?.sha256 || 
    dossier.metadata?.sha256 || 
    'UNAVAILABLE_RAW_HASH';

  const rawMd5 = options.rawMd5 || 
    dossier.integrity?.md5 || 
    dossier.hashes?.md5 || 
    dossier.emailHashes?.md5 || 
    dossier.metadata?.md5 || 
    null;

  const canonicalEvidence = extractCanonicalEvidence(dossier.evidence || []);
  const canonicalFindings = extractCanonicalFindings(dossier.findings || []);

  // Format related incidents with strict "potentially related" nomenclature
  const canonicalRelatedIncidents = (dossier.relatedIncidents || []).map(rel => ({
    targetCaseId: rel.targetCaseId,
    targetCaseNumber: rel.targetCaseNumber || `CASE-${rel.targetCaseId}`,
    correlationScore: rel.correlationScore,
    relationshipType: 'POTENTIALLY_RELATED',
    reasons: rel.reasons || [],
    sharedIndicators: rel.sharedIndicators || [],
    limitation: 'Shared indicators do not establish common authorship or attacker identity.'
  })).sort((a, b) => (b.correlationScore || 0) - (a.correlationScore || 0));

  // Format AI section as strictly advisory context
  const aiExplanation = dossier.aiExplanation || dossier.aiThreatIntelligence || null;
  const canonicalAi = aiExplanation ? {
    status: aiExplanation.available !== false ? 'AVAILABLE_ADVISORY' : 'UNAVAILABLE',
    classification: aiExplanation.threatClassification || aiExplanation.threatLevel || 'UNCLASSIFIED',
    summaryHypothesis: aiExplanation.summary || aiExplanation.executiveSummary || aiExplanation.forensicHypothesis || 'No AI hypothesis generated.',
    recommendedActions: aiExplanation.recommendedActions || aiExplanation.recommendedNextSteps || [],
    advisoryNotice: 'AI-generated analysis is advisory and does not constitute forensic evidence. Deterministic evidence and findings are authoritative.'
  } : {
    status: 'UNAVAILABLE',
    advisoryNotice: 'AI Investigation Assistant: Unavailable'
  };

  return {
    caseInformation: {
      caseId: dossier.caseId || options.caseId || null,
      caseNumber: dossier.caseNumber || options.caseNumber || 'UNASSIGNED',
      caseTitle: dossier.caseTitle || options.caseTitle || 'Forensic Email Examination'
    },
    emailProvenance: {
      filename: options.filename || dossier.filename || 'acquired_email.eml',
      subject: metadata.subject || envelope.subject || 'No Subject',
      from: metadata.from || envelope.from?.address || 'Unknown',
      to: metadata.to || envelope.to?.address || 'Unknown',
      date: metadata.date || envelope.date || 'Unknown',
      messageId: metadata.messageId || envelope.messageId || 'Unknown',
      replyTo: envelope.replyTo?.address || null,
      returnPath: envelope.returnPath || null
    },
    emailAcquisitionIntegrity: {
      sha256: rawSha256,
      md5Reference: rawMd5,
      hashSourceStatement: 'SHA-256 calculated from original acquired email content.',
      hashNote: 'SHA-256 is the primary integrity digest. MD5 is provided solely for legacy cross-reference and is not a secure modern integrity guarantee.'
    },
    riskAssessment: {
      heuristicRiskScore: risk.score ?? 0,
      riskLevel: risk.level || 'LOW',
      confidence: risk.confidence || 'LOW',
      nature: 'Heuristic calculation based on observed deterministic indicators; not a probability of guilt or malicious intent.',
      contributingSignals: risk.contributingFactors || risk.signals || []
    },
    authenticationAnalysis: {
      spf: auth.spf || { status: auth.spfStatus || 'NOT_EVALUATED' },
      dkim: auth.dkim || { status: auth.dkimStatus || 'NOT_EVALUATED' },
      dmarc: auth.dmarc || { status: auth.dmarcStatus || 'NOT_EVALUATED' },
      arc: auth.arc || { status: 'NOT_EVALUATED' },
      contextNote: 'Authentication statuses reflect header-reported records from recipient mail transfer agents in the ingested RFC 5322 payload.'
    },
    relayInfrastructure: {
      originatingIP: relay.originatingIP || originGeo.ip || 'NOT_IDENTIFIED',
      originStatus: relay.originatingIPStatus || 'UNVERIFIED',
      totalHops: relay.totalHops || 0,
      transitDelaySeconds: relay.totalTransitTimeSeconds || 0,
      timingAnomalies: relay.hopAnomalies || [],
      geolocation: {
        city: originGeo.city || 'Unknown',
        country: originGeo.country || 'Unknown',
        countryCode: originGeo.countryCode || '',
        asn: originGeo.asn || '',
        isp: originGeo.isp || '',
        limitation: 'IP geolocation describes network infrastructure and does not establish the physical location or identity of the sender.'
      }
    },
    indicatorsOfCompromise: {
      urls: iocs.urls || [],
      domains: iocs.domains || [],
      ips: iocs.ips || [],
      attachments: iocs.attachments || []
    },
    deterministicFindings: canonicalFindings,
    forensicEvidenceLedger: canonicalEvidence,
    potentiallyRelatedIncidents: canonicalRelatedIncidents,
    aiInvestigationAssistant: canonicalAi,
    forensicLimitations: [
      'Digital forensic analysis is bounded by available RFC 5322 email headers and message payloads.',
      'Header-reported authentication results were recorded by receiving systems and were not independently observed at network ingress.',
      'Observed network relay infrastructure indicates transit pathing and does not definitively identify physical actor identity or geography.',
      'Potential incident correlation reflects technical indicator overlap and does not assert unified campaign control or common authorship without independent evidence.'
    ]
  };
}

/**
 * Generates the structured Chain of Custody metadata envelope.
 */
export function generateChainOfCustodyCertificate(dossier, options = {}) {
  const reportUuid = options.reportUuid || crypto.randomUUID();
  const now = new Date().toISOString();

  const canonicalDossier = generateCanonicalDossier(dossier, options);
  const dossierDigest = computeCanonicalHash(canonicalDossier);

  const evidence = canonicalDossier.forensicEvidenceLedger || [];
  const findings = canonicalDossier.deterministicFindings || [];

  const evidenceRange = evidence.length > 0 
    ? `${evidence[0].evidenceId} ... ${evidence[evidence.length - 1].evidenceId}`
    : 'None';

  const findingRange = findings.length > 0
    ? `${findings[0].findingId} ... ${findings[findings.length - 1].findingId}`
    : 'None';

  const certData = {
    certificateType: 'Digital Evidence Chain of Custody',
    certificateId: `CERT-${reportUuid}`,
    examiner: 'AegisMail DFIR Automated Ingestion Engine',
    generatedAt: now,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    standardAlignment: 'Aligned with relevant digital-evidence handling principles (ISO/IEC 27037)',
    platform: 'AegisMail DFIR Forensic Investigation Platform v7.0',
    caseNumber: canonicalDossier.caseInformation.caseNumber,
    caseId: canonicalDossier.caseInformation.caseId,
    acquisition: {
      filename: canonicalDossier.emailProvenance.filename,
      sha256: canonicalDossier.emailAcquisitionIntegrity.sha256,
      rawSha256: canonicalDossier.emailAcquisitionIntegrity.sha256,
      md5: canonicalDossier.emailAcquisitionIntegrity.md5Reference,
      rawMd5: canonicalDossier.emailAcquisitionIntegrity.md5Reference,
      hashSource: canonicalDossier.emailAcquisitionIntegrity.hashSourceStatement
    },
    dossierIntegrity: {
      algorithm: 'SHA-256',
      digest: dossierDigest,
      scope: 'Deterministic SHA-256 integrity seal calculated over canonical investigation dossier'
    },
    integritySeal: {
      algorithm: 'SHA-256',
      dossierDigest,
      digest: dossierDigest,
      sealedAt: now
    },
    evidenceRange,
    findingRange,
    evidenceItemCount: evidence.length,
    findingItemCount: findings.length,
    evidenceSummary: {
      totalEvidenceRecords: evidence.length,
      totalFindings: findings.length
    }
  };

  return {
    ...certData,
    certificate: certData
  };
}

/**
 * Builds the canonical JSON forensic report export.
 */
export function generateJsonReport(dossier, options = {}) {
  const reportUuid = options.reportUuid || crypto.randomUUID();
  const certObj = generateChainOfCustodyCertificate(dossier, { ...options, reportUuid });
  const canonicalDossier = generateCanonicalDossier(dossier, options);
  const dossierDigest = certObj.certificate.dossierIntegrity.digest;

  const exportPayload = {
    format: 'aegismail-canonical-forensic-report',
    version: '7.0',
    specification: 'AICTE DFIR Problem Statement #26106',
    alignment: 'Aligned with relevant digital-evidence handling principles (ISO/IEC 27037)',
    reportUuid,
    generatedAt: certObj.certificate.generatedAt,
    chainOfCustody: certObj.certificate,
    dossier: canonicalDossier,
    integritySeal: {
      algorithm: 'SHA-256',
      dossierDigest,
      sealedAt: certObj.certificate.generatedAt,
      method: 'SHA-256 computed over canonical dossier contents'
    }
  };

  return {
    reportUuid,
    certificate: certObj.certificate,
    exportPayload,
    canonicalJson: JSON.stringify(exportPayload, null, 2)
  };
}

/**
 * Backward-compatible alias for generateJsonReport.
 */
export function generateCanonicalJsonExport(dossier, options = {}) {
  return generateJsonReport(dossier, options);
}

/**
 * Escapes HTML entities for safe template injection.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Renders a clean severity badge with embedded CSS.
 */
function renderSeverityBadge(severity) {
  const s = String(severity || 'low').toLowerCase();
  let bg = '#e2e8f0';
  let color = '#334155';
  let border = '#cbd5e1';

  if (s === 'critical') { bg = '#fee2e2'; color = '#991b1b'; border = '#fca5a5'; }
  else if (s === 'high') { bg = '#ffedd5'; color = '#9a3412'; border = '#fdba74'; }
  else if (s === 'medium') { bg = '#fef3c7'; color = '#92400e'; border = '#fde68a'; }
  else if (s === 'low') { bg = '#dcfce7'; color = '#166534'; border = '#86efac'; }

  return `<span style="display:inline-block;padding:2px 8px;font-size:11px;font-weight:700;text-transform:uppercase;border-radius:4px;background:${bg};color:${color};border:1px solid ${border};">${escapeHtml(s)}</span>`;
}

/**
 * Generates a professional, standalone, print/PDF-ready forensic HTML report.
 * Completely self-contained: no CDN, external fonts, external CSS, or external JS.
 */
export function generateHtmlReport(dossier, options = {}) {
  const jsonReport = generateJsonReport(dossier, options);
  const cert = jsonReport.certificate;
  const d = jsonReport.exportPayload.dossier;
  const seal = jsonReport.exportPayload.integritySeal;

  const findings = d.deterministicFindings || [];
  const evidence = d.forensicEvidenceLedger || [];
  const related = d.potentiallyRelatedIncidents || [];
  const ai = d.aiInvestigationAssistant || {};
  const auth = d.authenticationAnalysis || {};
  const relay = d.relayInfrastructure || {};
  const prov = d.emailProvenance || {};
  const risk = d.riskAssessment || {};

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forensic Investigation Report - ${escapeHtml(d.caseInformation.caseNumber)}</title>
  <style>
    /* Clean, professional forensic analyst styling - no external CDN or web fonts */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      background-color: #f8fafc;
      color: #1e293b;
      line-height: 1.5;
      font-size: 13px;
      padding: 24px;
    }
    .report-container {
      max-width: 980px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 32px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid #0f172a;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .header-left h1 {
      font-size: 20px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.3px;
    }
    .header-left .meta-sub {
      font-size: 11px;
      color: #64748b;
      margin-top: 4px;
    }
    .header-right {
      text-align: right;
    }
    .seal-badge {
      display: inline-block;
      padding: 6px 12px;
      background: #f0fdf4;
      border: 1px solid #86efac;
      border-radius: 6px;
      color: #166534;
      font-size: 11px;
      font-weight: 700;
    }
    .section-card {
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 20px;
      background: #ffffff;
      page-break-inside: avoid;
    }
    .section-title {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #0f172a;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 8px;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .field { margin-bottom: 6px; }
    .label { font-size: 10px; font-weight: 700; text-transform: uppercase; color: #64748b; }
    .value { font-size: 12px; color: #0f172a; word-break: break-all; }
    .mono { font-family: Consolas, Monaco, "Courier New", monospace; font-size: 11px; }
    .hash-box {
      font-family: Consolas, Monaco, "Courier New", monospace;
      font-size: 11px;
      background: #f1f5f9;
      padding: 4px 8px;
      border-radius: 4px;
      border: 1px solid #e2e8f0;
      color: #0f172a;
      word-break: break-all;
      display: inline-block;
    }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 12px; }
    th {
      text-align: left;
      padding: 8px;
      background: #f8fafc;
      border-bottom: 2px solid #cbd5e1;
      color: #475569;
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 700;
    }
    td {
      padding: 8px;
      border-bottom: 1px solid #e2e8f0;
      vertical-align: top;
    }
    tr:last-child td { border-bottom: none; }
    .advisory-box {
      background: #eff6ff;
      border-left: 3px solid #3b82f6;
      padding: 10px 14px;
      border-radius: 0 6px 6px 0;
      margin: 10px 0;
      font-size: 12px;
      color: #1e40af;
    }
    .limitation-box {
      background: #fffbeb;
      border-left: 3px solid #f59e0b;
      padding: 10px 14px;
      border-radius: 0 6px 6px 0;
      margin: 10px 0;
      font-size: 12px;
      color: #92400e;
    }
    .cert-container {
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 14px;
      margin-bottom: 20px;
    }
    .print-controls {
      display: flex;
      justify-content: flex-end;
      margin-bottom: 16px;
    }
    .btn-print {
      background: #0f172a;
      color: #ffffff;
      border: none;
      padding: 8px 16px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn-print:hover { background: #1e293b; }

    /* Print & PDF styling */
    @media print {
      body { background: #ffffff !important; padding: 0 !important; font-size: 11px !important; color: #000000 !important; }
      .report-container { max-width: 100% !important; border: none !important; box-shadow: none !important; padding: 0 !important; }
      .print-controls { display: none !important; }
      .section-card { border: 1px solid #cccccc !important; break-inside: avoid; margin-bottom: 12px !important; }
      .header-bar { border-bottom: 2px solid #000000 !important; }
      .seal-badge { border-color: #000000 !important; color: #000000 !important; }
      th { background: #f1f5f9 !important; border-bottom: 2px solid #000000 !important; color: #000000 !important; }
      td { border-bottom: 1px solid #e2e8f0 !important; color: #000000 !important; }
      .hash-box { background: #f8fafc !important; border: 1px solid #999999 !important; color: #000000 !important; }
      .advisory-box { background: #f9f9f9 !important; border-left-color: #000000 !important; color: #000000 !important; }
      .limitation-box { background: #f9f9f9 !important; border-left-color: #000000 !important; color: #000000 !important; }
    }
  </style>
</head>
<body>

  <div class="report-container">
    
    <!-- Top Print Control (Hidden in Print View) -->
    <div class="print-controls">
      <button class="btn-print" onclick="window.print()">Print / Save PDF</button>
    </div>

    <!-- 1. Report Title & Header -->
    <div class="header-bar">
      <div class="header-left">
        <h1>AEGISMAIL DFIR FORENSIC EXAMINATION REPORT</h1>
        <div class="meta-sub">
          Report Generated from the AegisMail Forensic Investigation Pipeline &bull; AICTE Problem Statement #26106
        </div>
        <div class="meta-sub">
          Standard Alignment: Aligned with relevant digital-evidence handling principles (ISO/IEC 27037)
        </div>
      </div>
      <div class="header-right">
        <div class="seal-badge">TAMPER-EVIDENT INTEGRITY SEAL</div>
        <div style="font-size: 10px; color: #64748b; margin-top: 4px; font-family: monospace;">UUID: ${escapeHtml(jsonReport.reportUuid)}</div>
      </div>
    </div>

    <!-- 2. Case Information -->
    <div class="section-card">
      <div class="section-title">Case Information</div>
      <div class="grid-3">
        <div class="field">
          <div class="label">Case Number</div>
          <div class="value" style="font-weight: 700;">${escapeHtml(d.caseInformation.caseNumber)}</div>
        </div>
        <div class="field">
          <div class="label">Case Title</div>
          <div class="value">${escapeHtml(d.caseInformation.caseTitle)}</div>
        </div>
        <div class="field">
          <div class="label">Generated Timestamp</div>
          <div class="value mono">${escapeHtml(cert.generatedAt)} (${escapeHtml(cert.timezone)})</div>
        </div>
      </div>
    </div>

    <!-- 3. Digital Evidence Chain of Custody Certificate -->
    <div class="cert-container">
      <div class="section-title" style="margin-bottom: 8px;">Digital Evidence Chain-of-Custody Metadata</div>
      <div class="grid-2">
        <div>
          <div class="field"><span class="label">Examiner / Provenance:</span> <span class="value">${escapeHtml(cert.examiner)}</span></div>
          <div class="field"><span class="label">Investigation Platform:</span> <span class="value">${escapeHtml(cert.platform)}</span></div>
          <div class="field"><span class="label">Evidence Range:</span> <span class="value mono">${escapeHtml(cert.evidenceRange)} (${cert.evidenceItemCount} records)</span></div>
          <div class="field"><span class="label">Finding Range:</span> <span class="value mono">${escapeHtml(cert.findingRange)} (${cert.findingItemCount} findings)</span></div>
        </div>
        <div>
          <div class="field">
            <span class="label">Acquisition Filename:</span> <span class="value mono">${escapeHtml(cert.acquisition.filename)}</span>
          </div>
          <div class="field">
            <span class="label">Original Email SHA-256 (Primary Integrity):</span><br>
            <span class="hash-box">${escapeHtml(cert.acquisition.sha256)}</span>
          </div>
          ${cert.acquisition.md5 ? `
          <div class="field">
            <span class="label">Legacy Reference MD5 (Not a security guarantee):</span><br>
            <span class="hash-box" style="color: #64748b;">${escapeHtml(cert.acquisition.md5)}</span>
          </div>
          ` : ''}
          <div class="field">
            <span class="label">Dossier SHA-256 Integrity Digest:</span><br>
            <span class="hash-box" style="border-color: #86efac; background: #f0fdf4;">${escapeHtml(cert.dossierIntegrity.digest)}</span>
          </div>
        </div>
      </div>
      <div style="font-size: 10px; color: #64748b; margin-top: 8px; font-style: italic;">
        ${escapeHtml(d.emailAcquisitionIntegrity.hashSourceStatement)} ${escapeHtml(d.emailAcquisitionIntegrity.hashNote)}
      </div>
    </div>

    <!-- 4. Executive Investigation Summary -->
    <div class="section-card">
      <div class="section-title">Executive Investigation Summary</div>
      <div class="grid-2">
        <div>
          <div class="field"><span class="label">Email Subject:</span> <span class="value" style="font-weight: 600;">${escapeHtml(prov.subject)}</span></div>
          <div class="field"><span class="label">Sender (From):</span> <span class="value mono">${escapeHtml(prov.from)}</span></div>
          <div class="field"><span class="label">Recipient (To):</span> <span class="value mono">${escapeHtml(prov.to)}</span></div>
        </div>
        <div>
          <div class="field"><span class="label">Date Header:</span> <span class="value">${escapeHtml(prov.date)}</span></div>
          <div class="field"><span class="label">Message-ID:</span> <span class="value mono">${escapeHtml(prov.messageId)}</span></div>
          ${prov.replyTo ? `<div class="field"><span class="label">Reply-To Address:</span> <span class="value mono" style="color: #b91c1c;">${escapeHtml(prov.replyTo)}</span></div>` : ''}
        </div>
      </div>
    </div>

    <!-- 5. Heuristic Risk Score -->
    <div class="section-card">
      <div class="section-title">Heuristic Risk Evaluation</div>
      <div class="grid-4" style="margin-bottom: 12px;">
        <div style="text-align:center; padding: 8px; background: #f8fafc; border-radius: 6px;">
          <div class="label">Heuristic Risk Score</div>
          <div style="font-size: 24px; font-weight: 800; color: ${risk.heuristicRiskScore >= 70 ? '#dc2626' : risk.heuristicRiskScore >= 40 ? '#d97706' : '#16a34a'};">
            ${risk.heuristicRiskScore}/100
          </div>
          <div style="font-size: 11px; font-weight: 700;">${escapeHtml(risk.riskLevel)}</div>
        </div>
        <div style="text-align:center; padding: 8px; background: #f8fafc; border-radius: 6px;">
          <div class="label">Confidence Level</div>
          <div style="font-size: 20px; font-weight: 700; color: #2563eb; margin-top: 4px;">${escapeHtml(risk.confidence)}</div>
          <div style="font-size: 10px; color: #64748b;">Deterministic Signals</div>
        </div>
        <div style="text-align:center; padding: 8px; background: #f8fafc; border-radius: 6px;">
          <div class="label">Total Findings</div>
          <div style="font-size: 20px; font-weight: 700; color: #0f172a; margin-top: 4px;">${findings.length}</div>
          <div style="font-size: 10px; color: #64748b;">Observable Findings</div>
        </div>
        <div style="text-align:center; padding: 8px; background: #f8fafc; border-radius: 6px;">
          <div class="label">Total Evidence Items</div>
          <div style="font-size: 20px; font-weight: 700; color: #0f172a; margin-top: 4px;">${evidence.length}</div>
          <div style="font-size: 10px; color: #64748b;">Recorded Artifacts</div>
        </div>
      </div>
      <div class="limitation-box" style="margin-bottom: 0;">
        <strong>Methodology Notice:</strong> ${escapeHtml(risk.nature)}
      </div>
    </div>

    <!-- 6. Deterministic Findings -->
    <div class="section-card">
      <div class="section-title">Deterministic Forensic Findings (${findings.length})</div>
      ${findings.length === 0 ? '<p style="color:#64748b; font-style:italic;">No deterministic threat findings identified.</p>' : `
      <table>
        <thead>
          <tr>
            <th style="width: 70px;">ID</th>
            <th style="width: 90px;">Severity</th>
            <th>Finding Details</th>
            <th style="width: 140px;">Supporting Evidence</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map(f => `
          <tr>
            <td class="mono" style="font-weight: 700;">${escapeHtml(f.findingId)}</td>
            <td>${renderSeverityBadge(f.severity)}</td>
            <td>
              <strong style="color: #0f172a;">${escapeHtml(f.title)}</strong><br>
              <span style="color: #334155;">${escapeHtml(f.summary)}</span>
              ${f.limitations && f.limitations.length > 0 ? `<br><small style="color: #92400e;"><em>Context:</em> ${escapeHtml(f.limitations.join('; '))}</small>` : ''}
              ${f.recommendedAction ? `<br><small style="color: #1e40af;"><em>Action:</em> ${escapeHtml(f.recommendedAction)}</small>` : ''}
            </td>
            <td>
              ${(f.evidenceIds || []).map(eid => `<span class="mono" style="display:inline-block; background:#f1f5f9; border:1px solid #cbd5e1; padding:1px 5px; border-radius:3px; margin:2px;">${escapeHtml(eid)}</span>`).join('')}
            </td>
          </tr>
          `).join('')}
        </tbody>
      </table>
      `}
    </div>

    <!-- 7. Evidence Trace Ledger -->
    <div class="section-card">
      <div class="section-title">Forensic Evidence Ledger (${evidence.length})</div>
      <table>
        <thead>
          <tr>
            <th style="width: 70px;">Evidence ID</th>
            <th style="width: 110px;">Type / Field</th>
            <th>Observed Artifact Value</th>
            <th style="width: 160px;">Origin / Collection</th>
          </tr>
        </thead>
        <tbody>
          ${evidence.map(e => `
          <tr>
            <td class="mono" style="font-weight: 700; color: #2563eb;">${escapeHtml(e.evidenceId)}</td>
            <td>
              <span style="text-transform: uppercase; font-size: 10px; font-weight: 700; color: #64748b;">${escapeHtml(e.type)}</span><br>
              <small class="mono" style="color: #475569;">${escapeHtml(e.field)}</small>
            </td>
            <td class="mono" style="word-break: break-all; color: #0f172a;">${escapeHtml(e.value)}</td>
            <td style="font-size: 11px; color: #64748b;">${escapeHtml(e.source || e.location || 'RFC 5322 Ingestion')}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <!-- 8. Authentication Analysis -->
    <div class="section-card">
      <div class="section-title">Email Authentication Analysis</div>
      <table>
        <thead>
          <tr>
            <th>Protocol</th>
            <th>Header-Reported Result</th>
            <th>Evaluated Identifier</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>SPF (RFC 7208)</strong></td>
            <td><span class="mono" style="font-weight: 700;">${escapeHtml(auth.spf?.status || 'NOT_EVALUATED')}</span></td>
            <td class="mono">${escapeHtml(auth.spf?.domain || prov.from?.split('@')[1] || '-')}</td>
          </tr>
          <tr>
            <td><strong>DKIM (RFC 6376)</strong></td>
            <td><span class="mono" style="font-weight: 700;">${escapeHtml(auth.dkim?.status || 'NOT_EVALUATED')}</span></td>
            <td class="mono">${escapeHtml(auth.dkim?.signingDomain || '-')}</td>
          </tr>
          <tr>
            <td><strong>DMARC (RFC 7489)</strong></td>
            <td><span class="mono" style="font-weight: 700;">${escapeHtml(auth.dmarc?.status || 'NOT_EVALUATED')}</span></td>
            <td class="mono">${escapeHtml(auth.dmarc?.policyDomain || prov.from?.split('@')[1] || '-')}</td>
          </tr>
        </tbody>
      </table>
      <div style="font-size: 10px; color: #64748b; margin-top: 8px;">
        ${escapeHtml(auth.contextNote)}
      </div>
    </div>

    <!-- 9. Relay & Infrastructure Analysis -->
    <div class="section-card">
      <div class="section-title">Relay & Routing Infrastructure</div>
      <div class="grid-2">
        <div>
          <div class="field"><span class="label">Claimed Originating IP:</span> <span class="mono" style="font-weight:700;">${escapeHtml(relay.originatingIP)}</span> <span style="font-size:10px; padding:1px 5px; background:#fef3c7; color:#92400e; border-radius:3px; font-weight:700;">${escapeHtml(relay.originStatus)}</span></div>
          <div class="field"><span class="label">Total Relay Hops:</span> <span class="value">${escapeHtml(relay.totalHops)}</span></div>
          <div class="field"><span class="label">Transit Delay:</span> <span class="value">${escapeHtml(relay.transitDelaySeconds)} seconds recorded</span></div>
        </div>
        <div>
          <div class="field"><span class="label">Infrastructure Location:</span> <span class="value">${escapeHtml(relay.geolocation?.city)}, ${escapeHtml(relay.geolocation?.country)} (${escapeHtml(relay.geolocation?.countryCode)})</span></div>
          <div class="field"><span class="label">ISP / Autonomous System:</span> <span class="value">${escapeHtml(relay.geolocation?.isp)} (${escapeHtml(relay.geolocation?.asn)})</span></div>
        </div>
      </div>
      <div style="font-size: 10px; color: #64748b; margin-top: 8px; font-style: italic;">
        ${escapeHtml(relay.geolocation?.limitation)}
      </div>
    </div>

    <!-- 10. Indicators of Compromise -->
    <div class="section-card">
      <div class="section-title">Observable Indicators</div>
      <div class="grid-2">
        <div>
          <div class="label" style="margin-bottom: 4px;">Extracted URLs (${d.indicatorsOfCompromise?.urls?.length || 0})</div>
          ${(d.indicatorsOfCompromise?.urls || []).length === 0 ? '<span style="color:#64748b; font-size:11px;">None extracted</span>' : `
          <ul class="mono" style="font-size: 11px; margin-left: 16px;">
            ${d.indicatorsOfCompromise.urls.slice(0, 10).map(u => `<li>${escapeHtml(u.defanged || u.url || u)}</li>`).join('')}
          </ul>
          `}
        </div>
        <div>
          <div class="label" style="margin-bottom: 4px;">Attachments (${d.indicatorsOfCompromise?.attachments?.length || 0})</div>
          ${(d.indicatorsOfCompromise?.attachments || []).length === 0 ? '<span style="color:#64748b; font-size:11px;">No attachments</span>' : `
          <ul class="mono" style="font-size: 11px; margin-left: 16px;">
            ${d.indicatorsOfCompromise.attachments.map(a => `<li>${escapeHtml(a.filename)} (${escapeHtml(a.sha256?.substring(0, 16))}...)</li>`).join('')}
          </ul>
          `}
        </div>
      </div>
    </div>

    <!-- 11. Potentially Related Incidents -->
    ${related.length > 0 ? `
    <div class="section-card">
      <div class="section-title">Potentially Related Incidents (${related.length})</div>
      <div class="limitation-box" style="margin-top:0;">
        <strong>Notice:</strong> POTENTIALLY RELATED incidents share observable technical indicators. Shared indicators do not establish common authorship or attacker identity.
      </div>
      <table>
        <thead>
          <tr>
            <th>Correlated Case</th>
            <th>Correlation Score</th>
            <th>Shared Technical Indicators</th>
            <th>Correlation Reasons</th>
          </tr>
        </thead>
        <tbody>
          ${related.map(r => `
          <tr>
            <td><strong>${escapeHtml(r.targetCaseNumber)}</strong></td>
            <td><strong style="color:#2563eb;">${escapeHtml(r.correlationScore)}%</strong></td>
            <td>
              ${(r.sharedIndicators || []).map(ind => `<span class="mono" style="display:inline-block; padding:2px 6px; background:#f1f5f9; border:1px solid #cbd5e1; border-radius:3px; margin:2px; font-size:10px;">${escapeHtml(ind.type)}: ${escapeHtml(ind.value)}</span>`).join('')}
            </td>
            <td style="font-size: 11px;">${(r.reasons || []).map(x => escapeHtml(x)).join('; ')}</td>
          </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ` : ''}

    <!-- 12. AI Investigation Assistant - Advisory -->
    <div class="section-card">
      <div class="section-title" style="color: #2563eb;">AI Investigation Assistant - Advisory</div>
      <div class="advisory-box">
        <strong>Non-Authoritative Advisory Notice:</strong> ${escapeHtml(ai.advisoryNotice)}
      </div>
      <div class="field" style="margin-top: 8px;">
        <div class="label">Investigation Hypothesis:</div>
        <p style="font-size: 12px; color: #1e293b; margin-top: 4px; line-height: 1.6;">${escapeHtml(ai.summaryHypothesis)}</p>
      </div>
      ${ai.recommendedActions && ai.recommendedActions.length > 0 ? `
      <div class="field" style="margin-top: 10px;">
        <div class="label">Prioritized Incident Response Actions:</div>
        <ul style="margin-left: 20px; margin-top: 4px; color: #334155; font-size: 12px;">
          ${ai.recommendedActions.map(act => `<li style="margin-bottom: 3px;">${escapeHtml(act)}</li>`).join('')}
        </ul>
      </div>
      ` : ''}
    </div>

    <!-- 13. Limitations & Disclaimers -->
    <div class="section-card">
      <div class="section-title">Forensic Limitations & Disclaimers</div>
      <ul style="margin-left: 20px; font-size: 11px; color: #475569; line-height: 1.6;">
        ${(d.forensicLimitations || []).map(l => `<li>${escapeHtml(l)}</li>`).join('')}
      </ul>
    </div>

    <!-- 14. Integrity Verification Information -->
    <div class="section-card" style="text-align: center; font-size: 11px; color: #64748b;">
      <div class="section-title" style="justify-content: center;">Evidence Integrity Verification Instructions</div>
      <p>
        <strong>1. Verify Original Email:</strong> Calculate SHA-256 over acquired file (<code class="mono">sha256sum ${escapeHtml(cert.acquisition.filename)}</code>). Output must match:<br>
        <span class="hash-box" style="margin-top: 4px;">${escapeHtml(cert.acquisition.sha256)}</span>
      </p>
      <p style="margin-top: 8px;">
        <strong>2. Verify Report Envelope:</strong> Submit exported JSON payload to AegisMail API endpoint <code class="mono">POST /api/reports/verify</code>.<br>
        Canonical Dossier Seal: <span class="hash-box" style="margin-top: 4px;">${escapeHtml(seal.dossierDigest)}</span>
      </p>
    </div>

  </div>

</body>
</html>`;
}

/**
 * Backward-compatible alias for generateHtmlReport.
 */
export function generateForensicHtmlReport(dossier, certificate) {
  return generateHtmlReport(dossier, { reportUuid: certificate?.certificate?.certificateId?.replace(/^CERT-/, '') });
}
