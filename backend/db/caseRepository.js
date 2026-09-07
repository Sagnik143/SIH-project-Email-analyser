/**
 * Case Repository & Data Access Layer
 * Provides clean, transactional database operations for cases, emails, evidence, findings, and indicators.
 */

import { getDb } from './database.js';
import crypto from 'crypto';

/**
 * Generates next sequential human-readable case number: CASE-001, CASE-002, etc.
 * Backend-guaranteed uniqueness across all persisted cases.
 */
export function generateNextCaseNumber() {
  const db = getDb();
  const rows = db.prepare(`SELECT case_number FROM cases ORDER BY id DESC`).all();

  let maxNum = 0;
  for (const r of rows) {
    const match = (r.case_number || '').match(/^CASE-(\d+)$/i);
    if (match) {
      const num = parseInt(match[1], 10);
      if (!isNaN(num) && num > maxNum) {
        maxNum = num;
      }
    }
  }

  const nextNum = maxNum + 1;
  return `CASE-${String(nextNum).padStart(3, '0')}`;
}

/**
 * Creates a new forensic investigation case.
 */
export function createCase({ title, status = 'open' }) {
  const db = getDb();

  const cleanTitle = (title || '').trim() || 'Untitled Forensic Investigation';
  const cleanStatus = ['open', 'reviewing', 'closed'].includes((status || '').toLowerCase())
    ? status.toLowerCase()
    : 'open';

  const caseNumber = generateNextCaseNumber();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO cases (case_number, title, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  const result = stmt.run(caseNumber, cleanTitle, cleanStatus, now, now);

  return {
    id: result.lastInsertRowid,
    caseNumber,
    title: cleanTitle,
    status: cleanStatus,
    createdAt: now,
    updatedAt: now
  };
}

/**
 * Lists all cases with attached email and finding counts.
 */
export function listCases() {
  const db = getDb();

  const query = `
    SELECT 
      c.id,
      c.case_number AS caseNumber,
      c.title,
      c.status,
      c.created_at AS createdAt,
      c.updated_at AS updatedAt,
      (SELECT COUNT(*) FROM emails e WHERE e.case_id = c.id) AS emailsCount,
      (SELECT COUNT(*) FROM findings f WHERE f.case_id = c.id) AS findingsCount,
      (SELECT COUNT(*) FROM findings f WHERE f.case_id = c.id AND f.severity = 'critical') AS criticalFindingsCount
    FROM cases c
    ORDER BY c.id DESC
  `;

  return db.prepare(query).all();
}

/**
 * Retrieves a single complete case by numeric ID or case number (e.g. 'CASE-001').
 * Reconstructs the complete Evidence -> Finding -> Limitation -> Recommendation graph.
 */
export function getCaseById(idOrCaseNumber) {
  const db = getDb();

  let caseRow;
  if (typeof idOrCaseNumber === 'string' && idOrCaseNumber.toUpperCase().startsWith('CASE-')) {
    caseRow = db.prepare(`SELECT * FROM cases WHERE case_number = ?`).get(idOrCaseNumber.toUpperCase());
  } else {
    const numId = parseInt(idOrCaseNumber, 10);
    if (!isNaN(numId)) {
      caseRow = db.prepare(`SELECT * FROM cases WHERE id = ?`).get(numId);
    }
  }

  if (!caseRow) {
    return null;
  }

  const caseId = caseRow.id;

  // 1. Fetch attached emails
  const emailRows = db.prepare(`
    SELECT id, case_id, filename, sha256, subject, sender, recipient, received_at, created_at
    FROM emails
    WHERE case_id = ?
    ORDER BY id ASC
  `).all(caseId);

  // 2. Fetch evidence records
  const evidenceRows = db.prepare(`
    SELECT id, email_id, evidence_key, source, field, value, collection_method, collected_at, details
    FROM evidence
    WHERE case_id = ?
    ORDER BY id ASC
  `).all(caseId);

  const formattedEvidence = evidenceRows.map(ev => {
    let parsedDetails = {};
    try {
      if (ev.details) parsedDetails = JSON.parse(ev.details);
    } catch (e) {}
    return {
      dbId: ev.id,
      emailId: ev.email_id,
      id: ev.evidence_key,
      source: ev.source,
      field: ev.field,
      value: ev.value,
      collectionMethod: ev.collection_method,
      collectedAt: ev.collected_at,
      details: parsedDetails
    };
  });

  // Map db evidence id -> human evidence key (E-001)
  const dbIdToEvKey = new Map(formattedEvidence.map(e => [e.dbId, e.id]));

  // 3. Fetch findings and their linked evidence
  const findingRows = db.prepare(`
    SELECT id, email_id, finding_key, type, severity, title, summary, limitations, recommended_action, created_at
    FROM findings
    WHERE case_id = ?
    ORDER BY id ASC
  `).all(caseId);

  const joinRows = db.prepare(`
    SELECT fe.finding_id, fe.evidence_id
    FROM finding_evidence fe
    JOIN findings f ON f.id = fe.finding_id
    WHERE f.case_id = ?
  `).all(caseId);

  const findingToEvIds = new Map();
  for (const j of joinRows) {
    if (!findingToEvIds.has(j.finding_id)) {
      findingToEvIds.set(j.finding_id, []);
    }
    const evKey = dbIdToEvKey.get(j.evidence_id);
    if (evKey) {
      findingToEvIds.get(j.finding_id).push(evKey);
    }
  }

  const formattedFindings = findingRows.map(f => {
    let parsedLimitations = [];
    try {
      if (f.limitations) parsedLimitations = JSON.parse(f.limitations);
    } catch (e) {}
    return {
      dbId: f.id,
      emailId: f.email_id,
      id: f.finding_key,
      type: f.type,
      severity: f.severity,
      title: f.title,
      summary: f.summary,
      evidenceIds: (findingToEvIds.get(f.id) || []).sort(),
      limitations: parsedLimitations,
      recommendedAction: f.recommended_action,
      createdAt: f.created_at
    };
  });

  // 4. Fetch indicators
  const indicatorRows = db.prepare(`
    SELECT id, email_id, type, value, defanged, is_suspicious, details, created_at
    FROM indicators
    WHERE case_id = ?
    ORDER BY id ASC
  `).all(caseId);

  const formattedIndicators = indicatorRows.map(ind => {
    let parsedDetails = {};
    try {
      if (ind.details) parsedDetails = JSON.parse(ind.details);
    } catch (e) {}
    return {
      id: ind.id,
      emailId: ind.email_id,
      type: ind.type,
      value: ind.value,
      defanged: ind.defanged,
      isSuspicious: Boolean(ind.is_suspicious),
      details: parsedDetails,
      createdAt: ind.created_at
    };
  });

  return {
    case: {
      id: caseRow.id,
      caseNumber: caseRow.case_number,
      title: caseRow.title,
      status: caseRow.status,
      createdAt: caseRow.created_at,
      updatedAt: caseRow.updated_at
    },
    emails: emailRows,
    evidence: formattedEvidence,
    findings: formattedFindings,
    indicators: formattedIndicators,
    stats: {
      totalEmails: emailRows.length,
      totalEvidence: formattedEvidence.length,
      totalFindings: formattedFindings.length,
      totalIndicators: formattedIndicators.length,
      criticalFindings: formattedFindings.filter(f => f.severity === 'critical').length,
      highFindings: formattedFindings.filter(f => f.severity === 'high').length
    }
  };
}

/**
 * Persists an analyzed email, its Phase 2 evidence, findings, and indicators into a case.
 * Runs atomically inside a SQLite transaction: rollback on any error.
 */
export function saveEmailAndAnalysisToCase(caseIdOrNumber, emailInput, dossier) {
  const db = getDb();

  // Find case first
  let caseRow;
  if (typeof caseIdOrNumber === 'string' && caseIdOrNumber.toUpperCase().startsWith('CASE-')) {
    caseRow = db.prepare(`SELECT * FROM cases WHERE case_number = ?`).get(caseIdOrNumber.toUpperCase());
  } else {
    const numId = parseInt(caseIdOrNumber, 10);
    if (!isNaN(numId)) {
      caseRow = db.prepare(`SELECT * FROM cases WHERE id = ?`).get(numId);
    }
  }

  if (!caseRow) {
    throw new Error(`Target case '${caseIdOrNumber}' not found.`);
  }

  const caseId = caseRow.id;
  const rawEmail = typeof emailInput.rawEmail === 'string'
    ? emailInput.rawEmail
    : (emailInput.buffer ? emailInput.buffer.toString('utf-8') : '');

  if (!rawEmail || rawEmail.trim().length === 0) {
    throw new Error('Cannot store empty raw email content.');
  }

  // Exact SHA-256 calculation preserving byte integrity
  const sha256 = crypto.createHash('sha256').update(rawEmail, 'utf-8').digest('hex');
  const now = new Date().toISOString();

  // Transaction statement execution
  const saveTransaction = db.transaction(() => {
    // 1. Insert Email record
    const insertEmailStmt = db.prepare(`
      INSERT INTO emails (case_id, filename, sha256, subject, sender, recipient, received_at, raw_email, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const emailResult = insertEmailStmt.run(
      caseId,
      emailInput.filename || 'uploaded_email.eml',
      sha256,
      dossier.envelope?.subject || '(No Subject)',
      dossier.envelope?.from?.address || dossier.envelope?.from?.raw || '',
      dossier.envelope?.to || '',
      dossier.envelope?.date || now,
      rawEmail,
      now
    );
    const emailId = emailResult.lastInsertRowid;

    // 2. Insert Evidence records and map key -> dbId
    const insertEvidenceStmt = db.prepare(`
      INSERT INTO evidence (case_id, email_id, evidence_key, source, field, value, collection_method, collected_at, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const evidenceKeyToDbId = new Map();
    const evidenceList = dossier.evidence || [];

    for (const ev of evidenceList) {
      const detailsJson = ev.details ? JSON.stringify(ev.details) : '{}';
      const evResult = insertEvidenceStmt.run(
        caseId,
        emailId,
        ev.id, // E-001
        ev.source,
        ev.field,
        ev.value,
        ev.collectionMethod || 'uploaded_eml',
        ev.collectedAt || now,
        detailsJson
      );
      evidenceKeyToDbId.set(ev.id, evResult.lastInsertRowid);
    }

    // 3. Insert Findings and map key -> dbId, then link join table
    const insertFindingStmt = db.prepare(`
      INSERT INTO findings (case_id, email_id, finding_key, type, severity, title, summary, limitations, recommended_action, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertJoinStmt = db.prepare(`
      INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id)
      VALUES (?, ?)
    `);

    const findingsList = dossier.findings || [];

    for (const f of findingsList) {
      const limitationsJson = Array.isArray(f.limitations) ? JSON.stringify(f.limitations) : '[]';
      const fResult = insertFindingStmt.run(
        caseId,
        emailId,
        f.id, // F-001
        f.type,
        f.severity,
        f.title,
        f.summary,
        limitationsJson,
        f.recommendedAction || '',
        now
      );
      const findingDbId = fResult.lastInsertRowid;

      // Link to evidence via join table
      for (const evKey of (f.evidenceIds || [])) {
        const evDbId = evidenceKeyToDbId.get(evKey);
        if (evDbId) {
          insertJoinStmt.run(findingDbId, evDbId);
        }
      }
    }

    // 4. Insert Indicators (URLs & Attachments)
    const insertIndicatorStmt = db.prepare(`
      INSERT INTO indicators (case_id, email_id, type, value, defanged, is_suspicious, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const urls = dossier.iocs?.urls || [];
    for (const u of urls) {
      insertIndicatorStmt.run(
        caseId,
        emailId,
        'url',
        u.original,
        u.defanged,
        u.isSuspicious ? 1 : 0,
        JSON.stringify(u.flags || []),
        now
      );
    }

    const attachments = dossier.iocs?.attachments || [];
    for (const a of attachments) {
      insertIndicatorStmt.run(
        caseId,
        emailId,
        'attachment',
        a.filename,
        a.filename,
        a.isDangerous ? 1 : 0,
        JSON.stringify({ sha256: a.sha256, ext: a.extension, size: a.size }),
        now
      );
    }

    // 5. Update case timestamp
    db.prepare(`UPDATE cases SET updated_at = ? WHERE id = ?`).run(now, caseId);

    return { emailId, caseId };
  });

  const txResult = saveTransaction();
  return getCaseById(txResult.caseId);
}

/**
 * Retrieves persisted related incidents records for a given case.
 */
export function getRelatedIncidentsForCase(caseId) {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM related_incidents
    WHERE source_case_id = ? OR target_case_id = ?
    ORDER BY correlation_score DESC
  `).all(caseId, caseId);

  return rows.map(r => {
    let reasons = [];
    let sharedIndicators = [];
    try { reasons = JSON.parse(r.reasons); } catch (e) {}
    try { sharedIndicators = JSON.parse(r.shared_indicators); } catch (e) {}
    return {
      id: r.id,
      sourceEmailId: r.source_email_id,
      targetEmailId: r.target_email_id,
      sourceCaseId: r.source_case_id,
      targetCaseId: r.target_case_id,
      correlationScore: r.correlation_score,
      relationshipType: r.relationship_type,
      reasons,
      sharedIndicators,
      createdAt: r.created_at
    };
  });
}

/**
 * Retrieves persisted related incidents records for a given email.
 */
export function getRelatedIncidentsForEmail(emailId) {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM related_incidents
    WHERE source_email_id = ? OR target_email_id = ?
    ORDER BY correlation_score DESC
  `).all(emailId, emailId);

  return rows.map(r => {
    let reasons = [];
    let sharedIndicators = [];
    try { reasons = JSON.parse(r.reasons); } catch (e) {}
    try { sharedIndicators = JSON.parse(r.shared_indicators); } catch (e) {}
    return {
      id: r.id,
      sourceEmailId: r.source_email_id,
      targetEmailId: r.target_email_id,
      sourceCaseId: r.source_case_id,
      targetCaseId: r.target_case_id,
      correlationScore: r.correlation_score,
      relationshipType: r.relationship_type,
      reasons,
      sharedIndicators,
      createdAt: r.created_at
    };
  });
}

/**
 * Logs an exported forensic report to the audit table.
 */
export function logReportExport(caseId, emailId, reportData) {
  const db = getDb();
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT INTO forensic_reports (
      case_id, email_id, report_uuid, report_title, export_format,
      raw_sha256, dossier_sha256, generated_at, report_metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    caseId,
    emailId || null,
    reportData.reportUuid,
    reportData.reportTitle || 'AegisMail Forensic Examination Report',
    reportData.exportFormat,
    reportData.rawSha256,
    reportData.dossierSha256,
    reportData.generatedAt || now,
    reportData.metadata ? JSON.stringify(reportData.metadata) : null
  );

  return {
    id: result.lastInsertRowid,
    reportUuid: reportData.reportUuid
  };
}

/**
 * Retrieves all exported reports logged for a specific case.
 */
export function getReportsForCase(caseId) {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM forensic_reports
    WHERE case_id = ?
    ORDER BY generated_at DESC
  `).all(caseId);

  return rows.map(r => {
    let metadata = {};
    try { metadata = r.report_metadata ? JSON.parse(r.report_metadata) : {}; } catch (e) {}
    return {
      id: r.id,
      caseId: r.case_id,
      emailId: r.email_id,
      reportUuid: r.report_uuid,
      reportTitle: r.report_title,
      exportFormat: r.export_format,
      rawSha256: r.raw_sha256,
      dossierSha256: r.dossier_sha256,
      generatedAt: r.generated_at,
      metadata
    };
  });
}

/**
 * Finds a report by its unique UUID.
 */
export function findReportByUuid(reportUuid) {
  const db = getDb();
  const row = db.prepare(`
    SELECT * FROM forensic_reports WHERE report_uuid = ?
  `).get(reportUuid);

  if (!row) return null;

  let metadata = {};
  try { metadata = row.report_metadata ? JSON.parse(row.report_metadata) : {}; } catch (e) {}

  return {
    id: row.id,
    caseId: row.case_id,
    emailId: row.email_id,
    reportUuid: row.report_uuid,
    reportTitle: row.report_title,
    exportFormat: row.export_format,
    rawSha256: row.raw_sha256,
    dossierSha256: row.dossier_sha256,
    generatedAt: row.generated_at,
    metadata
  };
}

/**
 * Finds reports matching a specific dossier hash or raw SHA-256.
 */
export function findReportByHashes(rawSha256, dossierSha256) {
  const db = getDb();
  const row = db.prepare(`
    SELECT * FROM forensic_reports
    WHERE raw_sha256 = ? OR dossier_sha256 = ?
    ORDER BY generated_at DESC
    LIMIT 1
  `).get(rawSha256 || '', dossierSha256 || '');

  if (!row) return null;

  let metadata = {};
  try { metadata = row.report_metadata ? JSON.parse(row.report_metadata) : {}; } catch (e) {}

  return {
    id: row.id,
    caseId: row.case_id,
    emailId: row.email_id,
    reportUuid: row.report_uuid,
    reportTitle: row.report_title,
    exportFormat: row.export_format,
    rawSha256: row.raw_sha256,
    dossierSha256: row.dossier_sha256,
    generatedAt: row.generated_at,
    metadata
  };
}

