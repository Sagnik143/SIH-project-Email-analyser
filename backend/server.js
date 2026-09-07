import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import { analyzeEmail } from './services/investigationEngine.js';
import { findRelatedCases, findRelatedEmails } from './services/correlationEngine.js';
import { SAMPLE_EMAILS } from './data/samples.js';
import { initDatabase } from './db/database.js';
import { createCase, listCases, getCaseById, saveEmailAndAnalysisToCase, logReportExport, getReportsForCase, findReportByUuid } from './db/caseRepository.js';
import { getDb } from './db/database.js';
import { generateChainOfCustodyCertificate, generateHtmlReport, generateJsonReport, generateForensicHtmlReport, generateCanonicalJsonExport } from './services/reportGeneratorService.js';
import { verifyReportIntegrity } from './services/reportVerificationService.js';

dotenv.config();

// Initialize SQLite database idempotently
initDatabase();

const app = express();
const PORT = process.env.PORT || 5001;

// Middlewares
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Multer memory storage for .eml file uploads
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    service: 'AegisMail DFIR Threat Intelligence API',
    problemStatementId: 26106,
    problemTitle: 'AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform',
    organization: 'All India Council for Technical Education (Cyber Security Cell)',
    aiEngineStatus: 'active',
    analysisPipeline: 'ready'
  });
});

// Get sample threat emails
app.get('/api/samples', (req, res) => {
  const summaries = SAMPLE_EMAILS.map(s => ({
    id: s.id,
    title: s.title,
    category: s.category,
    riskIndicator: s.riskIndicator,
    description: s.description
  }));
  res.json({ samples: summaries });
});

app.get('/api/samples/:id', (req, res) => {
  const sample = SAMPLE_EMAILS.find(s => s.id === req.params.id);
  if (!sample) {
    return res.status(404).json({ error: 'Sample not found' });
  }
  res.json(sample);
});

// Reusable Forensic Pipeline Execution (Canonical Investigation Engine Wrapper)
export async function runForensicPipeline(rawContent, options = {}) {
  return analyzeEmail(rawContent, options);
}

// Primary Forensic Analysis Endpoint (Stateless Backward Compatibility)
app.post('/api/analyze', upload.single('emailFile'), async (req, res) => {
  try {
    let rawContent = '';

    if (req.file) {
      rawContent = req.file.buffer.toString('utf-8');
    } else if (req.body.rawEmail) {
      rawContent = req.body.rawEmail;
    } else {
      return res.status(400).json({ error: 'No raw email or file provided' });
    }

    if (!rawContent || rawContent.trim().length === 0) {
      return res.status(400).json({ error: 'Email content cannot be empty' });
    }

    const forensicDossier = await runForensicPipeline(rawContent);
    console.log(`[Analyzer] Analysis complete: Risk ${forensicDossier.aiThreatIntelligence?.riskScore}/100`);
    res.json(sanitizeResponsePayload(forensicDossier));

  } catch (error) {
    console.error('[Analyzer] Unexpected analysis error:', error);
    res.status(500).json({
      error: 'Failed to complete forensic email analysis',
      message: error.message || 'An unexpected processing error occurred. Please try again later.'
    });
  }
});

// ============================================================
// PHASE 3: CASE MANAGEMENT API ENDPOINTS
// ============================================================

// Create Case
app.post('/api/cases', (req, res) => {
  try {
    const { title, status } = req.body || {};
    const newCase = createCase({ title, status });
    console.log(`[Cases] Created case ${newCase.caseNumber}: "${newCase.title}"`);
    res.status(201).json(newCase);
  } catch (err) {
    console.error('[Cases] Error creating case:', err);
    res.status(500).json({ error: 'Failed to create case', message: 'Unable to process case creation.' });
  }
});

// List Cases
app.get('/api/cases', (req, res) => {
  try {
    const cases = listCases();
    res.json({ cases });
  } catch (err) {
    console.error('[Cases] Error listing cases:', err);
    res.status(500).json({ error: 'Failed to list cases', message: 'Unable to retrieve cases.' });
  }
});

// Get Case By ID or Case Number
app.get('/api/cases/:id', (req, res) => {
  try {
    const caseData = getCaseById(req.params.id);
    if (!caseData) {
      return res.status(404).json({ error: 'Case not found' });
    }
    res.json(caseData);
  } catch (err) {
    console.error('[Cases] Error fetching case:', err);
    res.status(500).json({ error: 'Failed to fetch case', message: 'Unable to retrieve case details.' });
  }
});

// Upload and Analyze Email directly into a Case
app.post('/api/cases/:id/emails', upload.single('emailFile'), async (req, res) => {
  try {
    let rawContent = '';
    let filename = 'uploaded_email.eml';

    if (req.file) {
      rawContent = req.file.buffer.toString('utf-8');
      filename = req.file.originalname || filename;
    } else if (req.body.rawEmail) {
      rawContent = req.body.rawEmail;
      filename = req.body.filename || filename;
    } else {
      return res.status(400).json({ error: 'No raw email or file provided' });
    }

    if (!rawContent || rawContent.trim().length === 0) {
      return res.status(400).json({ error: 'Email content cannot be empty' });
    }

    // Run deterministic analysis
    const forensicDossier = await runForensicPipeline(rawContent);

    // Persist to database inside transaction
    const updatedCase = saveEmailAndAnalysisToCase(
      req.params.id,
      { filename, rawEmail: rawContent },
      forensicDossier
    );

    console.log(`[Cases] Successfully attached email to case ${req.params.id} (SHA256: ${forensicDossier.integrity?.sha256?.slice(0, 16)}...)`);
    res.status(201).json({
      case: updatedCase,
      dossier: sanitizeResponsePayload(forensicDossier)
    });
  } catch (err) {
    console.error('[Cases] Error attaching email to case:', err);
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'Case not found' });
    }
    res.status(500).json({
      error: 'Failed to attach email to case',
      message: 'An error occurred while saving analysis to case.'
    });
  }
});

// Associate existing analysis dossier to an existing case
app.post('/api/cases/:id/save-analysis', (req, res) => {
  try {
    const { rawEmail, dossier, filename = 'analyzed_email.eml' } = req.body || {};
    if (!rawEmail || !dossier) {
      return res.status(400).json({ error: 'Missing rawEmail or analysis dossier payload' });
    }

    const updatedCase = saveEmailAndAnalysisToCase(
      req.params.id,
      { filename, rawEmail },
      dossier
    );

    console.log(`[Cases] Saved existing analysis to case ${req.params.id}`);
    res.json({ case: updatedCase });
  } catch (err) {
    console.error('[Cases] Error saving existing analysis to case:', err);
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'Case not found' });
    }
    res.status(500).json({
      error: 'Failed to save analysis to case',
      message: 'Unable to associate analysis with case.'
    });
  }
});

// ============================================================
// PHASE 5: RELATED INCIDENTS API ENDPOINTS
// ============================================================

// Discover potentially related incidents for a case
app.get('/api/cases/:id/related', (req, res) => {
  try {
    const relatedData = findRelatedCases(req.params.id);
    res.json(sanitizeResponsePayload(relatedData));
  } catch (err) {
    console.error('[RelatedIncidents] Error discovering related cases:', err);
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'Case not found' });
    }
    res.status(500).json({
      error: 'Failed to retrieve related incidents',
      message: 'An error occurred during correlation analysis.'
    });
  }
});

// Discover potentially related incidents for a specific email
app.get('/api/emails/:id/related', (req, res) => {
  try {
    const relatedData = findRelatedEmails(req.params.id);
    res.json(sanitizeResponsePayload(relatedData));
  } catch (err) {
    console.error('[RelatedIncidents] Error discovering related emails:', err);
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'Email not found' });
    }
    res.status(500).json({
      error: 'Failed to retrieve related incidents for email',
      message: 'An error occurred during email correlation.'
    });
  }
});

// ============================================================
// PHASE 7: FORENSIC REPORTING & CHAIN-OF-CUSTODY EXPORTS
// ============================================================

// Helper to rebuild dossier for a case from its persisted records or raw EML
async function buildCaseDossier(caseIdOrNumber) {
  const caseData = getCaseById(caseIdOrNumber);
  if (!caseData) return null;

  const db = getDb();
  const primaryEmail = caseData.emails[0] || null;

  let rawEmail = null;
  if (primaryEmail) {
    const rawRow = db.prepare(`SELECT raw_email FROM emails WHERE id = ?`).get(primaryEmail.id);
    if (rawRow?.raw_email) {
      rawEmail = rawRow.raw_email;
    }
  }

  let dossier;
  if (rawEmail) {
    dossier = await analyzeEmail(rawEmail);
  } else {
    // Fallback minimal dossier from persisted records
    dossier = {
      caseId: caseData.case.id,
      caseNumber: caseData.case.caseNumber,
      metadata: {
        subject: primaryEmail?.subject,
        from: primaryEmail?.sender,
        to: primaryEmail?.recipient,
        date: primaryEmail?.received_at
      },
      hashes: { sha256: primaryEmail?.sha256 || 'NOT_AVAILABLE' },
      evidence: caseData.evidence || [],
      findings: caseData.findings || [],
      risk: { score: 0, level: 'LOW' }
    };
  }

  dossier.caseId = caseData.case.id;
  dossier.caseNumber = caseData.case.caseNumber;
  return { caseData, primaryEmail, dossier };
}

// Export canonical, tamper-sealed JSON dossier for a case
app.get('/api/cases/:id/export/json', async (req, res) => {
  try {
    const built = await buildCaseDossier(req.params.id);
    if (!built) {
      return res.status(404).json({ error: 'Case not found' });
    }

    const { caseData, primaryEmail, dossier } = built;
    const { certificate, exportPayload } = generateCanonicalJsonExport(dossier, {
      caseId: caseData.case.id,
      caseNumber: caseData.case.caseNumber,
      emailId: primaryEmail?.id,
      rawSha256: primaryEmail?.sha256
    });

    // Log export audit
    try {
      logReportExport(caseData.case.id, primaryEmail?.id, {
        reportUuid: certificate.certificateId.replace(/^CERT-/, ''),
        reportTitle: `Forensic Dossier Export - Case ${caseData.case.caseNumber}`,
        exportFormat: 'json',
        rawSha256: certificate.acquisition.rawSha256,
        dossierSha256: certificate.integritySeal.dossierDigest,
        metadata: { examiner: certificate.examiner, findingsCount: certificate.evidenceSummary.totalFindings }
      });
    } catch (logErr) {
      console.warn('[Reporting] Failed to log report export:', logErr.message);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${caseData.case.caseNumber}-forensic-report.json"`);
    res.json(sanitizeResponsePayload(exportPayload));
  } catch (err) {
    console.error('[Reporting] Error generating JSON export:', err);
    res.status(500).json({ error: 'Failed to generate forensic JSON export', message: err.message });
  }
});

// Export tamper-evident standalone forensic HTML report for a case
app.get('/api/cases/:id/export/html', async (req, res) => {
  try {
    const built = await buildCaseDossier(req.params.id);
    if (!built) {
      return res.status(404).json({ error: 'Case not found' });
    }

    const { caseData, primaryEmail, dossier } = built;
    const certificateObj = generateChainOfCustodyCertificate(dossier, {
      caseId: caseData.case.id,
      caseNumber: caseData.case.caseNumber,
      emailId: primaryEmail?.id,
      rawSha256: primaryEmail?.sha256
    });
    const certificate = certificateObj.certificate;

    const htmlContent = generateHtmlReport(dossier, {
      caseId: caseData.case.id,
      caseNumber: caseData.case.caseNumber,
      emailId: primaryEmail?.id,
      rawSha256: primaryEmail?.sha256
    });

    // Log export audit
    try {
      logReportExport(caseData.case.id, primaryEmail?.id, {
        reportUuid: certificate.certificateId.replace(/^CERT-/, ''),
        reportTitle: `Forensic HTML Report - Case ${caseData.case.caseNumber}`,
        exportFormat: 'html',
        rawSha256: certificate.acquisition.sha256,
        dossierSha256: certificate.dossierIntegrity.digest,
        metadata: { examiner: certificate.examiner, findingsCount: certificate.findingItemCount }
      });
    } catch (logErr) {
      console.warn('[Reporting] Failed to log report export:', logErr.message);
    }

    if (req.query.download === 'true') {
      res.setHeader('Content-Disposition', `attachment; filename="${caseData.case.caseNumber}-forensic-report.html"`);
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(htmlContent);
  } catch (err) {
    console.error('[Reporting] Error generating HTML export:', err);
    res.status(500).json({ error: 'Failed to generate forensic HTML report', message: err.message });
  }
});

// Generate and return certified HTML directly from in-memory dossier payload
app.post('/api/reports/export/html', (req, res) => {
  try {
    const { dossier, options = {} } = req.body;
    if (!dossier) {
      return res.status(400).json({ error: 'Missing dossier in request body' });
    }

    const certificate = generateChainOfCustodyCertificate(dossier, options);
    const htmlContent = generateForensicHtmlReport(dossier, certificate);

    if (dossier.caseId) {
      try {
        logReportExport(dossier.caseId, dossier.emailId || null, {
          reportUuid: certificate.certificateId.replace(/^CERT-/, ''),
          reportTitle: `Interactive Forensic Report - ${dossier.caseNumber || 'Session'}`,
          exportFormat: 'html',
          rawSha256: certificate.acquisition.rawSha256,
          dossierSha256: certificate.integritySeal.dossierDigest,
          metadata: { examiner: certificate.examiner }
        });
      } catch (e) {}
    }

    res.json({
      html: htmlContent,
      certificate
    });
  } catch (err) {
    console.error('[Reporting] Error generating HTML from dossier:', err);
    res.status(500).json({ error: 'Failed to generate HTML report', message: err.message });
  }
});

// Generate and return canonical JSON export directly from in-memory dossier payload
app.post('/api/reports/export/json', (req, res) => {
  try {
    const { dossier, options = {} } = req.body;
    if (!dossier) {
      return res.status(400).json({ error: 'Missing dossier in request body' });
    }

    const { certificate, exportPayload } = generateCanonicalJsonExport(dossier, options);

    if (dossier.caseId) {
      try {
        logReportExport(dossier.caseId, dossier.emailId || null, {
          reportUuid: certificate.certificateId.replace(/^CERT-/, ''),
          reportTitle: `Interactive Forensic Export - ${dossier.caseNumber || 'Session'}`,
          exportFormat: 'json',
          rawSha256: certificate.acquisition.rawSha256,
          dossierSha256: certificate.integritySeal.dossierDigest,
          metadata: { examiner: certificate.examiner }
        });
      } catch (e) {}
    }

    res.json(sanitizeResponsePayload(exportPayload));
  } catch (err) {
    console.error('[Reporting] Error generating JSON from dossier:', err);
    res.status(500).json({ error: 'Failed to generate JSON export', message: err.message });
  }
});

// Verify cryptographic integrity of an exported dossier or certificate
app.post('/api/reports/verify', (req, res) => {
  try {
    const result = verifyReportIntegrity(req.body);
    res.json(result);
  } catch (err) {
    console.error('[Reporting] Error verifying report:', err);
    res.status(500).json({
      status: 'VERIFICATION_ERROR',
      verified: false,
      tampered: false,
      message: 'Failed to complete verification: ' + err.message
    });
  }
});

// List audit reports for a specific case
app.get('/api/cases/:id/reports', (req, res) => {
  try {
    const caseData = getCaseById(req.params.id);
    if (!caseData) {
      return res.status(404).json({ error: 'Case not found' });
    }
    const rawReports = getReportsForCase(caseData.case.id);
    const reports = rawReports.map(r => ({
      reportUuid: r.reportUuid,
      exportFormat: r.exportFormat,
      generatedTimestamp: r.generatedAt,
      rawEmailSha256: r.rawSha256,
      dossierSha256: r.dossierSha256
    }));
    res.json({ reports });
  } catch (err) {
    console.error('[Reporting] Error listing case reports:', err);
    res.status(500).json({ error: 'Failed to retrieve case reports', message: err.message });
  }
});


function sanitizeResponsePayload(data) {
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map(sanitizeResponsePayload);

  const clean = {};
  for (const [key, value] of Object.entries(data)) {
    if (['modelUsed', 'reasoningTokens', 'provider', 'model', 'tokens', 'usage', 'prompt_tokens', 'completion_tokens', 'total_tokens', 'openrouterModel', 'internalReasoning'].includes(key)) {
      continue;
    }
    clean[key] = sanitizeResponsePayload(value);
  }
  return clean;
}

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`⚡ Email Threat Forensic & GeoLocation Server running`);
  console.log(`🚀 API Port: http://localhost:${PORT}`);
  console.log(`🛡️ AI Model: ${process.env.AI_MODEL || 'gpt-6-astra'} (ExperientialLabs)`);
  console.log(`======================================================\n`);
});
