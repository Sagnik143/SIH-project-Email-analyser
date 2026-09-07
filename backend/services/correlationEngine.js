/**
 * AegisMail Phase 5: Deterministic Correlation & Related Incidents Engine
 * 
 * Provides evidence-backed correlation across cases and emails based on shared observable indicators:
 * - Attachment SHA-256
 * - Normalized URLs
 * - Reply-To addresses
 * - Sender domains
 * - Observable relay infrastructure / IPs
 * - Suspicious domains
 * - Subject / display-name patterns
 * 
 * CORE PRINCIPLE:
 * Surfacing "POTENTIALLY RELATED" incidents based on observable telemetry.
 * NEVER claims "SAME ATTACKER", "SAME CAMPAIGN", or human physical attribution.
 */

import { getDb } from '../db/database.js';

// Common public freemail domains where domain alone should not indicate infrastructure overlap
const FREEMAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
  'aol.com', 'protonmail.com', 'mail.com', 'zoho.com', 'yandex.com'
]);

// =========================================================================
// 1. DETERMINISTIC INDICATOR NORMALIZATION
// =========================================================================

/**
 * Normalizes a URL deterministically for correlation comparison.
 * - Lowercases hostname
 * - Strips standard default ports (:80, :443)
 * - Normalizes duplicate slashes
 * - Preserves query parameters
 * Returns null if invalid URL.
 */
export function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;

  try {
    const parsed = new URL(trimmed);
    const protocol = parsed.protocol.toLowerCase();
    let hostname = parsed.hostname.toLowerCase();
    if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);

    let port = parsed.port;
    if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) {
      port = '';
    }

    const hostPart = port ? `${hostname}:${port}` : hostname;
    let pathname = parsed.pathname || '/';
    // Remove redundant multiple slashes in path
    pathname = pathname.replace(/\/+/g, '/');
    if (pathname.length > 1 && pathname.endsWith('/')) {
      pathname = pathname.slice(0, -1);
    }

    // Preserve query string intact
    const search = parsed.search || '';
    return `${protocol}//${hostPart}${pathname}${search}`;
  } catch (e) {
    // If not a full URL, attempt minimal cleanup
    return trimmed.toLowerCase().replace(/\/+$/, '');
  }
}

/**
 * Normalizes an email address.
 * Strips display names, brackets, trims, and lowercases domain and localpart.
 */
export function normalizeEmail(emailStr) {
  if (!emailStr || typeof emailStr !== 'string') return null;
  let clean = emailStr.trim();
  const match = clean.match(/<([^>]+)>/);
  if (match) {
    clean = match[1].trim();
  }
  clean = clean.toLowerCase();
  if (!clean.includes('@')) return clean;

  const parts = clean.split('@');
  const localPart = parts[0].trim();
  const domainPart = parts.slice(1).join('@').trim();
  return `${localPart}@${domainPart}`;
}

/**
 * Normalizes a domain name for comparison.
 */
export function normalizeDomain(domainStr) {
  if (!domainStr || typeof domainStr !== 'string') return null;
  let clean = domainStr.trim().toLowerCase();
  clean = clean.replace(/^[a-z]+:\/\//, '');
  clean = clean.split('/')[0].split(':')[0];
  if (clean.endsWith('.')) clean = clean.slice(0, -1);
  return clean || null;
}

/**
 * Normalizes an IP address canonical string.
 */
export function normalizeIp(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') return null;
  let clean = ipStr.trim().replace(/^\[|\]$/g, '').toLowerCase();
  // Strip IPv4-mapped IPv6 prefix ::ffff: if present
  if (clean.startsWith('::ffff:')) {
    clean = clean.replace('::ffff:', '');
  }
  return clean || null;
}

/**
 * Normalizes a hash string.
 */
export function normalizeHash(hashStr) {
  if (!hashStr || typeof hashStr !== 'string') return null;
  return hashStr.trim().toLowerCase() || null;
}

/**
 * Normalizes an email subject line for pattern comparison.
 * Strips common reply/forward and urgent prefixes.
 */
export function normalizeSubject(subjectStr) {
  if (!subjectStr || typeof subjectStr !== 'string') return '';
  let clean = subjectStr.trim().toLowerCase();
  clean = clean.replace(/^(re|fwd|fw|urgent|notice|alert):\s*/gi, '');
  clean = clean.replace(/\s+/g, ' ').trim();
  return clean;
}

// =========================================================================
// 2. FEATURE EXTRACTION FOR CORRELATION
// =========================================================================

/**
 * Extracts correlation features from an email row, its evidence, and indicators.
 */
export function extractEmailCorrelationFeatures(emailRow, evidenceRows = [], indicatorRows = []) {
  const emailId = emailRow.id;
  const caseId = emailRow.case_id;

  // 1. Raw email SHA-256
  const rawSha256 = normalizeHash(emailRow.sha256);

  // 2. Sender and Sender Domain
  const senderAddress = normalizeEmail(emailRow.sender);
  let senderDomain = null;
  if (senderAddress && senderAddress.includes('@')) {
    senderDomain = normalizeDomain(senderAddress.split('@')[1]);
  }

  // 3. Subject
  const subjectOriginal = emailRow.subject || '';
  const subjectNormalized = normalizeSubject(subjectOriginal);

  // 4. Evidence map by field for fast lookup
  const evidenceByField = new Map();
  for (const ev of evidenceRows) {
    if (!evidenceByField.has(ev.field)) {
      evidenceByField.set(ev.field, []);
    }
    evidenceByField.get(ev.field).push(ev);
  }

  // 5. Reply-To
  let replyToAddress = null;
  let replyToEvidenceId = null;
  const replyToEvList = evidenceByField.get('Reply-To') || [];
  if (replyToEvList.length > 0) {
    replyToAddress = normalizeEmail(replyToEvList[0].value);
    replyToEvidenceId = replyToEvList[0].evidence_key || replyToEvList[0].id;
  }

  // 6. Attachment SHA-256 hashes
  const attachments = [];
  const attachmentEvList = evidenceByField.get('attachment') || [];
  for (const ev of attachmentEvList) {
    let details = {};
    try { details = JSON.parse(ev.details || '{}'); } catch (e) {}
    if (details.sha256) {
      attachments.push({
        sha256: normalizeHash(details.sha256),
        filename: ev.value,
        evidenceId: ev.evidence_key || ev.id
      });
    }
  }

  // Also check indicators table for attachments
  for (const ind of indicatorRows) {
    if (ind.type === 'attachment') {
      let details = {};
      try { details = JSON.parse(ind.details || '{}'); } catch (e) {}
      if (details.sha256) {
        const hash = normalizeHash(details.sha256);
        if (!attachments.some(a => a.sha256 === hash)) {
          attachments.push({
            sha256: hash,
            filename: ind.value,
            evidenceId: null
          });
        }
      }
    }
  }

  // 7. URLs
  const urls = [];
  const urlEvList = evidenceByField.get('url') || [];
  for (const ev of urlEvList) {
    let details = {};
    try { details = JSON.parse(ev.details || '{}'); } catch (e) {}
    const original = details.original || ev.value;
    const normalized = normalizeUrl(original);
    if (normalized) {
      urls.push({
        original,
        normalized,
        evidenceId: ev.evidence_key || ev.id,
        isSuspicious: Boolean(details.isSuspicious)
      });
    }
  }

  // Also check indicators table for URLs
  for (const ind of indicatorRows) {
    if (ind.type === 'url') {
      const normalized = normalizeUrl(ind.value);
      if (normalized && !urls.some(u => u.normalized === normalized)) {
        urls.push({
          original: ind.value,
          normalized,
          evidenceId: null,
          isSuspicious: Boolean(ind.is_suspicious)
        });
      }
    }
  }

  // 8. Observable Relay IPs
  const relayIps = [];
  const receivedEvList = evidenceByField.get('Received') || [];
  for (const ev of receivedEvList) {
    let details = {};
    try { details = JSON.parse(ev.details || '{}'); } catch (e) {}
    if (details.ip && !details.isPrivate) {
      const normalized = normalizeIp(details.ip);
      if (normalized && !relayIps.some(r => r.ip === normalized)) {
        relayIps.push({
          ip: normalized,
          evidenceId: ev.evidence_key || ev.id
        });
      }
    }
  }

  return {
    emailId,
    caseId,
    filename: emailRow.filename || 'email.eml',
    rawSha256,
    sender: emailRow.sender,
    senderAddress,
    senderDomain,
    subject: subjectOriginal,
    subjectNormalized,
    replyToAddress,
    replyToEvidenceId,
    attachments,
    urls,
    relayIps
  };
}

// =========================================================================
// 3. PAIRWISE COMPARISON & EXPLAINABLE SCORING
// =========================================================================

/**
 * Compares two extracted email feature sets and calculates an explainable correlation score.
 * Enforces minimum threshold of 20 to declare a relationship.
 */
export function compareEmailFeatures(a, b) {
  if (a.emailId === b.emailId) {
    return null; // Self-comparison prohibited
  }

  let score = 0;
  const reasons = [];
  const sharedIndicators = [];

  // 1. Identical Raw Email Cryptographic Hash (Same exact email uploaded into multiple cases)
  if (a.rawSha256 && b.rawSha256 && a.rawSha256 === b.rawSha256) {
    score += 50;
    reasons.push({
      signal: 'identical_raw_email_hash',
      description: `Identical raw email cryptographic hash (SHA-256: ${a.rawSha256.slice(0, 16)}...) observed`
    });
    sharedIndicators.push({
      type: 'email_sha256',
      value: a.rawSha256,
      sourceEvidenceId: null,
      targetEvidenceId: null
    });
  }

  // 2. Same Attachment SHA-256 (+50)
  for (const attA of a.attachments) {
    for (const attB of b.attachments) {
      if (attA.sha256 && attB.sha256 && attA.sha256 === attB.sha256) {
        score += 50;
        reasons.push({
          signal: 'attachment_sha256',
          description: `Same attachment SHA-256 observed (${attA.sha256.slice(0, 16)}...) in "${attA.filename}" and "${attB.filename}"`
        });
        sharedIndicators.push({
          type: 'attachment_sha256',
          value: attA.sha256,
          sourceEvidenceId: attA.evidenceId,
          targetEvidenceId: attB.evidenceId,
          filenames: { source: attA.filename, target: attB.filename }
        });
        break; // Count once per unique matched attachment
      }
    }
  }

  // 3. Same Normalized URL (+40)
  for (const urlA of a.urls) {
    for (const urlB of b.urls) {
      if (urlA.normalized && urlB.normalized && urlA.normalized === urlB.normalized) {
        score += 40;
        reasons.push({
          signal: 'normalized_url',
          description: `Same normalized URL observed: ${urlA.normalized}`
        });
        sharedIndicators.push({
          type: 'normalized_url',
          value: urlA.normalized,
          sourceEvidenceId: urlA.evidenceId,
          targetEvidenceId: urlB.evidenceId
        });
        break; // Count once per matched URL
      }
    }
  }

  // 4. Same Reply-To Address (+30)
  if (a.replyToAddress && b.replyToAddress && a.replyToAddress === b.replyToAddress) {
    score += 30;
    reasons.push({
      signal: 'reply_to',
      description: `Same Reply-To address observed: ${a.replyToAddress}`
    });
    sharedIndicators.push({
      type: 'reply_to',
      value: a.replyToAddress,
      sourceEvidenceId: a.replyToEvidenceId,
      targetEvidenceId: b.replyToEvidenceId
    });
  }

  // 5. Same Sender Domain (+15) (only if not a generic freemail provider)
  if (a.senderDomain && b.senderDomain && a.senderDomain === b.senderDomain) {
    if (!FREEMAIL_DOMAINS.has(a.senderDomain)) {
      score += 15;
      reasons.push({
        signal: 'sender_domain',
        description: `Same custom sender domain observed: ${a.senderDomain}`
      });
      sharedIndicators.push({
        type: 'sender_domain',
        value: a.senderDomain,
        sourceEvidenceId: null,
        targetEvidenceId: null
      });
    }
  }

  // 6. Same Observable Relay Infrastructure IP (+15)
  for (const ipA of a.relayIps) {
    for (const ipB of b.relayIps) {
      if (ipA.ip && ipB.ip && ipA.ip === ipB.ip) {
        score += 15;
        reasons.push({
          signal: 'relay_infrastructure',
          description: `Same observable sending infrastructure IP observed: ${ipA.ip}`
        });
        sharedIndicators.push({
          type: 'relay_ip',
          value: ipA.ip,
          sourceEvidenceId: ipA.evidenceId,
          targetEvidenceId: ipB.evidenceId
        });
        break;
      }
    }
  }

  // 7. Same Subject Pattern (+5)
  if (a.subjectNormalized && b.subjectNormalized && a.subjectNormalized.length >= 8 && a.subjectNormalized === b.subjectNormalized) {
    score += 5;
    reasons.push({
      signal: 'subject_pattern',
      description: `Identical subject pattern observed: "${a.subjectNormalized}"`
    });
  }

  // Normalize score between 0 and 100
  const correlationScore = Math.min(100, Math.max(0, score));

  // Minimum threshold check: weak signals alone (e.g. subject alone = 5, sender domain alone = 15)
  // are NOT sufficient to declare incidents related. Requires score >= 20.
  if (correlationScore < 20) {
    return null;
  }

  return {
    sourceEmailId: a.emailId,
    targetEmailId: b.emailId,
    sourceCaseId: a.caseId,
    targetCaseId: b.caseId,
    correlationScore,
    relationship: 'potentially_related',
    reasons,
    sharedIndicators,
    limitations: [
      'Shared observable indicators do not establish common authorship, attacker identity, or a coordinated campaign.',
      'Correlation is an investigative heuristic requiring independent analyst review.'
    ]
  };
}

// =========================================================================
// 4. ORCHESTRATION & DISCOVERY
// =========================================================================

/**
 * Retrieves full feature sets for all emails in the database.
 */
export function loadAllEmailFeatures(db) {
  const emails = db.prepare(`SELECT * FROM emails ORDER BY id ASC`).all();
  const allEvidence = db.prepare(`SELECT * FROM evidence ORDER BY id ASC`).all();
  const allIndicators = db.prepare(`SELECT * FROM indicators ORDER BY id ASC`).all();

  const evidenceByEmail = new Map();
  for (const ev of allEvidence) {
    if (!evidenceByEmail.has(ev.email_id)) evidenceByEmail.set(ev.email_id, []);
    evidenceByEmail.get(ev.email_id).push(ev);
  }

  const indicatorsByEmail = new Map();
  for (const ind of allIndicators) {
    if (!indicatorsByEmail.has(ind.email_id)) indicatorsByEmail.set(ind.email_id, []);
    indicatorsByEmail.get(ind.email_id).push(ind);
  }

  return emails.map(emailRow => {
    const evs = evidenceByEmail.get(emailRow.id) || [];
    const inds = indicatorsByEmail.get(emailRow.id) || [];
    return extractEmailCorrelationFeatures(emailRow, evs, inds);
  });
}

/**
 * Persists or updates a canonical related incident pair in the database.
 * Enforces canonical ordering min(source, target) to prevent duplicate A-B / B-A rows.
 */
export function persistRelatedIncident(db, correlation) {
  const id1 = Math.min(correlation.sourceEmailId, correlation.targetEmailId);
  const id2 = Math.max(correlation.sourceEmailId, correlation.targetEmailId);
  const case1 = correlation.sourceEmailId === id1 ? correlation.sourceCaseId : correlation.targetCaseId;
  const case2 = correlation.sourceEmailId === id1 ? correlation.targetCaseId : correlation.sourceCaseId;

  const now = new Date().toISOString();
  const reasonsJson = JSON.stringify(correlation.reasons);
  const indicatorsJson = JSON.stringify(correlation.sharedIndicators);

  const stmt = db.prepare(`
    INSERT INTO related_incidents (
      source_email_id, target_email_id, source_case_id, target_case_id,
      correlation_score, relationship_type, reasons, shared_indicators, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(min(source_email_id, target_email_id), max(source_email_id, target_email_id))
    DO UPDATE SET
      correlation_score = excluded.correlation_score,
      reasons = excluded.reasons,
      shared_indicators = excluded.shared_indicators
  `);

  stmt.run(id1, id2, case1, case2, correlation.correlationScore, correlation.relationship, reasonsJson, indicatorsJson, now);
}

/**
 * Finds all potentially related incidents for a specific email.
 */
export function findRelatedEmails(emailId) {
  const db = getDb();
  const numId = parseInt(emailId, 10);
  if (isNaN(numId)) throw new Error('Invalid email ID');

  const allFeatures = loadAllEmailFeatures(db);
  const targetEmail = allFeatures.find(f => f.emailId === numId);
  if (!targetEmail) return { results: [], emailId: numId, totalRelated: 0 };

  const casesMap = new Map(db.prepare(`SELECT id, case_number, title FROM cases`).all().map(c => [c.id, c]));
  const results = [];

  for (const candidate of allFeatures) {
    if (candidate.emailId === numId) continue;
    const comparison = compareEmailFeatures(targetEmail, candidate);
    if (comparison) {
      persistRelatedIncident(db, comparison);

      const relatedCase = casesMap.get(candidate.caseId) || { id: candidate.caseId, caseNumber: `CASE-${candidate.caseId}`, title: 'Investigation Case' };
      results.push({
        case: {
          id: relatedCase.id,
          caseNumber: relatedCase.case_number,
          title: relatedCase.title
        },
        email: {
          id: candidate.emailId,
          filename: candidate.filename
        },
        correlationScore: comparison.correlationScore,
        relationship: comparison.relationship,
        reasons: comparison.reasons,
        sharedIndicators: comparison.sharedIndicators,
        limitations: comparison.limitations
      });
    }
  }

  // Sort descending by correlation score
  results.sort((a, b) => b.correlationScore - a.correlationScore);

  return {
    emailId: numId,
    results,
    totalRelated: results.length
  };
}

/**
 * Finds all potentially related incidents for a specific case.
 * Compares all emails in the requested case against all other emails across the database.
 */
export function findRelatedCases(caseIdOrNumber) {
  const db = getDb();

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
    throw new Error(`Case '${caseIdOrNumber}' not found.`);
  }

  const caseId = caseRow.id;
  const allFeatures = loadAllEmailFeatures(db);
  const caseEmails = allFeatures.filter(f => f.caseId === caseId);

  if (caseEmails.length === 0) {
    return {
      case: { id: caseRow.id, caseNumber: caseRow.case_number, title: caseRow.title },
      results: [],
      totalRelated: 0
    };
  }

  const casesMap = new Map(db.prepare(`SELECT id, case_number, title FROM cases`).all().map(c => [c.id, c]));
  const seenPairKeys = new Set();
  const results = [];

  for (const sourceEmail of caseEmails) {
    for (const candidate of allFeatures) {
      if (candidate.emailId === sourceEmail.emailId) continue;

      const comparison = compareEmailFeatures(sourceEmail, candidate);
      if (comparison) {
        persistRelatedIncident(db, comparison);

        const pairKey = `${Math.min(sourceEmail.emailId, candidate.emailId)}-${Math.max(sourceEmail.emailId, candidate.emailId)}`;
        if (seenPairKeys.has(pairKey)) continue;
        seenPairKeys.add(pairKey);

        const relatedCase = casesMap.get(candidate.caseId) || { id: candidate.caseId, caseNumber: `CASE-${candidate.caseId}`, title: 'Investigation Case' };
        results.push({
          case: {
            id: relatedCase.id,
            caseNumber: relatedCase.case_number,
            title: relatedCase.title
          },
          email: {
            id: candidate.emailId,
            filename: candidate.filename
          },
          sourceEmail: {
            id: sourceEmail.emailId,
            filename: sourceEmail.filename
          },
          correlationScore: comparison.correlationScore,
          relationship: comparison.relationship,
          reasons: comparison.reasons,
          sharedIndicators: comparison.sharedIndicators,
          limitations: comparison.limitations
        });
      }
    }
  }

  // Sort descending by score
  results.sort((a, b) => b.correlationScore - a.correlationScore);

  return {
    case: {
      id: caseRow.id,
      caseNumber: caseRow.case_number,
      title: caseRow.title
    },
    results,
    totalRelated: results.length
  };
}
