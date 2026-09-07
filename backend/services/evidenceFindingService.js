/**
 * Evidence & Finding Architecture Service (Phase 2)
 *
 * Implements a deterministic, evidence-backed forensic data contract:
 * Evidence -> Finding -> Limitation -> Recommendation
 *
 * Rules:
 * 1. Every finding must reference at least one real, registered evidence ID.
 * 2. Deterministic analysis creates findings; evidence supports findings.
 * 3. AI must never invent findings or evidence.
 * 4. Severity values are strictly normalized: 'low' | 'medium' | 'high' | 'critical'.
 * 5. Phase 1 defensible trust terminology is strictly preserved.
 */

const ALLOWED_SOURCES = new Set([
  'raw_header',
  'raw_body',
  'authentication_result',
  'relay_observation',
  'url',
  'attachment',
  'domain',
  'ip',
  'enrichment',
  'system_observation'
]);

const ALLOWED_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

/**
 * Creates an Evidence and Finding Collector for a single analysis run.
 * Guarantees stable IDs (E-001, E-002..., F-001, F-002...) and strict validation.
 */
export function createEvidenceFindingCollector(options = {}) {
  const collectionTimestamp = options.timestamp || new Date().toISOString();
  let evidenceCounter = 0;
  let findingCounter = 0;

  const evidenceList = [];
  const evidenceMap = new Map(); // id -> evidence
  const evidenceKeyIndex = new Map(); // deduplication key -> evidence

  const findingsList = [];
  const findingKeyIndex = new Map(); // deduplication key -> finding

  /**
   * Registers a piece of evidence.
   * If identical evidence (source + field + value) is already registered, returns existing evidence.
   */
  function addEvidence({
    source,
    field,
    value,
    collectionMethod = 'uploaded_eml',
    details = {}
  }) {
    if (!source || !field || value === undefined || value === null) {
      throw new Error(`Invalid evidence registration: source, field, and value are required.`);
    }

    const normalizedSource = ALLOWED_SOURCES.has(source) ? source : 'system_observation';
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);

    // Deduplicate identical evidence items within the analysis
    const dedupKey = `${normalizedSource}::${field}::${stringValue}`;
    if (evidenceKeyIndex.has(dedupKey)) {
      return evidenceKeyIndex.get(dedupKey);
    }

    evidenceCounter += 1;
    const padCounter = String(evidenceCounter).padStart(3, '0');
    const id = `E-${padCounter}`;

    const evidenceItem = {
      id,
      source: normalizedSource,
      field,
      value: stringValue,
      collectionMethod,
      collectedAt: collectionTimestamp,
      details: typeof details === 'object' && details !== null ? details : {}
    };

    evidenceList.push(evidenceItem);
    evidenceMap.set(id, evidenceItem);
    evidenceKeyIndex.set(dedupKey, evidenceItem);

    return evidenceItem;
  }

  /**
   * Registers a forensic finding backed by one or more evidence IDs.
   * Validates evidence references and enforces normalized severities.
   */
  function addFinding({
    type,
    severity,
    title,
    summary,
    evidenceIds = [],
    limitations = [],
    recommendedAction = ''
  }) {
    if (!type || !title || !summary) {
      console.warn('[EvidenceEngine] Skipped finding missing required metadata (type, title, or summary).');
      return null;
    }

    // Enforce Rule: A finding must have at least one valid evidence reference
    if (!Array.isArray(evidenceIds) || evidenceIds.length === 0) {
      console.warn(`[EvidenceEngine] Finding '${type}' rejected: No supporting evidence IDs provided.`);
      return null;
    }

    // Validate that all referenced evidence IDs actually exist in this collector
    const validEvidenceIds = evidenceIds.filter(eId => evidenceMap.has(eId));
    if (validEvidenceIds.length === 0) {
      console.warn(`[EvidenceEngine] Finding '${type}' rejected: None of the referenced evidence IDs [${evidenceIds.join(', ')}] exist.`);
      return null;
    }

    // Normalize severity to one of: low | medium | high | critical
    let normalizedSeverity = (severity || 'medium').toLowerCase();
    if (!ALLOWED_SEVERITIES.has(normalizedSeverity)) {
      normalizedSeverity = 'medium';
    }

    // Deduplication key: type + sorted unique evidence IDs
    const sortedEvIds = [...new Set(validEvidenceIds)].sort();
    const dedupKey = `${type}::${sortedEvIds.join('+')}`;

    if (findingKeyIndex.has(dedupKey)) {
      // Finding for this exact condition and evidence already recorded; merge limitations if new
      const existing = findingKeyIndex.get(dedupKey);
      if (Array.isArray(limitations)) {
        for (const lim of limitations) {
          if (!existing.limitations.includes(lim)) {
            existing.limitations.push(lim);
          }
        }
      }
      return existing;
    }

    findingCounter += 1;
    const padCounter = String(findingCounter).padStart(3, '0');
    const id = `F-${padCounter}`;

    const normalizedLimitations = Array.isArray(limitations) && limitations.length > 0
      ? [...limitations]
      : ['Heuristic observation based on uploaded email headers; verify out-of-band before taking irreversible action.'];

    const findingItem = {
      id,
      type,
      severity: normalizedSeverity,
      title,
      summary,
      evidenceIds: sortedEvIds,
      limitations: normalizedLimitations,
      recommendedAction: recommendedAction || 'Review supporting headers and verify authenticity out-of-band.'
    };

    findingsList.push(findingItem);
    findingKeyIndex.set(dedupKey, findingItem);

    return findingItem;
  }

  /**
   * Finalizes and builds the structured evidence and findings contract.
   * Performs a final validation pass to guarantee no orphaned or evidence-less findings.
   */
  function build() {
    // Final verification of evidence and findings integrity
    const verifiedFindings = findingsList.filter(f => {
      if (!f.evidenceIds || f.evidenceIds.length === 0) return false;
      return f.evidenceIds.every(id => evidenceMap.has(id));
    });

    return {
      evidence: evidenceList,
      findings: verifiedFindings,
      stats: {
        totalEvidence: evidenceList.length,
        totalFindings: verifiedFindings.length,
        criticalFindings: verifiedFindings.filter(f => f.severity === 'critical').length,
        highFindings: verifiedFindings.filter(f => f.severity === 'high').length,
        mediumFindings: verifiedFindings.filter(f => f.severity === 'medium').length,
        lowFindings: verifiedFindings.filter(f => f.severity === 'low').length
      }
    };
  }

  return {
    addEvidence,
    addFinding,
    getEvidence: (id) => evidenceMap.get(id),
    build
  };
}

/**
 * Deterministically analyzes parsed email telemetry and generates structured Evidence & Findings.
 *
 * Connects:
 * - Reply-To & Return-Path alignment
 * - Display name & authority spoofing
 * - Lookalike domain / typosquatting
 * - SPF / DKIM / DMARC reported authentication
 * - Extracted URLs & deceptive anchors
 * - Attachment extensions and cryptographic hashes
 * - Transmission relay hops & timing inconsistencies
 * - Claimed Origin (UNVERIFIED)
 */
export function generateForensicFindings(parsedEmail, relayAnalysis, authData, iocData, originGeo) {
  const collector = createEvidenceFindingCollector({
    timestamp: parsedEmail?.integrity?.analyzedAt || new Date().toISOString()
  });

  const headers = parsedEmail?.headers || {};
  const envelope = parsedEmail?.envelope || {};

  // -------------------------------------------------------------
  // 1. BASELINE HEADER EVIDENCE
  // -------------------------------------------------------------
  const fromHeader = headers['from']?.[0] || envelope.from?.raw || '';
  let fromEv = null;
  if (fromHeader) {
    fromEv = collector.addEvidence({
      source: 'raw_header',
      field: 'From',
      value: fromHeader,
      collectionMethod: 'header_parsing',
      details: {
        name: envelope.from?.name || '',
        address: envelope.from?.address || '',
        domain: envelope.from?.domain || ''
      }
    });
  }

  const replyToHeader = headers['reply-to']?.[0] || envelope.replyTo?.raw || '';
  let replyToEv = null;
  if (replyToHeader) {
    replyToEv = collector.addEvidence({
      source: 'raw_header',
      field: 'Reply-To',
      value: replyToHeader,
      collectionMethod: 'header_parsing',
      details: {
        name: envelope.replyTo?.name || '',
        address: envelope.replyTo?.address || '',
        domain: envelope.replyTo?.domain || ''
      }
    });
  }

  const returnPathHeader = headers['return-path']?.[0] || envelope.returnPath || '';
  let returnPathEv = null;
  if (returnPathHeader) {
    returnPathEv = collector.addEvidence({
      source: 'raw_header',
      field: 'Return-Path',
      value: returnPathHeader,
      collectionMethod: 'header_parsing',
      details: {
        address: envelope.returnPath || ''
      }
    });
  }

  const subjectHeader = headers['subject']?.[0] || envelope.subject || '';
  if (subjectHeader) {
    collector.addEvidence({
      source: 'raw_header',
      field: 'Subject',
      value: subjectHeader,
      collectionMethod: 'header_parsing'
    });
  }

  const messageIdHeader = headers['message-id']?.[0] || envelope.messageId || '';
  if (messageIdHeader) {
    collector.addEvidence({
      source: 'raw_header',
      field: 'Message-ID',
      value: messageIdHeader,
      collectionMethod: 'header_parsing'
    });
  }

  // -------------------------------------------------------------
  // 2. REPLY-TO & HEADER ALIGNMENT FINDINGS
  // -------------------------------------------------------------
  const alignment = authData?.alignmentAnalysis;
  if (alignment?.hasReplyToDiscrepancy && fromEv && replyToEv) {
    collector.addFinding({
      type: 'reply_to_mismatch',
      severity: 'medium',
      title: 'Reply-To Address Redirection Discrepancy',
      summary: `Replies will be routed to "${envelope.replyTo?.address || replyToHeader}" instead of visible sender domain "@${alignment.fromDomain}".`,
      evidenceIds: [fromEv.id, replyToEv.id],
      limitations: [
        'Legitimate newsletters, mailing lists, and enterprise helpdesk systems frequently use separate Reply-To routing.',
        'A Reply-To discrepancy alone is not definitive proof of malice without corroborating social engineering or spoofing indicators.'
      ],
      recommendedAction: 'Verify the reply destination out-of-band before communicating sensitive credentials, wire details, or proprietary files.'
    });
  }

  if (alignment?.hasReturnPathDiscrepancy && fromEv && returnPathEv) {
    collector.addFinding({
      type: 'return_path_mismatch',
      severity: 'low',
      title: 'Return-Path / Envelope Sender Mismatch',
      summary: `The technical return envelope is "@${alignment.returnPathDomain}", which differs from the visible sender domain "@${alignment.fromDomain}".`,
      evidenceIds: [fromEv.id, returnPathEv.id],
      limitations: [
        'Authorized third-party Email Service Providers (ESPs) such as SendGrid, Mailgun, and Salesforce regularly use distinct Return-Path domains.'
      ],
      recommendedAction: 'Check SPF and DKIM alignment to determine if the sending service is authorized by the domain owner.'
    });
  }

  // -------------------------------------------------------------
  // 3. DISPLAY NAME SPOOFING & IMPERSONATION FINDINGS
  // -------------------------------------------------------------
  const displayNameAnalysis = authData?.displayNameAnalysis;
  if (displayNameAnalysis?.isSpoofed && fromEv) {
    const flagsSummary = (displayNameAnalysis.flags || []).join('; ');
    collector.addFinding({
      type: 'display_name_spoofing',
      severity: 'high',
      title: 'Display Name Impersonation / Spoofing Detected',
      summary: `The sender display name "${displayNameAnalysis.displayName}" employs deceptive framing: ${flagsSummary}.`,
      evidenceIds: [fromEv.id],
      limitations: [
        'Display names are arbitrary text strings configured by the sender client and are not validated by the SMTP protocol.',
        'Users occasionally use informal executive-style titles or nicknames on personal consumer webmail accounts.'
      ],
      recommendedAction: 'Examine the actual RFC 5322 From mailbox address rather than trusting the human-readable display name.'
    });
  }

  // -------------------------------------------------------------
  // 4. LOOKALIKE DOMAIN / TYPOSQUATTING FINDINGS
  // -------------------------------------------------------------
  const domainAnalysis = authData?.domainAnalysis;
  if (domainAnalysis?.isLookalike && fromEv) {
    const domainEv = collector.addEvidence({
      source: 'domain',
      field: 'sender_domain',
      value: domainAnalysis.senderDomain,
      collectionMethod: 'system_observation',
      details: {
        targetBrand: domainAnalysis.targetBrand,
        flags: domainAnalysis.flags
      }
    });

    collector.addFinding({
      type: 'lookalike_domain',
      severity: 'high',
      title: `Lookalike / Typosquatting Domain (${domainAnalysis.targetBrand || 'Brand Imitation'})`,
      summary: `The domain "${domainAnalysis.senderDomain}" visually imitates legitimate brand "${domainAnalysis.targetBrand}". Flags: ${(domainAnalysis.flags || []).join('; ')}.`,
      evidenceIds: [fromEv.id, domainEv.id],
      limitations: [
        'Algorithmic similarity scores detect typographical proximity; organizations sometimes register defensive or regional lookalike domains.',
        'Whois registration and DNS telemetry must be checked independently to establish ownership.'
      ],
      recommendedAction: 'Do not click links or respond to messages originating from this domain; add domain to perimeter blocklist.'
    });
  }

  // -------------------------------------------------------------
  // 5. SENDER AUTHENTICATION (SPF / DKIM / DMARC) EVIDENCE & FINDINGS
  // -------------------------------------------------------------
  const authResultsHeader = headers['authentication-results']?.[0] || '';
  const receivedSpfHeader = headers['received-spf']?.[0] || '';

  let authHeaderEv = null;
  if (authResultsHeader || receivedSpfHeader) {
    authHeaderEv = collector.addEvidence({
      source: 'raw_header',
      field: 'Authentication-Results',
      value: authResultsHeader || receivedSpfHeader,
      collectionMethod: 'header_parsing',
      details: {
        receivedSpf: receivedSpfHeader
      }
    });
  }

  const spf = authData?.spf;
  if (spf && (spf.status === 'FAIL' || spf.status === 'SOFTFAIL')) {
    const spfEv = collector.addEvidence({
      source: 'authentication_result',
      field: 'SPF',
      value: spf.status,
      collectionMethod: 'header_parsing',
      details: { details: spf.details, source: spf.source }
    });

    const evIds = [spfEv.id];
    if (authHeaderEv) evIds.push(authHeaderEv.id);
    if (fromEv) evIds.push(fromEv.id);

    collector.addFinding({
      type: 'spf_validation_failure',
      severity: spf.status === 'FAIL' ? 'high' : 'medium',
      title: `Reported SPF Validation ${spf.status}`,
      summary: `Intermediate receiving MTA reported SPF ${spf.status}: ${spf.details}.`,
      evidenceIds: evIds,
      limitations: [
        'Results reflect claims reported inside uploaded message headers by an intermediate receiving mail server, not live DNS queries.',
        'Forwarding or indirect mail relays frequently break SPF validation unless SRS (Sender Rewriting Scheme) is active.'
      ],
      recommendedAction: 'Verify sending IP against the publishing domain SPF record in DNS.'
    });
  }

  const dkim = authData?.dkim;
  if (dkim && dkim.status === 'FAIL') {
    const dkimEv = collector.addEvidence({
      source: 'authentication_result',
      field: 'DKIM',
      value: dkim.status,
      collectionMethod: 'header_parsing',
      details: { details: dkim.details, source: dkim.source }
    });

    const evIds = [dkimEv.id];
    if (authHeaderEv) evIds.push(authHeaderEv.id);
    if (fromEv) evIds.push(fromEv.id);

    collector.addFinding({
      type: 'dkim_validation_failure',
      severity: 'high',
      title: 'Reported DKIM Signature Failure',
      summary: `Intermediate receiving mail server reported DKIM signature verification failure: ${dkim.details}.`,
      evidenceIds: evIds,
      limitations: [
        'Results reflect claims reported inside uploaded message headers by an intermediate receiving mail server, not live cryptographic verification by AegisMail.',
        'MTA line wrapping, footer injection, or content reformatting in transit can invalidate an otherwise legitimate cryptographic signature.'
      ],
      recommendedAction: 'Check DKIM selector and verify whether message body or headers were modified in transit.'
    });
  }

  const dmarc = authData?.dmarc;
  if (dmarc && dmarc.status === 'FAIL') {
    const dmarcEv = collector.addEvidence({
      source: 'authentication_result',
      field: 'DMARC',
      value: dmarc.status,
      collectionMethod: 'header_parsing',
      details: { details: dmarc.details, source: dmarc.source }
    });

    const evIds = [dmarcEv.id];
    if (authHeaderEv) evIds.push(authHeaderEv.id);
    if (fromEv) evIds.push(fromEv.id);

    collector.addFinding({
      type: 'dmarc_policy_violation',
      severity: 'high',
      title: 'Reported DMARC Policy Violation',
      summary: `Intermediate receiving mail server reported DMARC policy failure: ${dmarc.details}.`,
      evidenceIds: evIds,
      limitations: [
        'Results reflect claims reported inside uploaded message headers by an intermediate receiving mail server, not live DNS policy queries.',
        'DMARC evaluation depends upon SPF and DKIM identifier alignment.'
      ],
      recommendedAction: 'Inspect domain DMARC policy (p=reject, p=quarantine, or p=none) in authoritative DNS.'
    });
  }

  // -------------------------------------------------------------
  // 6. INDICATORS OF COMPROMISE (URLs & ATTACHMENTS)
  // -------------------------------------------------------------
  const urls = iocData?.urls || [];
  for (const urlItem of urls) {
    if (urlItem.isSuspicious) {
      const urlEv = collector.addEvidence({
        source: 'url',
        field: 'extracted_url',
        value: urlItem.original,
        collectionMethod: 'body_extraction',
        details: {
          defanged: urlItem.defanged,
          hostname: urlItem.hostname,
          flags: urlItem.flags
        }
      });

      const evIds = [urlEv.id];
      collector.addFinding({
        type: 'suspicious_url',
        severity: urlItem.isIpHost ? 'high' : 'medium',
        title: 'Suspicious / High-Risk URL in Message Body',
        summary: `URL "${urlItem.defanged}" contains known threat indicators: ${(urlItem.flags || []).join('; ')}.`,
        evidenceIds: evIds,
        limitations: [
          'URL heuristics evaluate structural patterns, direct IPs, and untrusted TLDs; web categorization feeds may occasionally flag newly registered legitimate domains.',
          'Dynamic sandbox detonation is required to confirm whether the landing page currently hosts active malware or credential phishing.'
        ],
        recommendedAction: 'Do not click or navigate directly to this URL. Submit to isolated threat intelligence sandbox for behavioral inspection.'
      });
    }
  }

  const attachments = iocData?.attachments || [];
  for (const att of attachments) {
    const attEv = collector.addEvidence({
      source: 'attachment',
      field: 'attachment_file',
      value: att.filename,
      collectionMethod: 'uploaded_eml',
      details: {
        contentType: att.contentType,
        size: att.size,
        sha256: att.sha256,
        md5: att.md5,
        extension: att.extension,
        isDangerous: att.isDangerous
      }
    });

    if (att.isDangerous) {
      collector.addFinding({
        type: 'dangerous_attachment',
        severity: 'critical',
        title: `Weaponized / Executable Attachment Detected (${att.filename})`,
        summary: `Attachment "${att.filename}" has dangerous file type (.${att.extension}) frequently used for malware delivery. SHA-256: ${att.sha256}.`,
        evidenceIds: [attEv.id],
        limitations: [
          'File extension and hash analysis provide static identification; legitimate IT administration scripts or password-protected archives may share similar extensions.',
          'Dynamic behavioral detonation in an isolated sandbox is required to determine payload capability.'
        ],
        recommendedAction: 'Quarantine attachment immediately. Do not execute or decompress in standard workstation environment.'
      });
    }
  }

  // -------------------------------------------------------------
  // 7. TRANSMISSION RELAY HOPS & TIMING INCONSISTENCIES
  // -------------------------------------------------------------
  const hops = relayAnalysis?.hops || [];
  const hopEvidenceMap = new Map(); // hopNumber -> evidence

  for (const hop of hops) {
    const hopEv = collector.addEvidence({
      source: 'relay_observation',
      field: 'Received',
      value: `${hop.fromHost || 'unknown'} -> ${hop.byHost || 'unknown'} [${hop.ip || 'no-ip'}]`,
      collectionMethod: 'header_parsing',
      details: {
        hopNumber: hop.hopNumber,
        ip: hop.ip,
        isPrivate: hop.isPrivate,
        transitDelaySeconds: hop.transitDelaySeconds,
        city: hop.geo?.city || 'Unknown',
        country: hop.geo?.country || 'Unknown'
      }
    });
    hopEvidenceMap.set(hop.hopNumber, hopEv);
  }

  const hopAnomalies = relayAnalysis?.hopAnomalies || [];
  for (const anomaly of hopAnomalies) {
    const prevEv = hopEvidenceMap.get(anomaly.fromHop);
    const currEv = hopEvidenceMap.get(anomaly.toHop);

    const evIds = [];
    if (prevEv) evIds.push(prevEv.id);
    if (currEv) evIds.push(currEv.id);

    if (evIds.length > 0) {
      collector.addFinding({
        type: 'relay_routing_inconsistency',
        severity: 'medium',
        title: 'Multi-Hop Relay Timing / Routing Inconsistency',
        summary: anomaly.alert || `Inconsistency observed between Hop ${anomaly.fromHop} and Hop ${anomaly.toHop} with recorded delay ${anomaly.delaySeconds}s.`,
        evidenceIds: evIds,
        limitations: [
          'Transit calculations rely on timestamps recorded by independent intermediate mail transfer agents; system clock skew or unsynchronized NTP can produce artificial timing deltas.',
          'Geographic distances reflect server infrastructure routing rather than physical travel of the sender.'
        ],
        recommendedAction: 'Inspect full Received: headers chronologically and verify cryptographic TLS handshakes where available.'
      });
    }
  }

  // -------------------------------------------------------------
  // 8. UNVERIFIED CLAIMED ORIGIN (X-Originating-IP)
  // -------------------------------------------------------------
  const xOriginatingIP = headers['x-originating-ip']?.[0] ||
                         headers['x-sender-ip']?.[0] ||
                         headers['x-client-ip']?.[0];

  if (xOriginatingIP) {
    const xIpEv = collector.addEvidence({
      source: 'raw_header',
      field: 'X-Originating-IP',
      value: xOriginatingIP,
      collectionMethod: 'header_parsing',
      details: {
        status: 'UNVERIFIED',
        label: 'Claimed Earlier Origin (UNVERIFIED)'
      }
    });

    collector.addFinding({
      type: 'unverified_claimed_origin',
      severity: 'low',
      title: 'Claimed Earlier Origin Header Present (UNVERIFIED)',
      summary: `The email contains an unauthenticated origin assertion: "${xOriginatingIP}". This is labeled UNVERIFIED.`,
      evidenceIds: [xIpEv.id],
      limitations: [
        'X-Originating-IP headers can be freely fabricated, spoofed, or altered by the sender MUA or untrusted intermediate relays.',
        'This header is unauthenticated and does not establish verified sender attribution or identity.'
      ],
      recommendedAction: 'Rely primarily on the earliest public hop in the authenticated Received: relay chain rather than synthetic headers.'
    });
  }

  // -------------------------------------------------------------
  // 9. CLEAN / BASELINE OBSERVATION (If no suspicious findings)
  // -------------------------------------------------------------
  const currentBuild = collector.build();
  if (currentBuild.findings.length === 0) {
    // Normal legitimate email: provide baseline finding backed by From and Received evidence
    const baselineEvIds = [];
    if (fromEv) baselineEvIds.push(fromEv.id);
    if (hops.length > 0 && hopEvidenceMap.get(1)) {
      baselineEvIds.push(hopEvidenceMap.get(1).id);
    }
    if (authHeaderEv) baselineEvIds.push(authHeaderEv.id);

    if (baselineEvIds.length > 0) {
      collector.addFinding({
        type: 'legitimate_baseline',
        severity: 'low',
        title: 'No Critical Threat Indicators Identified',
        summary: 'Technical headers, reported authentication, and transmission relay hops align with standard email communication patterns.',
        evidenceIds: baselineEvIds,
        limitations: [
          'Clean static indicators do not guarantee the absence of sophisticated targeted social engineering or zero-day phishing lures.',
          'Always verify unexpected wire transfer requests, password resets, or confidential data inquiries out-of-band.'
        ],
        recommendedAction: 'Standard corporate handling; maintain routine awareness for unexpected business communications.'
      });
    }
  }

  return collector.build();
}
