/**
 * Sender Authentication Validator
 * Analyzes SPF, DKIM, DMARC, Display Name Spoofing, and Domain Lookalikes
 */

const TARGET_BRANDS = [
  'microsoft.com', 'office365.com', 'apple.com', 'google.com',
  'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
  'amazon.com', 'netflix.com', 'docusign.com', 'dropbox.com',
  'irs.gov', 'fedex.com', 'ups.com', 'dhl.com', 'facebook.com',
  'citibank.com', 'linkedin.com', 'slack.com', 'zoom.us'
];

const EXECUTIVE_TITLES = [
  'ceo', 'cfo', 'coo', 'cto', 'president', 'director', 'chairman',
  'chief executive', 'chief financial', 'executive director',
  'payroll', 'human resources', 'hr department', 'it support',
  'helpdesk', 'system administrator', 'security team', 'account verification'
];

export function validateAuthentication(email) {
  const headers = email.headers || {};
  const authResults = headers['authentication-results'] || [];
  const receivedSpf = headers['received-spf'] || [];
  const dkimSignature = headers['dkim-signature'] || [];
  const arcResults = headers['arc-authentication-results'] || [];

  // Parse SPF
  let spf = { status: 'none', details: 'No SPF record or validation header detected', scoreImpact: 10 };
  const spfCombined = [...receivedSpf, ...authResults].join(' ');
  if (/spf=(pass)\b/i.test(spfCombined) || /^pass\b/i.test(receivedSpf[0] || '')) {
    spf = { status: 'PASS', details: 'Sender IP is explicitly authorized by domain SPF record', scoreImpact: 0 };
  } else if (/spf=(fail)\b/i.test(spfCombined) || /^fail\b/i.test(receivedSpf[0] || '')) {
    spf = { status: 'FAIL', details: 'Hard SPF Fail: Sender IP unauthorized by domain SPF record', scoreImpact: 35 };
  } else if (/spf=(softfail)\b/i.test(spfCombined) || /^softfail\b/i.test(receivedSpf[0] || '')) {
    spf = { status: 'SOFTFAIL', details: 'Soft SPF Fail: Sender IP not listed in SPF policy (~all)', scoreImpact: 25 };
  } else if (/spf=(neutral|none)\b/i.test(spfCombined)) {
    spf = { status: 'NEUTRAL', details: 'SPF Neutral: Domain does not assert sender validity (?all)', scoreImpact: 15 };
  }

  // Parse DKIM
  let dkim = { status: 'none', details: 'No DKIM cryptographic signature header present', scoreImpact: 15 };
  const dkimCombined = [...authResults, ...arcResults].join(' ');
  if (/dkim=(pass)\b/i.test(dkimCombined)) {
    dkim = { status: 'PASS', details: 'Valid RSA/Ed25519 cryptographic DKIM signature verified', scoreImpact: 0 };
  } else if (/dkim=(fail)\b/i.test(dkimCombined)) {
    dkim = { status: 'FAIL', details: 'DKIM signature check failed: Body or header has been altered', scoreImpact: 35 };
  } else if (dkimSignature.length > 0) {
    dkim = { status: 'UNVERIFIED', details: 'DKIM-Signature header present but unvalidated by receiver', scoreImpact: 10 };
  }

  // Parse DMARC
  let dmarc = { status: 'none', details: 'No DMARC evaluation found in headers', scoreImpact: 15 };
  if (/dmarc=(pass)\b/i.test(authResults.join(' '))) {
    dmarc = { status: 'PASS', details: 'DMARC alignment passed with domain policy', scoreImpact: 0 };
  } else if (/dmarc=(fail)\b/i.test(authResults.join(' '))) {
    dmarc = { status: 'FAIL', details: 'DMARC validation failed: Domain policy violation', scoreImpact: 40 };
  }

  // Display Name Spoofing Check
  const displayNameAnalysis = checkDisplayNameSpoofing(email.envelope);

  // Lookalike Domain / Typosquatting Check
  const domainAnalysis = checkDomainLookalike(email.envelope.from?.domain);

  // Return-Path & Reply-To Alignment Check
  const alignmentAnalysis = checkHeaderAlignment(email.envelope);

  // Aggregate authentication threat score
  let authRiskScore = 0;
  authRiskScore += spf.scoreImpact;
  authRiskScore += dkim.scoreImpact;
  authRiskScore += dmarc.scoreImpact;
  if (displayNameAnalysis.isSpoofed) authRiskScore += 45;
  if (domainAnalysis.isLookalike) authRiskScore += 40;
  if (alignmentAnalysis.hasReplyToDiscrepancy) authRiskScore += 30;

  // Cap at 100
  authRiskScore = Math.min(100, authRiskScore);

  return {
    spf,
    dkim,
    dmarc,
    displayNameAnalysis,
    domainAnalysis,
    alignmentAnalysis,
    authRiskScore,
    overallAuthStatus: (spf.status === 'PASS' && dkim.status === 'PASS' && dmarc.status === 'PASS' && !displayNameAnalysis.isSpoofed)
      ? 'AUTHENTIC'
      : (authRiskScore >= 60 ? 'CRITICAL_RISK' : (authRiskScore >= 30 ? 'SUSPICIOUS' : 'LOW_RISK'))
  };
}

function checkDisplayNameSpoofing(envelope) {
  const name = (envelope.from?.name || '').trim();
  const address = (envelope.from?.address || '').toLowerCase();
  const domain = (envelope.from?.domain || '').toLowerCase();

  const flags = [];
  let isSpoofed = false;

  if (!name) {
    return { isSpoofed: false, flags: [] };
  }

  // 1. Display name contains an email address that doesn't match the actual address
  const embeddedEmailMatch = name.match(/[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}/);
  if (embeddedEmailMatch) {
    const embeddedEmail = embeddedEmailMatch[0].toLowerCase();
    if (embeddedEmail !== address) {
      isSpoofed = true;
      flags.push(`Display Name contains deceptive embedded email: "${embeddedEmail}" while actual sender is "${address}"`);
    }
  }

  // 2. Executive / Authority persona impersonation on generic or consumer webmail domain (e.g. gmail, yahoo, outlook, protonmail)
  const lowerName = name.toLowerCase();
  const isConsumerDomain = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com', 'aol.com', 'mail.com'].includes(domain);

  const matchedTitle = EXECUTIVE_TITLES.find(title => lowerName.includes(title));
  if (matchedTitle && isConsumerDomain) {
    isSpoofed = true;
    flags.push(`Authority impersonation detected: Display name claims authority role ("${matchedTitle}") but sends from free consumer webmail ("${domain}")`);
  }

  // 3. Known Brand impersonation in display name
  const matchedBrand = TARGET_BRANDS.find(brand => {
    const brandName = brand.split('.')[0];
    return lowerName.includes(brandName) && !domain.includes(brandName);
  });
  if (matchedBrand) {
    isSpoofed = true;
    flags.push(`Brand Impersonation: Display name mentions "${matchedBrand.split('.')[0]}" while sender domain is unrelated ("${domain}")`);
  }

  return {
    isSpoofed,
    displayName: name,
    actualAddress: address,
    flags
  };
}

function checkDomainLookalike(senderDomain) {
  if (!senderDomain) return { isLookalike: false, targetBrand: null, flags: [] };

  const domain = senderDomain.toLowerCase();
  const flags = [];
  let isLookalike = false;
  let matchedBrand = null;

  // Check Punycode (IDN homograph attack)
  if (domain.startsWith('xn--') || domain.includes('.xn--')) {
    isLookalike = true;
    flags.push(`Punycode / IDN Homograph Attack: Domain "${domain}" uses encoded non-ASCII homoglyphs to visually spoof legitimate characters`);
  }

  // Check common typosquatting substitutions (e.g., o -> 0, l -> 1, m -> rn, vv -> w)
  for (const brand of TARGET_BRANDS) {
    const brandBase = brand.split('.')[0];
    const domainBase = domain.split('.')[0];

    // Direct match is legitimate
    if (domain === brand) continue;

    // Subdomain lookalike (e.g., paypal.com.attacker.com)
    if (domain.includes(brandBase) && !domain.endsWith('.' + brand) && domain !== brand) {
      isLookalike = true;
      matchedBrand = brand;
      flags.push(`Subdomain Spoofing / Combo-squatting: Domain "${domain}" incorporates brand "${brandBase}" into a hostile host`);
      break;
    }

    // Levenshtein distance check
    const dist = levenshteinDistance(domainBase, brandBase);
    if (dist > 0 && dist <= 2 && Math.abs(domainBase.length - brandBase.length) <= 2) {
      isLookalike = true;
      matchedBrand = brand;
      flags.push(`Typo-squatting detected: Domain "${domain}" is suspiciously similar (distance ${dist}) to major brand "${brand}"`);
      break;
    }

    // Character swap check (0 for o, 1 for l, rn for m)
    const normalized = domainBase.replace(/0/g, 'o').replace(/1/g, 'l').replace(/rn/g, 'm').replace(/vv/g, 'w');
    if (normalized === brandBase && domainBase !== brandBase) {
      isLookalike = true;
      matchedBrand = brand;
      flags.push(`Visual Leetspeak / Homoglyph Impersonation: "${domainBase}" visually imitates "${brandBase}"`);
      break;
    }
  }

  return {
    isLookalike,
    senderDomain: domain,
    targetBrand: matchedBrand,
    flags
  };
}

function checkHeaderAlignment(envelope) {
  const fromDomain = (envelope.from?.domain || '').toLowerCase();
  const replyToDomain = (envelope.replyTo?.domain || '').toLowerCase();
  const returnPathDomain = (envelope.returnPath || '').split('@')[1]?.toLowerCase() || '';

  const flags = [];
  let hasReplyToDiscrepancy = false;
  let hasReturnPathDiscrepancy = false;

  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    hasReplyToDiscrepancy = true;
    flags.push(`Reply-To Mismatch (BEC Indicator): From domain is "@${fromDomain}", but replies will be routed to "@${replyToDomain}"`);
  }

  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    hasReturnPathDiscrepancy = true;
    flags.push(`Return-Path / Envelope Sender Mismatch: Technical sender "@${returnPathDomain}" does not match header From "@${fromDomain}"`);
  }

  return {
    hasReplyToDiscrepancy,
    hasReturnPathDiscrepancy,
    fromDomain,
    replyToDomain,
    returnPathDomain,
    flags
  };
}

function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}
