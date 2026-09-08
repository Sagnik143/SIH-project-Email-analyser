/**
 * Domain Intelligence Module
 * Analyzes domain reputation, typosquatting, and infrastructure patterns.
 */

/**
 * Analyze a domain for threat indicators
 */
export function analyzeDomain(domain) {
  if (!domain) return null;

  const cleanDomain = domain.toLowerCase().trim();

  return {
    domain: cleanDomain,
    isFreeEmail: isFreeEmailProvider(cleanDomain),
    isDisposable: isDisposableEmail(cleanDomain),
    typosquatResults: checkTyposquatting(cleanDomain),
    domainAge: estimateDomainAge(cleanDomain),
    tldAnalysis: analyzeTLD(cleanDomain),
    reputationScore: calculateDomainReputation(cleanDomain),
    findings: generateDomainFindings(cleanDomain),
  };
}

/**
 * Check if domain is a free email provider
 */
function isFreeEmailProvider(domain) {
  const freeProviders = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'mail.com', 'protonmail.com', 'proton.me', 'zoho.com', 'yandex.com',
    'tutanota.com', 'gmx.com', 'gmx.net', 'icloud.com', 'me.com',
    'live.com', 'msn.com', 'ymail.com', 'inbox.com', 'fastmail.com',
    'hushmail.com', 'mailinator.com', 'rediffmail.com',
  ];
  return freeProviders.includes(domain);
}

/**
 * Check if domain is a known disposable email service
 */
function isDisposableEmail(domain) {
  const disposable = [
    'tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com',
    'trashmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'yopmail.com',
    'temp-mail.org', '10minutemail.com', 'fakeinbox.com', 'mailnesia.com',
    'maildrop.cc', 'dispostable.com', 'mintemail.com', 'tempail.com',
    'emailondeck.com', 'getnada.com', 'mohmal.com', 'burnermail.io',
  ];
  return disposable.includes(domain);
}

/**
 * Check for typosquatting against known brands
 */
function checkTyposquatting(domain) {
  const brands = {
    'paypal.com': 'PayPal',
    'microsoft.com': 'Microsoft',
    'google.com': 'Google',
    'apple.com': 'Apple',
    'amazon.com': 'Amazon',
    'netflix.com': 'Netflix',
    'facebook.com': 'Facebook',
    'instagram.com': 'Instagram',
    'linkedin.com': 'LinkedIn',
    'twitter.com': 'Twitter',
    'dropbox.com': 'Dropbox',
    'bankofamerica.com': 'Bank of America',
    'wellsfargo.com': 'Wells Fargo',
    'chase.com': 'Chase',
    'hdfcbank.com': 'HDFC Bank',
    'icicibank.com': 'ICICI Bank',
    'sbi.co.in': 'SBI',
  };

  const results = [];
  const domainBase = domain.split('.')[0];

  for (const [legit, brandName] of Object.entries(brands)) {
    const legitBase = legit.split('.')[0];

    if (domain === legit) continue;

    // Levenshtein distance check
    const distance = levenshteinDistance(domainBase, legitBase);
    const maxLen = Math.max(domainBase.length, legitBase.length);
    const similarity = 1 - (distance / maxLen);

    if (similarity >= 0.7 && distance <= 3) {
      results.push({
        targetBrand: brandName,
        targetDomain: legit,
        similarity: Math.round(similarity * 100),
        distance,
      });
    }

    // Check if domain contains brand name
    if (domainBase.includes(legitBase) && domain !== legit) {
      results.push({
        targetBrand: brandName,
        targetDomain: legit,
        similarity: 85,
        distance: 0,
        note: `Domain contains "${legitBase}" but is not the legitimate domain`,
      });
    }
  }

  return results;
}

/**
 * Levenshtein distance calculation
 */
function levenshteinDistance(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Estimate domain age (heuristic)
 */
function estimateDomainAge(domain) {
  // Well-known old domains
  const knownOldDomains = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'microsoft.com',
    'google.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'paypal.com', 'ebay.com', 'netflix.com',
  ];

  if (knownOldDomains.includes(domain)) {
    return { estimated: '15+ years', isNew: false, riskLevel: 'low' };
  }

  // Check TLD for newly registered patterns
  const newTLDs = ['xyz', 'top', 'club', 'online', 'site', 'click', 'link', 'buzz', 'fun'];
  const tld = domain.split('.').pop();

  if (newTLDs.includes(tld)) {
    return { estimated: 'Likely recent', isNew: true, riskLevel: 'high' };
  }

  return { estimated: 'Unknown', isNew: false, riskLevel: 'medium' };
}

/**
 * Analyze TLD characteristics
 */
function analyzeTLD(domain) {
  const tld = domain.split('.').pop();

  const trustedTLDs = ['com', 'org', 'net', 'gov', 'edu', 'mil', 'int', 'co', 'io', 'in'];
  const suspiciousTLDs = ['xyz', 'top', 'club', 'online', 'site', 'click', 'link', 'buzz', 'fun', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws'];
  const countryTLDs = ['uk', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'au', 'ca', 'in', 'ng'];

  if (trustedTLDs.includes(tld)) {
    return { tld, category: 'trusted', risk: 'low' };
  } else if (suspiciousTLDs.includes(tld)) {
    return { tld, category: 'suspicious', risk: 'high' };
  } else if (countryTLDs.includes(tld)) {
    return { tld, category: 'country-code', risk: 'medium' };
  }

  return { tld, category: 'other', risk: 'medium' };
}

/**
 * Calculate overall domain reputation score (0-100, higher is more trusted)
 */
function calculateDomainReputation(domain) {
  let score = 50;

  if (isFreeEmailProvider(domain)) score -= 5;
  if (isDisposableEmail(domain)) score -= 40;

  const typos = checkTyposquatting(domain);
  if (typos.length > 0) score -= 30;

  const tld = analyzeTLD(domain);
  if (tld.risk === 'high') score -= 20;
  if (tld.risk === 'low') score += 20;

  const age = estimateDomainAge(domain);
  if (age.isNew) score -= 15;
  if (age.riskLevel === 'low') score += 15;

  return Math.max(0, Math.min(100, score));
}

/**
 * Generate domain findings
 */
function generateDomainFindings(domain) {
  const findings = [];

  if (isDisposableEmail(domain)) {
    findings.push({
      category: 'Disposable Email',
      severity: 'danger',
      description: `"${domain}" is a known disposable/temporary email service`,
      details: ['Disposable emails are frequently used for fraud and spam'],
    });
  }

  const typos = checkTyposquatting(domain);
  if (typos.length > 0) {
    findings.push({
      category: 'Domain Impersonation',
      severity: 'danger',
      description: `Domain may be impersonating known brand(s)`,
      details: typos.map(t => `Resembles ${t.targetBrand} (${t.targetDomain}) — ${t.similarity}% similarity`),
    });
  }

  const tld = analyzeTLD(domain);
  if (tld.risk === 'high') {
    findings.push({
      category: 'Suspicious TLD',
      severity: 'warning',
      description: `Top-level domain ".${tld.tld}" is commonly associated with malicious activity`,
      details: [],
    });
  }

  return findings;
}
