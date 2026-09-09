/**
 * NLP Analyzer
 * Performs natural language analysis on email content to detect
 * phishing, impersonation, social engineering, and BEC patterns.
 */

import { URGENCY_PHRASES, PHISHING_KEYWORDS, BRAND_NAMES, BEC_PATTERNS, SOCIAL_ENGINEERING_PHRASES, AUTHORITY_PHRASES, FEAR_PHRASES, REWARD_PHRASES } from '../data/threatPatterns';

/**
 * Run full NLP analysis on email content
 */
export function analyzeEmailContent(subject, body, from) {
  const fullText = `${subject} ${body}`.toLowerCase();
  const subjectLower = (subject || '').toLowerCase();
  const fromLower = (from?.name || '').toLowerCase() + ' ' + (from?.email || '').toLowerCase();

  const urgency = detectUrgency(fullText, subjectLower);
  const phishing = detectPhishingLanguage(fullText, subjectLower);
  const impersonation = detectImpersonation(from, fullText);
  const socialEngineering = detectSocialEngineering(fullText);
  const bec = detectBEC(fullText, from);
  const sentiment = analyzeSentiment(fullText);

  const findings = [
    ...urgency.findings,
    ...phishing.findings,
    ...impersonation.findings,
    ...socialEngineering.findings,
    ...bec.findings,
  ];

  // Calculate overall NLP threat score
  const nlpScore = calculateNLPScore({
    urgencyScore: urgency.score,
    phishingScore: phishing.score,
    impersonationScore: impersonation.score,
    socialEngineeringScore: socialEngineering.score,
    becScore: bec.score,
    sentimentScore: sentiment.manipulationScore,
  });

  return {
    urgency,
    phishing,
    impersonation,
    socialEngineering,
    bec,
    sentiment,
    findings,
    nlpScore,
    classification: classifyByNLP(nlpScore, findings),
  };
}

/**
 * Detect urgency and time-pressure language
 */
function detectUrgency(text, subject) {
  const matched = [];

  for (const phrase of URGENCY_PHRASES) {
    if (text.includes(phrase.toLowerCase())) {
      matched.push(phrase);
    }
  }

  // Subject line urgency amplification
  let subjectUrgency = 0;
  for (const phrase of URGENCY_PHRASES) {
    if (subject.includes(phrase.toLowerCase())) {
      subjectUrgency += 15;
    }
  }

  // Exclamation marks
  const exclamationCount = (text.match(/!/g) || []).length;
  if (exclamationCount > 3) {
    matched.push('Excessive exclamation marks (!!!)');
  }

  // ALL CAPS words
  const capsWords = text.match(/\b[A-Z]{4,}\b/g) || [];
  if (capsWords.length > 2) {
    matched.push(`Excessive CAPS usage: ${capsWords.slice(0, 3).join(', ')}`);
  }

  const score = Math.min(100, matched.length * 18 + subjectUrgency);

  return {
    score,
    matched,
    findings: matched.length > 0 ? [{
      category: 'Urgency Detection',
      severity: score > 50 ? 'danger' : 'warning',
      description: `Detected ${matched.length} urgency indicator(s) commonly used in phishing attacks`,
      details: matched,
    }] : [],
  };
}

/**
 * Detect phishing-specific language patterns
 */
function detectPhishingLanguage(text, subject) {
  const matched = [];

  for (const keyword of PHISHING_KEYWORDS) {
    if (text.includes(keyword.toLowerCase())) {
      matched.push(keyword);
    }
  }

  // Check for credential harvesting patterns
  const credentialPatterns = [
    'enter your password', 'confirm your identity', 'verify your account',
    'update your payment', 'confirm your details', 'validate your credentials',
    'sign in to continue', 'login required', 'security verification required',
    'enter your ssn', 'provide your credit card', 'bank account details'
  ];

  for (const pattern of credentialPatterns) {
    if (text.includes(pattern)) {
      matched.push(`Credential harvesting: "${pattern}"`);
    }
  }

  const score = Math.min(100, matched.length * 15);

  return {
    score,
    matched,
    findings: matched.length > 0 ? [{
      category: 'Phishing Indicators',
      severity: score > 50 ? 'danger' : 'warning',
      description: `Found ${matched.length} phishing language pattern(s)`,
      details: matched,
    }] : [],
  };
}

/**
 * Detect impersonation attempts
 */
function detectImpersonation(from, text) {
  const matched = [];
  const fromName = (from?.name || '').toLowerCase();
  const fromEmail = (from?.email || '').toLowerCase();

  // Check for brand impersonation in display name
  for (const brand of BRAND_NAMES) {
    const brandLower = brand.toLowerCase();
    if (fromName.includes(brandLower)) {
      // Check if email domain matches the brand
      const expectedDomains = getBrandDomains(brand);
      const emailDomain = fromEmail.split('@')[1] || '';

      if (!expectedDomains.some(d => emailDomain.includes(d))) {
        matched.push(`Brand impersonation: Display name contains "${brand}" but email domain is ${emailDomain}`);
      }
    }
  }

  // Check for title-based impersonation
  const titlePatterns = [
    /\b(ceo|cfo|cto|president|director|manager|chairman)\b/i,
    /\b(it department|helpdesk|help desk|tech support|system admin)\b/i,
    /\b(human resources|hr department|payroll)\b/i,
  ];

  for (const pattern of titlePatterns) {
    if (pattern.test(fromName) || pattern.test(text.slice(0, 200))) {
      matched.push(`Authority impersonation: Uses title/role "${fromName || text.slice(0, 50)}"`);
      break;
    }
  }

  // Check if display name is an email address (common trick)
  if (fromName && fromName.includes('@') && fromName !== fromEmail) {
    matched.push(`Display name spoofing: Name field contains email "${fromName}" different from actual sender`);
  }

  const score = Math.min(100, matched.length * 30);

  return {
    score,
    matched,
    findings: matched.length > 0 ? [{
      category: 'Impersonation Detection',
      severity: 'danger',
      description: `Detected ${matched.length} impersonation indicator(s)`,
      details: matched,
    }] : [],
  };
}

/**
 * Detect social engineering patterns
 */
function detectSocialEngineering(text) {
  const matched = [];

  for (const phrase of SOCIAL_ENGINEERING_PHRASES) {
    if (text.includes(phrase.toLowerCase())) {
      matched.push(phrase);
    }
  }

  // Authority-based manipulation
  for (const phrase of AUTHORITY_PHRASES) {
    if (text.includes(phrase.toLowerCase())) {
      matched.push(`Authority manipulation: "${phrase}"`);
    }
  }

  // Fear-based manipulation
  for (const phrase of FEAR_PHRASES) {
    if (text.includes(phrase.toLowerCase())) {
      matched.push(`Fear-based pressure: "${phrase}"`);
    }
  }

  // Reward-based manipulation
  for (const phrase of REWARD_PHRASES) {
    if (text.includes(phrase.toLowerCase())) {
      matched.push(`Reward/lure: "${phrase}"`);
    }
  }

  const score = Math.min(100, matched.length * 12);

  return {
    score,
    matched,
    findings: matched.length > 0 ? [{
      category: 'Social Engineering',
      severity: score > 60 ? 'danger' : 'warning',
      description: `Found ${matched.length} social engineering technique(s)`,
      details: matched,
    }] : [],
  };
}

/**
 * Detect Business Email Compromise (BEC) patterns
 */
function detectBEC(text, from) {
  const matched = [];

  for (const pattern of BEC_PATTERNS) {
    if (text.includes(pattern.toLowerCase())) {
      matched.push(pattern);
    }
  }

  // Wire transfer / payment diversion
  const paymentPatterns = [
    'wire transfer', 'bank transfer', 'update bank details', 'new payment instructions',
    'change of account', 'updated routing number', 'revised payment', 'pay the attached invoice',
    'purchase gift cards', 'buy itunes cards', 'google play cards',
  ];

  for (const p of paymentPatterns) {
    if (text.includes(p)) {
      matched.push(`Payment diversion: "${p}"`);
    }
  }

  const score = Math.min(100, matched.length * 20);

  return {
    score,
    matched,
    findings: matched.length > 0 ? [{
      category: 'Business Email Compromise',
      severity: 'danger',
      description: `Detected ${matched.length} BEC indicator(s) — possible financial fraud attempt`,
      details: matched,
    }] : [],
  };
}

/**
 * Simple sentiment / manipulation analysis
 */
function analyzeSentiment(text) {
  let fearScore = 0;
  let urgencyScore = 0;
  let authorityScore = 0;
  let rewardScore = 0;

  for (const p of FEAR_PHRASES) {
    if (text.includes(p.toLowerCase())) fearScore += 20;
  }
  for (const p of URGENCY_PHRASES) {
    if (text.includes(p.toLowerCase())) urgencyScore += 15;
  }
  for (const p of AUTHORITY_PHRASES) {
    if (text.includes(p.toLowerCase())) authorityScore += 18;
  }
  for (const p of REWARD_PHRASES) {
    if (text.includes(p.toLowerCase())) rewardScore += 15;
  }

  const manipulationScore = Math.min(100, (fearScore + urgencyScore + authorityScore + rewardScore) / 4);

  return {
    fearScore: Math.min(100, fearScore),
    urgencyScore: Math.min(100, urgencyScore),
    authorityScore: Math.min(100, authorityScore),
    rewardScore: Math.min(100, rewardScore),
    manipulationScore: Math.round(manipulationScore),
  };
}

/**
 * Calculate weighted NLP score
 */
function calculateNLPScore(scores) {
  const weights = {
    urgencyScore: 0.20,
    phishingScore: 0.25,
    impersonationScore: 0.20,
    socialEngineeringScore: 0.15,
    becScore: 0.15,
    sentimentScore: 0.05,
  };

  let total = 0;
  for (const [key, weight] of Object.entries(weights)) {
    total += (scores[key] || 0) * weight;
  }

  const values = Object.values(scores || {});
  const maxSignal = values.length > 0 ? Math.max(...values) : 0;
  total = Math.max(total, maxSignal * 0.6);

  return Math.round(Math.min(100, total));
}

/**
 * Classify email by NLP score
 */
function classifyByNLP(score, findings) {
  const hasBEC = findings.some(f => f.category === 'Business Email Compromise');
  const hasImpersonation = findings.some(f => f.category === 'Impersonation Detection');

  if (hasBEC && score > 40) return 'fraud';
  if (hasImpersonation && score > 30) return 'impersonation';
  if (score >= 65) return 'phishing';
  if (score >= 35) return 'suspicious';
  return 'legitimate';
}

/**
 * Get expected domains for known brands
 */
function getBrandDomains(brand) {
  const map = {
    'PayPal': ['paypal.com'],
    'Microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com'],
    'Google': ['google.com', 'gmail.com'],
    'Apple': ['apple.com', 'icloud.com'],
    'Amazon': ['amazon.com', 'amazon.in'],
    'Netflix': ['netflix.com'],
    'Facebook': ['facebook.com', 'fb.com', 'meta.com'],
    'Instagram': ['instagram.com'],
    'WhatsApp': ['whatsapp.com'],
    'LinkedIn': ['linkedin.com'],
    'Twitter': ['twitter.com', 'x.com'],
    'Dropbox': ['dropbox.com'],
    'Bank of America': ['bankofamerica.com'],
    'Wells Fargo': ['wellsfargo.com'],
    'Chase': ['chase.com'],
    'Citibank': ['citibank.com', 'citi.com'],
    'HDFC Bank': ['hdfcbank.com'],
    'ICICI Bank': ['icicibank.com'],
    'SBI': ['sbi.co.in', 'onlinesbi.com'],
    'DHL': ['dhl.com'],
    'FedEx': ['fedex.com'],
    'UPS': ['ups.com'],
  };

  return map[brand] || [brand.toLowerCase().replace(/\s+/g, '') + '.com'];
}
