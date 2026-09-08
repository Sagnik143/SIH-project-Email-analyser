/**
 * Link Analyzer
 * Extracts and analyzes URLs from email content for phishing indicators.
 */

import { SUSPICIOUS_TLDS } from '../data/threatPatterns';

/**
 * Analyze all links in email body
 */
export function analyzeLinks(body) {
  const urls = extractURLs(body);
  const results = [];

  for (const url of urls) {
    results.push(analyzeURL(url));
  }

  const overallScore = results.length > 0
    ? Math.round(results.reduce((sum, r) => sum + r.riskScore, 0) / results.length)
    : 0;

  const highRiskCount = results.filter(r => r.riskScore >= 60).length;

  return {
    urls: results,
    totalLinks: results.length,
    highRiskLinks: highRiskCount,
    overallScore,
    findings: generateLinkFindings(results),
  };
}

/**
 * Extract all URLs from text
 */
function extractURLs(text) {
  if (!text) return [];

  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  const matches = text.match(urlRegex) || [];

  // Also check for href attributes
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let hrefMatch;
  while ((hrefMatch = hrefRegex.exec(text)) !== null) {
    if (!matches.includes(hrefMatch[1])) {
      matches.push(hrefMatch[1]);
    }
  }

  return [...new Set(matches)];
}

/**
 * Analyze a single URL for risk indicators
 */
function analyzeURL(url) {
  const indicators = [];
  let riskScore = 0;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    const fullUrl = url.toLowerCase();

    // 1. IP-based URL (no domain name)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      indicators.push({ type: 'IP_URL', description: 'URL uses raw IP address instead of domain name', severity: 'high' });
      riskScore += 40;
    }

    // 2. Suspicious TLD
    const tld = hostname.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      indicators.push({ type: 'SUSPICIOUS_TLD', description: `Suspicious top-level domain: .${tld}`, severity: 'medium' });
      riskScore += 20;
    }

    // 3. URL shortener
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'tiny.cc'];
    if (shorteners.some(s => hostname.includes(s))) {
      indicators.push({ type: 'URL_SHORTENER', description: 'Uses URL shortening service to hide true destination', severity: 'high' });
      riskScore += 30;
    }

    // 4. Excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      indicators.push({ type: 'EXCESSIVE_SUBDOMAINS', description: `Suspicious: ${subdomainCount} subdomains used`, severity: 'medium' });
      riskScore += 15;
    }

    // 5. Typosquatting detection
    const typosquatIndicators = detectTyposquatting(hostname);
    if (typosquatIndicators.length > 0) {
      for (const t of typosquatIndicators) {
        indicators.push(t);
        riskScore += 35;
      }
    }

    // 6. Credential harvesting path patterns
    const credPaths = ['/login', '/signin', '/auth', '/verify', '/confirm', '/secure', '/account', '/password', '/update', '/validate'];
    if (credPaths.some(p => path.includes(p))) {
      indicators.push({ type: 'CREDENTIAL_PATH', description: `URL path contains login/credential keyword: ${path}`, severity: 'medium' });
      riskScore += 20;
    }

    // 7. Encoded/obfuscated characters
    if (url.includes('%') && (url.match(/%[0-9A-Fa-f]{2}/g) || []).length > 3) {
      indicators.push({ type: 'URL_ENCODING', description: 'Excessive URL encoding detected — possible obfuscation', severity: 'medium' });
      riskScore += 15;
    }

    // 8. Non-standard port
    if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
      indicators.push({ type: 'NON_STANDARD_PORT', description: `Non-standard port: ${parsed.port}`, severity: 'medium' });
      riskScore += 15;
    }

    // 9. HTTP instead of HTTPS
    if (parsed.protocol === 'http:') {
      indicators.push({ type: 'NO_HTTPS', description: 'Uses unencrypted HTTP connection', severity: 'low' });
      riskScore += 10;
    }

    // 10. Data URI
    if (fullUrl.startsWith('data:')) {
      indicators.push({ type: 'DATA_URI', description: 'Data URI detected — could embed malicious content', severity: 'high' });
      riskScore += 40;
    }

    // 11. @ symbol in URL (user info attack)
    if (fullUrl.includes('@') && !fullUrl.includes('mailto:')) {
      indicators.push({ type: 'AT_SIGN_URL', description: 'URL contains @ symbol — possible URL obfuscation attack', severity: 'high' });
      riskScore += 35;
    }

    // 12. Homograph attack (mixed scripts)
    if (/xn--/.test(hostname)) {
      indicators.push({ type: 'PUNYCODE', description: 'Punycode/IDN domain detected — possible homograph attack', severity: 'high' });
      riskScore += 40;
    }

    return {
      url,
      hostname,
      riskScore: Math.min(100, riskScore),
      indicators,
      isHighRisk: riskScore >= 60,
    };
  } catch {
    return {
      url,
      hostname: '',
      riskScore: 20,
      indicators: [{ type: 'INVALID_URL', description: 'Malformed URL', severity: 'low' }],
      isHighRisk: false,
    };
  }
}

/**
 * Detect typosquatting (lookalike domains)
 */
function detectTyposquatting(hostname) {
  const indicators = [];
  const knownDomains = {
    'paypal.com': ['paypa1.com', 'paypai.com', 'paypaI.com', 'pαypal.com', 'paypal-secure.com', 'paypal.security-check.com', 'paypal-login.com'],
    'microsoft.com': ['microsft.com', 'micros0ft.com', 'microsoft-login.com', 'microsoft.support-center.com'],
    'google.com': ['g00gle.com', 'gogle.com', 'googIe.com', 'google-login.com'],
    'apple.com': ['app1e.com', 'appie.com', 'apple-id.com', 'apple.support-center.com'],
    'amazon.com': ['amaz0n.com', 'amazom.com', 'amazon-login.com'],
    'netflix.com': ['netf1ix.com', 'netflix-login.com'],
    'facebook.com': ['faceb00k.com', 'facebook-login.com'],
    'linkedin.com': ['linkedln.com', 'linkedin-login.com'],
  };

  for (const [legit, fakes] of Object.entries(knownDomains)) {
    // Direct match with known typosquats
    if (fakes.some(f => hostname.includes(f.split('.')[0]))) {
      indicators.push({
        type: 'TYPOSQUATTING',
        description: `Domain "${hostname}" appears to impersonate ${legit}`,
        severity: 'critical',
      });
    }

    // Check if domain contains brand name but is a different domain
    const brand = legit.split('.')[0];
    if (hostname.includes(brand) && !hostname.endsWith(legit)) {
      indicators.push({
        type: 'BRAND_IN_DOMAIN',
        description: `Domain contains "${brand}" but is not the legitimate ${legit}`,
        severity: 'high',
      });
    }
  }

  return indicators;
}

/**
 * Generate findings from link analysis
 */
function generateLinkFindings(results) {
  const findings = [];
  const highRisk = results.filter(r => r.isHighRisk);

  if (highRisk.length > 0) {
    findings.push({
      category: 'Malicious Links',
      severity: 'danger',
      description: `${highRisk.length} high-risk URL(s) detected in email body`,
      details: highRisk.map(r => `${r.url} — ${r.indicators.map(i => i.description).join('; ')}`),
    });
  }

  const shorteners = results.filter(r => r.indicators.some(i => i.type === 'URL_SHORTENER'));
  if (shorteners.length > 0) {
    findings.push({
      category: 'URL Obfuscation',
      severity: 'warning',
      description: `${shorteners.length} shortened URL(s) detected — true destinations are hidden`,
      details: shorteners.map(r => r.url),
    });
  }

  return findings;
}
