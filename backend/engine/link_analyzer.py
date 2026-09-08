"""
Link Analyzer
Extracts and inspects URLs from email body, checking for IP URLs, typosquatting,
credential paths, URL shorteners, punycode/homograph attacks, and suspicious TLDs.
"""

import re
from urllib.parse import urlparse
from data.threat_patterns import SUSPICIOUS_TLDS

def analyze_links(body: str) -> dict:
    urls = _extract_urls(body)
    results = [_analyze_url(u) for u in urls]

    overall_score = round(sum(r["riskScore"] for r in results) / len(results)) if results else 0
    high_risk_count = sum(1 for r in results if r["riskScore"] >= 60)

    return {
        "urls": results,
        "totalLinks": len(results),
        "highRiskLinks": high_risk_count,
        "overallScore": overall_score,
        "findings": _generate_link_findings(results),
    }

def _extract_urls(text: str) -> list:
    if not text:
        return []
    url_regex = r'https?://[^\s<>"\'\)\]]+'
    matches = re.findall(url_regex, text, re.IGNORECASE)
    href_regex = r'href=["\']([^"\']+)["\']'
    href_matches = re.findall(href_regex, text, re.IGNORECASE)

    all_urls = []
    for u in matches + href_matches:
        if u.startswith('http://') or u.startswith('https://'):
            if u not in all_urls:
                all_urls.append(u)
    return all_urls

def _analyze_url(url: str) -> dict:
    indicators = []
    risk_score = 0

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        full_url = url.lower()

        # 1. IP-based URL
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            indicators.append({
                "type": "IP_URL",
                "description": "URL uses raw IP address instead of domain name",
                "severity": "high"
            })
            risk_score += 40

        # 2. Suspicious TLD
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        if tld in SUSPICIOUS_TLDS:
            indicators.append({
                "type": "SUSPICIOUS_TLD",
                "description": f"Suspicious top-level domain: .{tld}",
                "severity": "medium"
            })
            risk_score += 20

        # 3. URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'tiny.cc']
        if any(s in hostname for s in shorteners):
            indicators.append({
                "type": "URL_SHORTENER",
                "description": "Uses URL shortening service to mask true destination",
                "severity": "high"
            })
            risk_score += 30

        # 4. Excessive subdomains
        parts = hostname.split('.')
        if len(parts) >= 4:
            indicators.append({
                "type": "EXCESSIVE_SUBDOMAINS",
                "description": f"Suspicious subdomain nesting: {len(parts)-2} subdomains",
                "severity": "medium"
            })
            risk_score += 15

        # 5. Credential harvesting path keywords
        cred_paths = ['/login', '/signin', '/auth', '/verify', '/confirm', '/secure', '/account', '/password', '/update', '/validate']
        if any(p in path for p in cred_paths):
            indicators.append({
                "type": "CREDENTIAL_PATH",
                "description": f"URL path contains credential keyword: {path}",
                "severity": "medium"
            })
            risk_score += 20

        # 6. Typosquatting heuristics
        typos = _detect_typosquatting(hostname)
        for t in typos:
            indicators.append(t)
            risk_score += 35

        # 7. Unencrypted HTTP
        if parsed.scheme == 'http':
            indicators.append({
                "type": "NO_HTTPS",
                "description": "Uses unencrypted HTTP protocol",
                "severity": "low"
            })
            risk_score += 10

        # 8. Userinfo '@' in URL
        if '@' in full_url:
            indicators.append({
                "type": "AT_SIGN_URL",
                "description": "URL contains @ symbol — possible obfuscation trick",
                "severity": "high"
            })
            risk_score += 35

        # 9. Punycode
        if 'xn--' in hostname:
            indicators.append({
                "type": "PUNYCODE",
                "description": "Punycode/IDN domain detected — possible homograph spoofing",
                "severity": "high"
            })
            risk_score += 40

        return {
            "url": url,
            "hostname": hostname,
            "riskScore": min(100, risk_score),
            "indicators": indicators,
            "isHighRisk": risk_score >= 60,
        }
    except Exception:
        return {
            "url": url,
            "hostname": "",
            "riskScore": 20,
            "indicators": [{"type": "INVALID_URL", "description": "Malformed URL", "severity": "low"}],
            "isHighRisk": False,
        }

def _detect_typosquatting(hostname: str) -> list:
    brands = {
        'paypal.com': 'PayPal',
        'microsoft.com': 'Microsoft',
        'google.com': 'Google',
        'apple.com': 'Apple',
        'amazon.com': 'Amazon',
        'netflix.com': 'Netflix',
        'chase.com': 'Chase',
        'wellsfargo.com': 'Wells Fargo',
    }
    indicators = []
    base = hostname.split('.')[0]

    for legit_domain, brand in brands.items():
        legit_base = legit_domain.split('.')[0]
        if hostname == legit_domain or hostname.endswith('.' + legit_domain):
            continue
        if legit_base in hostname:
            indicators.append({
                "type": "BRAND_IN_HOSTNAME",
                "description": f'Domain contains brand name "{brand}" but is not legitimate {legit_domain}',
                "severity": "high"
            })
    return indicators

def _generate_link_findings(results: list) -> list:
    findings = []
    for r in results:
        if r.get("isHighRisk"):
            findings.append({
                "category": "High-Risk Link",
                "severity": "danger",
                "description": f"Suspicious URL detected: {r['url']}",
                "details": [ind["description"] for ind in r.get("indicators", [])]
            })
    return findings
