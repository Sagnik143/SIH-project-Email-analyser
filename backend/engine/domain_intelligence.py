"""
Domain Intelligence Module
Evaluates domain reputation, free/disposable status, typosquatting distance,
and TLD characteristics.
"""

from data.threat_patterns import SUSPICIOUS_TLDS

def analyze_domain(domain: str) -> dict:
    if not domain:
        return {}

    clean = domain.lower().strip()

    free_email = _is_free_provider(clean)
    disposable = _is_disposable(clean)
    typosquat = _check_typosquatting(clean)
    tld_analysis = _analyze_tld(clean)
    reputation = _calculate_reputation(clean, free_email, disposable, typosquat, tld_analysis)

    return {
        "domain": clean,
        "isFreeEmail": free_email,
        "isDisposable": disposable,
        "typosquatResults": typosquat,
        "tldAnalysis": tld_analysis,
        "reputationScore": reputation,
        "findings": _generate_findings(clean, free_email, disposable, typosquat, tld_analysis),
    }

def _is_free_provider(domain: str) -> bool:
    providers = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'mail.com', 'protonmail.com', 'proton.me', 'zoho.com', 'yandex.com',
        'tutanota.com', 'gmx.com', 'gmx.net', 'icloud.com', 'me.com',
        'live.com', 'msn.com', 'ymail.com', 'inbox.com', 'fastmail.com',
    ]
    return domain in providers

def _is_disposable(domain: str) -> bool:
    disposables = [
        'tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com',
        'trashmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'yopmail.com',
        'temp-mail.org', '10minutemail.com', 'fakeinbox.com', 'mailnesia.com',
        'maildrop.cc', 'dispostable.com', 'mintemail.com', 'tempail.com',
    ]
    return domain in disposables

def _check_typosquatting(domain: str) -> list:
    brands = {
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
        'chase.com': 'Chase',
        'wellsfargo.com': 'Wells Fargo',
        'bankofamerica.com': 'Bank of America',
        'sbi.co.in': 'SBI',
    }
    results = []
    base = domain.split('.')[0]

    for legit_domain, brand in brands.items():
        legit_base = legit_domain.split('.')[0]
        if domain == legit_domain:
            continue

        dist = _levenshtein(base, legit_base)
        max_len = max(len(base), len(legit_base))
        sim = 1.0 - (dist / max_len) if max_len > 0 else 0

        if sim >= 0.7 and dist <= 3:
            results.append({
                "targetBrand": brand,
                "targetDomain": legit_domain,
                "similarity": round(sim * 100),
                "distance": dist,
            })
        elif legit_base in base and domain != legit_domain:
            results.append({
                "targetBrand": brand,
                "targetDomain": legit_domain,
                "similarity": 85,
                "distance": 0,
                "note": f'Domain contains "{legit_base}" brand root',
            })

    return results

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def _analyze_tld(domain: str) -> dict:
    tld = domain.split('.')[-1] if '.' in domain else ''
    is_suspicious = tld in SUSPICIOUS_TLDS
    return {
        "tld": tld,
        "isSuspicious": is_suspicious,
        "risk": "high" if is_suspicious else "low",
    }

def _calculate_reputation(domain: str, is_free: bool, is_disp: bool, typosquat: list, tld_info: dict) -> int:
    score = 80
    if is_free:
        score = 50
    if is_disp:
        score = 10
    if typosquat:
        score = max(5, score - 50)
    if tld_info.get("isSuspicious"):
        score = max(5, score - 30)
    return max(0, min(100, score))

def _generate_findings(domain: str, is_free: bool, is_disp: bool, typosquat: list, tld_info: dict) -> list:
    findings = []
    if typosquat:
        findings.append({
            "category": "Domain Typosquatting",
            "severity": "danger",
            "description": f"Domain closely mimics legitimate brand domain(s)",
            "details": [f"Mimics {t['targetBrand']} ({t['targetDomain']})" for t in typosquat]
        })
    if is_disp:
        findings.append({
            "category": "Disposable Email Service",
            "severity": "danger",
            "description": f"Sender domain {domain} is a temporary disposable email inbox",
            "details": ["Disposable domains are commonly used for anonymous fraudulent emails"]
        })
    if tld_info.get("isSuspicious"):
        findings.append({
            "category": "Suspicious Top-Level Domain",
            "severity": "warning",
            "description": f"Domain uses high-abuse TLD: .{tld_info['tld']}",
            "details": ["This TLD is statistically prevalent in spam and phishing campaigns"]
        })
    return findings
