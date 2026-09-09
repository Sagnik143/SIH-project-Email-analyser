"""
NLP Analyzer
Natural language analysis on email text to detect urgency, phishing keywords,
brand/authority impersonation, BEC, and manipulative social engineering.
"""

import re
from data.threat_patterns import (
    URGENCY_PHRASES,
    PHISHING_KEYWORDS,
    BRAND_NAMES,
    BEC_PATTERNS,
    SOCIAL_ENGINEERING_PHRASES,
    AUTHORITY_PHRASES,
    FEAR_PHRASES,
    REWARD_PHRASES,
)

def analyze_email_content(subject: str, body: str, from_data: dict) -> dict:
    subject = subject or ""
    body = body or ""
    full_text = f"{subject} {body}".lower()
    subject_lower = subject.lower()

    urgency = _detect_urgency(full_text, subject_lower)
    phishing = _detect_phishing_language(full_text, subject_lower)
    impersonation = _detect_impersonation(from_data, full_text)
    social_engineering = _detect_social_engineering(full_text)
    bec = _detect_bec(full_text, from_data)
    sentiment = _analyze_sentiment(full_text)

    findings = []
    findings.extend(urgency["findings"])
    findings.extend(phishing["findings"])
    findings.extend(impersonation["findings"])
    findings.extend(social_engineering["findings"])
    findings.extend(bec["findings"])

    nlp_score = _calculate_nlp_score({
        "urgencyScore": urgency["score"],
        "phishingScore": phishing["score"],
        "impersonationScore": impersonation["score"],
        "socialEngineeringScore": social_engineering["score"],
        "becScore": bec["score"],
        "sentimentScore": sentiment["manipulationScore"],
    })

    return {
        "urgency": urgency,
        "phishing": phishing,
        "impersonation": impersonation,
        "socialEngineering": social_engineering,
        "bec": bec,
        "sentiment": sentiment,
        "findings": findings,
        "nlpScore": nlp_score,
        "classification": _classify_by_nlp(nlp_score, findings),
    }

def _detect_urgency(text: str, subject: str) -> dict:
    matched = []
    for phrase in URGENCY_PHRASES:
        if phrase.lower() in text:
            matched.append(phrase)

    subject_urgency = 0
    for phrase in URGENCY_PHRASES:
        if phrase.lower() in subject:
            subject_urgency += 15

    excl_count = text.count('!')
    if excl_count > 3:
        matched.append("Excessive exclamation marks (!!!)")

    caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if len(caps_words) > 2:
        matched.append(f"Excessive CAPS usage: {', '.join(caps_words[:3])}")

    score = min(100, len(matched) * 18 + subject_urgency)

    findings = []
    if matched:
        findings.append({
            "category": "Urgency Detection",
            "severity": "danger" if score > 50 else "warning",
            "description": f"Detected {len(matched)} urgency indicator(s) commonly used in phishing attacks",
            "details": matched,
        })

    return {
        "score": score,
        "matched": matched,
        "findings": findings,
    }

def _detect_phishing_language(text: str, subject: str) -> dict:
    matched = []
    for kw in PHISHING_KEYWORDS:
        if kw.lower() in text:
            matched.append(kw)

    credential_patterns = [
        'enter your password', 'confirm your identity', 'verify your account',
        'update your payment', 'confirm your details', 'validate your credentials',
        'sign in to continue', 'login required', 'security verification required',
        'enter your ssn', 'provide your credit card', 'bank account details'
    ]
    for p in credential_patterns:
        if p in text:
            matched.append(f'Credential harvesting: "{p}"')

    score = min(100, len(matched) * 15)

    findings = []
    if matched:
        findings.append({
            "category": "Phishing Indicators",
            "severity": "danger" if score > 50 else "warning",
            "description": f"Found {len(matched)} phishing language pattern(s)",
            "details": matched,
        })

    return {
        "score": score,
        "matched": matched,
        "findings": findings,
    }

def _detect_impersonation(from_data: dict, text: str) -> dict:
    matched = []
    from_name = (from_data.get("name") or "").lower()
    from_email = (from_data.get("email") or "").lower()

    for brand in BRAND_NAMES:
        brand_lower = brand.lower()
        if brand_lower in from_name:
            expected_domains = _get_brand_domains(brand)
            email_domain = from_email.split("@")[1] if "@" in from_email else ""
            if not any(d in email_domain for d in expected_domains):
                matched.append(f'Brand impersonation: Display name contains "{brand}" but email domain is {email_domain}')

    title_patterns = [
        r'\b(ceo|cfo|cto|president|director|manager|chairman)\b',
        r'\b(it department|helpdesk|help desk|tech support|system admin)\b',
        r'\b(human resources|hr department|payroll)\b',
    ]
    for pattern in title_patterns:
        if re.search(pattern, from_name, re.IGNORECASE) or re.search(pattern, text[:200], re.IGNORECASE):
            matched.append(f'Authority impersonation: Uses executive/IT title')
            break

    if from_name and '@' in from_name and from_name != from_email:
        matched.append(f'Display name spoofing: Name field contains email address "{from_name}"')

    score = min(100, len(matched) * 30)

    findings = []
    if matched:
        findings.append({
            "category": "Impersonation Detection",
            "severity": "danger",
            "description": f"Detected {len(matched)} impersonation indicator(s)",
            "details": matched,
        })

    return {
        "score": score,
        "matched": matched,
        "findings": findings,
    }

def _detect_social_engineering(text: str) -> dict:
    matched = []
    for phrase in SOCIAL_ENGINEERING_PHRASES:
        if phrase.lower() in text:
            matched.append(phrase)

    for phrase in AUTHORITY_PHRASES:
        if phrase.lower() in text:
            matched.append(f'Authority manipulation: "{phrase}"')

    for phrase in FEAR_PHRASES:
        if phrase.lower() in text:
            matched.append(f'Fear-based pressure: "{phrase}"')

    for phrase in REWARD_PHRASES:
        if phrase.lower() in text:
            matched.append(f'Reward/lure: "{phrase}"')

    score = min(100, len(matched) * 12)

    findings = []
    if matched:
        findings.append({
            "category": "Social Engineering",
            "severity": "danger" if score > 60 else "warning",
            "description": f"Found {len(matched)} social engineering technique(s)",
            "details": matched,
        })

    return {
        "score": score,
        "matched": matched,
        "findings": findings,
    }

def _detect_bec(text: str, from_data: dict) -> dict:
    matched = []
    for pattern in BEC_PATTERNS:
        if pattern.lower() in text:
            matched.append(pattern)

    payment_patterns = [
        'wire transfer', 'bank transfer', 'update bank details', 'new payment instructions',
        'change of account', 'updated routing number', 'revised payment', 'pay the attached invoice',
        'purchase gift cards', 'buy itunes cards', 'google play cards',
    ]
    for p in payment_patterns:
        if p in text:
            matched.append(f'Payment diversion: "{p}"')

    score = min(100, len(matched) * 20)

    findings = []
    if matched:
        findings.append({
            "category": "Business Email Compromise",
            "severity": "danger",
            "description": f"Detected {len(matched)} BEC indicator(s) — possible financial fraud attempt",
            "details": matched,
        })

    return {
        "score": score,
        "matched": matched,
        "findings": findings,
    }

def _analyze_sentiment(text: str) -> dict:
    fear = 0
    urgency = 0
    authority = 0
    reward = 0

    for p in FEAR_PHRASES:
        if p.lower() in text:
            fear += 20
    for p in URGENCY_PHRASES:
        if p.lower() in text:
            urgency += 15
    for p in AUTHORITY_PHRASES:
        if p.lower() in text:
            authority += 18
    for p in REWARD_PHRASES:
        if p.lower() in text:
            reward += 15

    manipulation = min(100, (fear + urgency + authority + reward) / 4)

    return {
        "fearScore": min(100, fear),
        "urgencyScore": min(100, urgency),
        "authorityScore": min(100, authority),
        "rewardScore": min(100, reward),
        "manipulationScore": round(manipulation),
    }

def _calculate_nlp_score(scores: dict) -> int:
    weights = {
        "urgencyScore": 0.20,
        "phishingScore": 0.25,
        "impersonationScore": 0.20,
        "socialEngineeringScore": 0.15,
        "becScore": 0.15,
        "sentimentScore": 0.05,
    }
    total = sum((scores.get(k, 0) * w) for k, w in weights.items())
    max_signal = max(scores.values()) if scores else 0
    total = max(total, max_signal * 0.6)
    return round(min(100, total))

def _classify_by_nlp(score: int, findings: list) -> str:
    has_bec = any(f.get("category") == "Business Email Compromise" for f in findings)
    has_imp = any(f.get("category") == "Impersonation Detection" for f in findings)

    if has_bec and score > 40:
        return "fraud"
    if has_imp and score > 30:
        return "impersonation"
    if score >= 65:
        return "phishing"
    if score >= 35:
        return "suspicious"
    return "legitimate"

def _get_brand_domains(brand: str) -> list:
    mapping = {
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
    }
    return mapping.get(brand, [brand.lower().replace(" ", "") + ".com"])
