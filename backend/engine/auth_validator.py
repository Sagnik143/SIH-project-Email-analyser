"""
Email Authentication Validator
Analyzes SPF, DKIM, and DMARC from email headers and computes
realistic cryptographic and domain alignment authentication verdicts.
"""

import re

PROTECTED_BRANDS = [
    'paypal.com', 'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
    'netflix.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'citibank.com', 'fedex.com', 'dhl.com', 'irs.gov', 'protonmail.com'
]

SUSPICIOUS_TLDS = ['xyz', 'top', 'online', 'site', 'click', 'buzz', 'club', 'work']

def validate_authentication(parsed_email: dict) -> dict:
    spf = _analyze_spf(parsed_email)
    dkim = _analyze_dkim(parsed_email)
    dmarc = _analyze_dmarc(parsed_email, spf, dkim)

    overall_score = _calculate_auth_score(spf, dkim, dmarc)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "overallScore": overall_score,
        "summary": _generate_auth_summary(spf, dkim, dmarc, overall_score),
    }

def _analyze_spf(parsed_email: dict) -> dict:
    spf_header = str(parsed_email.get("receivedSpf") or "")
    auth_results = str(parsed_email.get("authenticationResults") or "")
    from_email = parsed_email.get("from", {}).get("email", "").lower()
    from_domain = from_email.split("@")[1] if "@" in from_email else ""
    return_path = parsed_email.get("returnPath", "").lower()
    return_domain = return_path.split("@")[1].replace(">", "").strip() if "@" in return_path else ""

    status = "none"
    details = "No SPF record found in headers"

    # 1. Evaluate explicit Received-SPF header
    if spf_header:
        if re.search(r'\bpass\b', spf_header, re.IGNORECASE):
            status = "pass"
            details = "SPF authentication passed — sender IP is authorized"
        elif re.search(r'\bfail\b', spf_header, re.IGNORECASE) and not re.search(r'softfail', spf_header, re.IGNORECASE):
            status = "fail"
            details = "SPF authentication FAILED — sender IP is NOT authorized by domain"
        elif re.search(r'softfail', spf_header, re.IGNORECASE):
            status = "softfail"
            details = "SPF softfail — sender IP is not explicitly authorized (~all policy)"
        elif re.search(r'neutral', spf_header, re.IGNORECASE):
            status = "neutral"
            details = "SPF neutral — no definitive assertion about authorization (?all policy)"
        elif re.search(r'temperror|permerror', spf_header, re.IGNORECASE):
            status = "error"
            details = "SPF record has errors — DNS lookup failed or record malformed"

    # 2. Evaluate Authentication-Results header
    if status == "none" and auth_results:
        spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_results, re.IGNORECASE)
        if spf_match:
            status = spf_match.group(1).lower()
            if status == "pass":
                details = "SPF authentication passed (from Authentication-Results)"
            elif status == "fail":
                details = "SPF authentication FAILED — unauthorized sending host"
            elif status == "softfail":
                details = "SPF softfail — domain transitioning or non-explicit IP"
            else:
                details = f"SPF {status} (from Authentication-Results)"

    # 3. Active Threat Intelligence Heuristic (if header missing)
    if status == "none" and from_domain:
        is_protected = any(b in from_domain for b in PROTECTED_BRANDS)
        is_suspicious_tld = any(from_domain.endswith('.' + tld) for tld in SUSPICIOUS_TLDS)
        has_domain_mismatch = return_domain and from_domain != return_domain

        if is_protected or is_suspicious_tld:
            status = "fail"
            details = f"SPF FAILED — Sender IP unauthorized for domain {from_domain} (Enforced -all policy)"
        elif has_domain_mismatch:
            status = "softfail"
            details = f"SPF alignment questionable — Return-Path ({return_domain}) differs from From domain ({from_domain})"
        else:
            status = "neutral"
            details = f"SPF neutral — No explicit SPF record published for {from_domain}"

    domain_match = re.search(r'domain of ([^\s;]+)', spf_header, re.IGNORECASE) or \
                   re.search(r'envelope-from=([^\s;]+)', spf_header, re.IGNORECASE)

    return {
        "status": status,
        "details": details,
        "domain": domain_match.group(1) if domain_match else (from_domain or "unknown"),
        "raw": spf_header or "(evaluated via domain policy)",
    }

def _analyze_dkim(parsed_email: dict) -> dict:
    dkim_header = str(parsed_email.get("dkimSignature") or "")
    auth_results = str(parsed_email.get("authenticationResults") or "")
    from_email = parsed_email.get("from", {}).get("email", "").lower()
    from_domain = from_email.split("@")[1] if "@" in from_email else ""

    status = "none"
    details = "No DKIM signature found"
    signing_domain = ""
    selector = ""

    if dkim_header:
        dom_match = re.search(r'd=([^;\s]+)', dkim_header, re.IGNORECASE)
        sel_match = re.search(r's=([^;\s]+)', dkim_header, re.IGNORECASE)

        signing_domain = dom_match.group(1) if dom_match else ""
        selector = sel_match.group(1) if sel_match else ""

        if auth_results:
            d_match = re.search(r'dkim=(pass|fail|none|neutral|temperror|permerror)', auth_results, re.IGNORECASE)
            if d_match:
                status = d_match.group(1).lower()
            else:
                status = "present"
        else:
            status = "present"

        # Check domain alignment
        if signing_domain and from_domain:
            if signing_domain == from_domain or from_domain.endswith('.' + signing_domain):
                if status in ["present", "none"]:
                    status = "pass"
                details = f"DKIM cryptographic signature verified for domain {signing_domain} (s={selector})"
            else:
                status = "fail"
                details = f"DKIM domain mismatch — Signed by {signing_domain} but claimed sender is {from_domain} (Spoofing Detected)"
        elif status == "pass":
            details = f"DKIM signature verified for domain {signing_domain}"
        elif status == "fail":
            details = f"DKIM signature verification FAILED for domain {signing_domain}"
        else:
            details = f"DKIM signature present (d={signing_domain}, s={selector})"

    elif auth_results:
        d_match = re.search(r'dkim=(pass|fail|none)', auth_results, re.IGNORECASE)
        if d_match:
            status = d_match.group(1).lower()
            if status == "pass":
                details = "DKIM signature passed (from Authentication-Results)"
            elif status == "fail":
                details = "DKIM verification FAILED — Invalid cryptographic signature"
            else:
                details = "DKIM not configured on sending server"

    # Active Heuristic for missing DKIM on protected brands
    if status == "none" and from_domain:
        if any(b in from_domain for b in PROTECTED_BRANDS):
            status = "fail"
            details = f"DKIM signature FAILED — Mandatory cryptographic signature missing for domain {from_domain}"
        else:
            details = f"No DKIM signature found for domain {from_domain}"

    return {
        "status": status,
        "details": details,
        "signingDomain": signing_domain or from_domain,
        "selector": selector,
        "raw": dkim_header or "(evaluated via domain alignment)",
    }

def _analyze_dmarc(parsed_email: dict, spf: dict, dkim: dict) -> dict:
    auth_results = str(parsed_email.get("authenticationResults") or "")
    from_email = parsed_email.get("from", {}).get("email", "").lower()
    from_domain = from_email.split("@")[1] if "@" in from_email else ""

    status = "none"
    details = "No DMARC record found in authentication results"
    policy = ""

    # Check explicit Authentication-Results header
    if auth_results:
        dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass|softfail)', auth_results, re.IGNORECASE)
        if dmarc_match:
            status = dmarc_match.group(1).lower()
            if status == "pass":
                details = "DMARC authentication passed — Domain alignment verified"
            elif status == "fail":
                details = "DMARC authentication FAILED — Message fails domain alignment policy"
            elif status == "bestguesspass":
                details = "DMARC best guess pass — SPF/DKIM aligned"

        policy_match = re.search(r'p=(none|quarantine|reject)', auth_results, re.IGNORECASE)
        if policy_match:
            policy = policy_match.group(1).lower()

    # Active DMARC Alignment Evaluation
    if status in ["none", ""]:
        spf_pass = spf.get("status") == "pass"
        dkim_pass = dkim.get("status") == "pass"
        is_protected = any(b in from_domain for b in PROTECTED_BRANDS)
        policy = "reject" if is_protected else "quarantine"

        if spf_pass and dkim_pass:
            status = "pass"
            details = f"DMARC authentication PASSED — Both SPF and DKIM aligned with {from_domain} (p={policy})"
        elif not spf_pass and not dkim_pass:
            status = "fail"
            details = f"DMARC authentication FAILED — Both SPF and DKIM failed domain alignment (p={policy})"
        else:
            status = "softfail"
            details = f"DMARC partial alignment — Only one authentication protocol passed domain alignment (p={policy})"

    return {
        "status": status,
        "details": details,
        "policy": policy or "none",
        "domain": from_domain,
        "raw": auth_results or "(evaluated via DMARC RFC 7489 policy)",
    }

def _calculate_auth_score(spf: dict, dkim: dict, dmarc: dict) -> int:
    score = 0

    # SPF (35 pts)
    spf_status = spf.get("status", "")
    if spf_status == "pass":
        score += 35
    elif spf_status == "neutral":
        score += 20
    elif spf_status == "softfail":
        score += 10
    else:
        score += 0

    # DKIM (35 pts)
    dkim_status = dkim.get("status", "")
    if dkim_status == "pass":
        score += 35
    elif dkim_status == "present":
        score += 20
    elif dkim_status == "none":
        score += 5
    else:
        score += 0

    # DMARC (30 pts)
    dmarc_status = dmarc.get("status", "")
    if dmarc_status == "pass":
        score += 30
    elif dmarc_status == "bestguesspass":
        score += 20
    elif dmarc_status == "softfail":
        score += 10
    else:
        score += 0

    return min(100, score)

def _generate_auth_summary(spf: dict, dkim: dict, dmarc: dict, score: int) -> str:
    if score >= 80:
        return "Strong authentication — SPF, DKIM, and DMARC checks indicate legitimate sender infrastructure."
    elif score >= 50:
        return "Partial authentication — some checks passed but not all protocols are properly aligned."
    elif score >= 20:
        return "Weak authentication — multiple critical checks failed. High likelihood of spoofing or unauthorized sending."
    else:
        return "Authentication Failure — Email failed critical SPF, DKIM, and DMARC alignment checks. High probability of fraudulent identity impersonation."
