"""
Threat Scorer
Aggregates authentication results, NLP detection, link indicators, header anomalies,
IP geolocation risk, and domain reputation into an overall threat assessment.
"""

def calculate_threat_score(analysis_results: dict) -> dict:
    header_anomalies = analysis_results.get("headerAnomalies", [])
    auth_result = analysis_results.get("authResult", {})
    nlp_result = analysis_results.get("nlpResult", {})
    link_result = analysis_results.get("linkResult", {})
    ip_results = analysis_results.get("ipResults", [])
    domain_result = analysis_results.get("domainResult", {})

    scores = {
        "authentication": 100 - (auth_result.get("overallScore") or 50),
        "nlp": nlp_result.get("nlpScore") or 0,
        "links": link_result.get("overallScore") or 0,
        "headerAnomalies": min(100, len(header_anomalies) * 20),
        "ipRisk": _calculate_aggregate_ip_risk(ip_results),
        "domainRisk": 100 - (domain_result.get("reputationScore") or 50) if domain_result else 50,
    }

    weights = {
        "authentication": 0.20,
        "nlp": 0.30,
        "links": 0.15,
        "headerAnomalies": 0.15,
        "ipRisk": 0.10,
        "domainRisk": 0.10,
    }

    weighted_score = sum(scores[k] * weights[k] for k in weights)
    threat_score = round(min(100, weighted_score))

    classification = _classify_threat(threat_score, analysis_results)
    confidence = _calculate_confidence(scores)
    risk_level = _get_risk_level(threat_score)
    summary = _generate_threat_summary(threat_score, classification, scores)
    recommendation = _get_recommendation(threat_score, classification)
    all_findings = _collect_findings(analysis_results)

    return {
        "threatScore": threat_score,
        "classification": classification,
        "confidence": confidence,
        "scores": scores,
        "summary": summary,
        "findings": all_findings,
        "riskLevel": risk_level,
        "recommendation": recommendation,
    }

def _calculate_aggregate_ip_risk(ip_results: list) -> int:
    if not ip_results:
        return 20
    max_risk = 0
    for ip in ip_results:
        risk = 0
        if ip.get("isProxy"):
            risk += 40
        if ip.get("isHosting"):
            risk += 20
        for ind in ip.get("riskIndicators", []):
            sev = ind.get("severity")
            if sev == "critical":
                risk += 40
            elif sev == "high":
                risk += 25
            elif sev == "medium":
                risk += 10
        max_risk = max(max_risk, min(100, risk))
    return max_risk

def _classify_threat(score: int, results: dict) -> str:
    nlp = results.get("nlpResult", {})
    bec_score = nlp.get("bec", {}).get("score", 0)
    imp_score = nlp.get("impersonation", {}).get("score", 0)
    phish_score = nlp.get("phishing", {}).get("score", 0)

    if bec_score > 30 and score > 35:
        return "fraud"
    if imp_score > 30 and score > 30:
        return "impersonation"
    if phish_score > 40 and score > 35:
        return "phishing"
    if score >= 65:
        return "phishing"
    if score >= 35:
        return "suspicious"
    return "legitimate"

def _get_risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "minimal"

def _calculate_confidence(scores: dict) -> int:
    signals = list(scores.values())
    high_count = sum(1 for s in signals if s > 50)
    low_count = sum(1 for s in signals if s < 20)

    if high_count >= 4:
        return 95
    if high_count >= 3:
        return 85
    if low_count >= 4:
        return 90
    if high_count >= 2:
        return 75
    return 65

def _generate_threat_summary(score: int, classification: str, scores: dict) -> str:
    parts = []
    if classification == "fraud":
        parts.append("⚠️ This email exhibits strong indicators of Business Email Compromise (BEC) or financial fraud.")
    elif classification == "impersonation":
        parts.append("🎭 This email shows signs of sender impersonation — the claimed identity does not match the actual sender infrastructure.")
    elif classification == "phishing":
        parts.append("🎣 This email contains multiple phishing indicators including deceptive language and suspicious links.")
    elif classification == "suspicious":
        parts.append("🔍 This email has some suspicious characteristics that warrant further investigation.")
    else:
        parts.append("✅ This email appears legitimate based on available indicators.")

    if scores.get("authentication", 0) > 60:
        parts.append("Email failed critical authentication checks (SPF/DKIM/DMARC).")
    if scores.get("nlp", 0) > 50:
        parts.append("Content analysis detected coercive or deceptive phrasing.")
    if scores.get("links", 0) > 50:
        parts.append("Contains links with high-risk attributes.")

    return " ".join(parts)

def _get_recommendation(score: int, classification: str) -> str:
    if score >= 75:
        return "BLOCK & QUARANTINE: Highly malicious email. Do not interact with links, attachments, or sender."
    if score >= 55:
        return "FLAG & WARN: Suspicious email. Quarantine pending administrator review."
    if score >= 35:
        return "EXERCISE CAUTION: Moderate risk detected. Verify sender identity through out-of-band communication."
    return "DELIVER NORMALLY: Email passed standard verification checks."

def _collect_findings(results: dict) -> list:
    all_findings = []
    
    # Header anomalies
    for a in results.get("headerAnomalies", []):
        all_findings.append({
            "category": "Header Forensics",
            "severity": "danger" if a.get("severity") == "high" else "warning",
            "description": a.get("description", ""),
            "details": [str(a.get("details", {}))]
        })

    # NLP findings
    for f in results.get("nlpResult", {}).get("findings", []):
        all_findings.append(f)

    # Link findings
    for f in results.get("linkResult", {}).get("findings", []):
        all_findings.append(f)

    # Domain findings
    for f in results.get("domainResult", {}).get("findings", []):
        all_findings.append(f)

    return all_findings
