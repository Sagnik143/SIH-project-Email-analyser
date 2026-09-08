"""
Analyze Router
Provides POST /api/analyze endpoint for end-to-end email threat analysis.
"""

from fastapi import APIRouter, HTTPException
import time
from datetime import datetime
from models.request_models import EmailAnalyzeRequest
from data.database import save_report

from engine.header_parser import (
    parse_email,
    extract_ips,
    reconstruct_relay_path,
    detect_header_anomalies,
)
from engine.auth_validator import validate_authentication
from engine.nlp_analyzer import analyze_email_content
from engine.link_analyzer import analyze_links
from engine.ip_intelligence import batch_lookup_ips
from engine.domain_intelligence import analyze_domain
from engine.threat_scorer import calculate_threat_score

router = APIRouter(prefix="/api", tags=["Analysis"])

@router.post("/analyze")
async def analyze_email_endpoint(payload: EmailAnalyzeRequest):
    raw_email = payload.raw
    if not raw_email or not raw_email.strip():
        raise HTTPException(status_code=400, detail="Empty email content provided")

    try:
        # Step 1: Parse headers
        parsed = parse_email(raw_email)

        # Step 2: Extract IPs and relay path
        ips = extract_ips(parsed.get("receivedHeaders", []))
        relay_path = reconstruct_relay_path(parsed.get("receivedHeaders", []))
        header_anomalies = detect_header_anomalies(parsed)

        # Step 3: Authentication validation
        auth_result = validate_authentication(parsed)

        # Step 4: NLP content analysis
        subject = parsed.get("subject", "")
        body = parsed.get("body", "")
        from_dict = parsed.get("from", {})
        nlp_result = analyze_email_content(subject, body, from_dict)

        # Step 5: Link analysis
        link_result = analyze_links(body)

        # Step 6: IP geolocation (limit to first 5 IPs)
        ip_results = await batch_lookup_ips(ips[:5])

        # Step 7: Domain intelligence
        from_email = from_dict.get("email", "")
        sender_domain = from_email.split("@")[1] if "@" in from_email else ""
        domain_result = analyze_domain(sender_domain)

        # Step 8: Unified threat assessment
        analysis_context = {
            "headerAnomalies": header_anomalies,
            "authResult": auth_result,
            "nlpResult": nlp_result,
            "linkResult": link_result,
            "ipResults": ip_results,
            "domainResult": domain_result,
        }
        threat_assessment = calculate_threat_score(analysis_context)

        analysis_id = f"EMAIL-{int(time.time() * 1000)}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        result = {
            "id": analysis_id,
            "timestamp": timestamp,
            "raw": raw_email,
            "parsed": parsed,
            "ips": ips,
            "relayPath": relay_path,
            "headerAnomalies": header_anomalies,
            "authResult": auth_result,
            "nlpResult": nlp_result,
            "linkResult": link_result,
            "ipResults": ip_results,
            "domainResult": domain_result,
            "threatAssessment": threat_assessment,
        }

        # Auto-save report in database
        save_report(result)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")
