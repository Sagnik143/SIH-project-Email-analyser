"""
IP Intelligence Module
Performs IP geolocation lookups via ip-api.com, proxy/hosting detection,
cloud infrastructure classification, and risk evaluation.
"""

import httpx
import asyncio

async def lookup_ip(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query", ip),
                        "country": data.get("country", "Unknown"),
                        "countryCode": data.get("countryCode", "XX"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "timezone": data.get("timezone", ""),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "as": data.get("as", ""),
                        "asName": data.get("asname", ""),
                        "reverse": data.get("reverse", ""),
                        "isMobile": bool(data.get("mobile")),
                        "isProxy": bool(data.get("proxy")),
                        "isHosting": bool(data.get("hosting")),
                        "riskIndicators": _assess_ip_risk(data),
                        "error": None,
                    }
                else:
                    return _create_fallback_result(ip, data.get("message", "Lookup failed"))
            else:
                return _create_fallback_result(ip, f"HTTP status {response.status_code}")
    except Exception as e:
        return _create_fallback_result(ip, str(e))

async def batch_lookup_ips(ips: list) -> list:
    results = []
    for i, ip in enumerate(ips):
        if i > 0:
            await asyncio.sleep(0.3)
        res = await lookup_ip(ip)
        results.append(res)
    return results

def _assess_ip_risk(data: dict) -> list:
    indicators = []

    if data.get("proxy"):
        indicators.append({
            "type": "PROXY_VPN",
            "severity": "high",
            "description": "IP is associated with a proxy, VPN, or anonymization gateway"
        })

    if data.get("hosting"):
        indicators.append({
            "type": "HOSTING_PROVIDER",
            "severity": "medium",
            "description": f"IP belongs to a hosting/cloud provider ({data.get('org') or data.get('isp')})"
        })

    cloud_provider = _detect_cloud_provider(data.get("org", ""), data.get("isp", ""), data.get("as", ""))
    if cloud_provider:
        indicators.append({
            "type": "CLOUD_INFRASTRUCTURE",
            "severity": "medium",
            "description": f"IP hosted on {cloud_provider} infrastructure"
        })

    if _is_tor_indicator(data.get("org", ""), data.get("isp", ""), data.get("reverse", "")):
        indicators.append({
            "type": "TOR_EXIT",
            "severity": "critical",
            "description": "IP matches known TOR exit node or relay signature"
        })

    high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'UA', 'BY']
    if data.get("countryCode") in high_risk_countries:
        indicators.append({
            "type": "HIGH_RISK_COUNTRY",
            "severity": "medium",
            "description": f"IP originates from high-risk jurisdiction: {data.get('country')}"
        })

    return indicators

def _detect_cloud_provider(org: str, isp: str, as_field: str) -> str:
    combined = f"{org} {isp} {as_field}".lower()
    if 'amazon' in combined or 'aws' in combined or 'ec2' in combined:
        return 'Amazon Web Services (AWS)'
    if 'microsoft' in combined or 'azure' in combined:
        return 'Microsoft Azure'
    if 'google' in combined or 'gcp' in combined:
        return 'Google Cloud Platform'
    if 'digitalocean' in combined:
        return 'DigitalOcean'
    if 'linode' in combined or 'akamai' in combined:
        return 'Linode/Akamai'
    if 'ovh' in combined:
        return 'OVH'
    if 'hetzner' in combined:
        return 'Hetzner'
    if 'cloudflare' in combined:
        return 'Cloudflare'
    return ""

def _is_tor_indicator(org: str, isp: str, reverse: str) -> bool:
    combined = f"{org} {isp} {reverse}".lower()
    return 'tor' in combined or 'exit' in combined or 'relay' in combined

def _create_fallback_result(ip: str, err: str) -> dict:
    return {
        "ip": ip,
        "country": "Unknown",
        "countryCode": "XX",
        "region": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "timezone": "",
        "isp": "Unknown",
        "org": "Unknown",
        "as": "",
        "asName": "",
        "reverse": "",
        "isMobile": False,
        "isProxy": False,
        "isHosting": False,
        "riskIndicators": [],
        "error": err,
    }

def calculate_ip_risk_score(ip_result: dict) -> int:
    if not ip_result or ip_result.get("error"):
        return 30
    score = 0
    for ind in ip_result.get("riskIndicators", []):
        sev = ind.get("severity")
        if sev == "critical":
            score += 40
        elif sev == "high":
            score += 30
        elif sev == "medium":
            score += 15
        elif sev == "low":
            score += 5
    return min(100, score)
