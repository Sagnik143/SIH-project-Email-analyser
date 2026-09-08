"""
Email Header Parser
Parses raw email content (RFC 822) and extracts structured headers,
received relay chain, originating IPs, and detects header anomalies.
"""

import re
import email
from email import policy
from email.parser import Parser

def parse_email(raw_email: str) -> dict:
    lines = raw_email.replace('\r\n', '\n').split('\n')
    headers = {}
    received_headers = []
    current_header = ""
    current_value = ""
    body_start_index = -1

    for i, line in enumerate(lines):
        if line.strip() == "" and body_start_index == -1:
            if current_header:
                _add_header(headers, received_headers, current_header, current_value.strip())
            body_start_index = i + 1
            break

        if re.match(r'^\s+', line) and current_header:
            current_value += " " + line.strip()
            continue

        match = re.match(r'^([A-Za-z0-9-]+):\s*(.*)', line)
        if match:
            if current_header:
                _add_header(headers, received_headers, current_header, current_value.strip())
            current_header = match.group(1)
            current_value = match.group(2)

    if body_start_index == -1 and current_header:
        _add_header(headers, received_headers, current_header, current_value.strip())
        body_start_index = len(lines)

    body = "\n".join(lines[body_start_index:]).strip() if body_start_index >= 0 else ""

    def _get_h(target_names):
        if isinstance(target_names, str):
            target_names = [target_names]
        lower_targets = [t.lower() for t in target_names]
        for k, v in headers.items():
            if k.lower() in lower_targets:
                if isinstance(v, list):
                    return "\n".join(str(item) for item in v)
                return str(v)
        return ""

    from_header = _get_h(['From'])
    to_header = _get_h(['To'])
    subject_header = _get_h(['Subject']) or '(No Subject)'
    date_header = _get_h(['Date'])
    message_id = _get_h(['Message-ID', 'Message-Id'])
    return_path = _get_h(['Return-Path'])
    reply_to = _get_h(['Reply-To'])
    x_orig_ip = _get_h(['X-Originating-IP'])
    content_type = _get_h(['Content-Type'])
    auth_results = _get_h(['Authentication-Results', 'X-Authentication-Results', 'ARC-Authentication-Results'])
    dkim_sig = _get_h(['DKIM-Signature', 'X-DKIM-Signature'])
    received_spf = _get_h(['Received-SPF', 'X-Received-SPF'])

    return {
        "headers": headers,
        "receivedHeaders": received_headers,
        "body": body,
        "from": parse_address_field(from_header),
        "to": parse_address_field(to_header),
        "subject": subject_header,
        "date": date_header,
        "messageId": message_id,
        "returnPath": return_path,
        "replyTo": reply_to,
        "xOriginatingIp": x_orig_ip,
        "contentType": content_type,
        "authenticationResults": auth_results,
        "dkimSignature": dkim_sig,
        "receivedSpf": received_spf,
    }

def _add_header(headers: dict, received_headers: list, name: str, value: str):
    if name.lower() == 'received':
        received_headers.append(value)
    if name in headers:
        if isinstance(headers[name], list):
            headers[name].append(value)
        else:
            headers[name] = [headers[name], value]
    else:
        headers[name] = value

def parse_address_field(field: str) -> dict:
    if not field:
        return {"name": "", "email": "", "raw": ""}
    
    match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', field)
    if match:
        return {
            "name": match.group(1).strip(),
            "email": match.group(2).strip().lower(),
            "raw": field,
        }
    
    email_only = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', field)
    if email_only:
        return {
            "name": "",
            "email": email_only.group(1).lower(),
            "raw": field,
        }
    
    return {
        "name": field.strip(),
        "email": "",
        "raw": field,
    }

def is_private_ip(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 0:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
        return False
    except Exception:
        return False

def extract_ips(received_headers: list) -> list:
    ips = []
    ip_regex = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ipv6_regex = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'

    for header in received_headers:
        v4matches = re.findall(ip_regex, header)
        v6matches = re.findall(ipv6_regex, header)

        for ip in v4matches + v6matches:
            if not is_private_ip(ip) and ip not in ips:
                ips.append(ip)

    return ips

def reconstruct_relay_path(received_headers: list) -> list:
    hops = []
    reversed_headers = list(reversed(received_headers))

    for i, header in enumerate(reversed_headers):
        hop = _parse_received_header(header)
        hop["hopNumber"] = i + 1
        hops.append(hop)

    return hops

def _parse_received_header(header: str) -> dict:
    from_match = re.search(r'from\s+([^\s(]+)', header, re.IGNORECASE)
    by_match = re.search(r'by\s+([^\s(]+)', header, re.IGNORECASE)
    with_match = re.search(r'with\s+(\S+)', header, re.IGNORECASE)
    date_match = re.search(r';\s*(.+)$', header)
    ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
    ip_match2 = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', header)

    ip = ip_match.group(1) if ip_match else (ip_match2.group(1) if ip_match2 else "")

    return {
        "from": from_match.group(1) if from_match else "unknown",
        "by": by_match.group(1) if by_match else "unknown",
        "protocol": with_match.group(1) if with_match else "SMTP",
        "timestamp": date_match.group(1).strip() if date_match else "",
        "ip": ip,
        "raw": header,
    }

def detect_header_anomalies(parsed_email: dict) -> list:
    anomalies = []

    # From vs Return-Path mismatch
    from_email = parsed_email.get("from", {}).get("email", "")
    return_path_raw = parsed_email.get("returnPath", "")
    if return_path_raw and from_email:
        ret_parsed = parse_address_field(return_path_raw)
        return_email = ret_parsed.get("email", "")
        if return_email and return_email != from_email:
            from_domain = from_email.split("@")[1] if "@" in from_email else ""
            ret_domain = return_email.split("@")[1] if "@" in return_email else ""
            if from_domain and ret_domain and from_domain != ret_domain:
                anomalies.append({
                    "type": "FROM_RETURN_PATH_MISMATCH",
                    "severity": "high",
                    "description": f"From domain ({from_domain}) does not match Return-Path domain ({ret_domain})",
                    "details": {"from": from_email, "returnPath": return_email}
                })

    # Reply-To mismatch
    reply_to_raw = parsed_email.get("replyTo", "")
    if reply_to_raw and from_email:
        reply_parsed = parse_address_field(reply_to_raw)
        reply_email = reply_parsed.get("email", "")
        if reply_email and reply_email != from_email:
            from_domain = from_email.split("@")[1] if "@" in from_email else ""
            reply_domain = reply_email.split("@")[1] if "@" in reply_email else ""
            if from_domain and reply_domain and from_domain != reply_domain:
                anomalies.append({
                    "type": "REPLY_TO_MISMATCH",
                    "severity": "high",
                    "description": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
                    "details": {"from": from_email, "replyTo": reply_email}
                })

    # X-Originating-IP
    x_orig = parsed_email.get("xOriginatingIp", "")
    if x_orig:
        clean_ip = re.sub(r'[\[\]]', '', x_orig)
        anomalies.append({
            "type": "X_ORIGINATING_IP",
            "severity": "info",
            "description": f"Email originated from webmail IP: {clean_ip}",
            "details": {"ip": clean_ip}
        })

    # Excessive hops
    rec_headers = parsed_email.get("receivedHeaders", [])
    if len(rec_headers) > 10:
        anomalies.append({
            "type": "EXCESSIVE_HOPS",
            "severity": "medium",
            "description": f"Unusually long relay chain ({len(rec_headers)} hops)",
            "details": {"hopCount": len(rec_headers)}
        })

    # Missing essential headers
    if not parsed_email.get("messageId"):
        anomalies.append({
            "type": "MISSING_MESSAGE_ID",
            "severity": "medium",
            "description": "Email is missing standard Message-ID header",
            "details": {}
        })

    if not parsed_email.get("date"):
        anomalies.append({
            "type": "MISSING_DATE",
            "severity": "low",
            "description": "Email is missing Date header",
            "details": {}
        })

    return anomalies
