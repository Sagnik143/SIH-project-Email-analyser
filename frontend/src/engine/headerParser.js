/**
 * Email Header Parser
 * Parses raw email headers (RFC 822) and extracts structured data
 * including Received chain, authentication headers, and sender info.
 */

/**
 * Parse raw email content into structured headers + body
 */
export function parseEmail(rawEmail) {
  const lines = rawEmail.replace(/\r\n/g, '\n').split('\n');
  const headers = {};
  const receivedHeaders = [];
  let currentHeader = '';
  let currentValue = '';
  let bodyStartIndex = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Empty line separates headers from body
    if (line.trim() === '' && bodyStartIndex === -1) {
      if (currentHeader) {
        addHeader(headers, receivedHeaders, currentHeader, currentValue.trim());
      }
      bodyStartIndex = i + 1;
      break;
    }

    // Continuation of previous header (starts with whitespace)
    if (line.match(/^\s+/) && currentHeader) {
      currentValue += ' ' + line.trim();
      continue;
    }

    // New header
    const headerMatch = line.match(/^([A-Za-z0-9-]+):\s*(.*)/);
    if (headerMatch) {
      if (currentHeader) {
        addHeader(headers, receivedHeaders, currentHeader, currentValue.trim());
      }
      currentHeader = headerMatch[1];
      currentValue = headerMatch[2];
    }
  }

  // If no empty line found, the whole thing is headers
  if (bodyStartIndex === -1 && currentHeader) {
    addHeader(headers, receivedHeaders, currentHeader, currentValue.trim());
    bodyStartIndex = lines.length;
  }

  const body = bodyStartIndex >= 0 ? lines.slice(bodyStartIndex).join('\n').trim() : '';

  const getH = (names) => {
    const lowerNames = (Array.isArray(names) ? names : [names]).map(n => n.toLowerCase());
    for (const [k, v] of Object.entries(headers)) {
      if (lowerNames.includes(k.toLowerCase())) {
        return Array.isArray(v) ? v.join('\n') : String(v || '');
      }
    }
    return '';
  };

  return {
    headers,
    receivedHeaders,
    body,
    from: parseAddressField(getH(['From'])),
    to: parseAddressField(getH(['To'])),
    subject: getH(['Subject']) || '(No Subject)',
    date: getH(['Date']),
    messageId: getH(['Message-ID', 'Message-Id']),
    returnPath: getH(['Return-Path']),
    replyTo: getH(['Reply-To']),
    xOriginatingIp: getH(['X-Originating-IP']),
    contentType: getH(['Content-Type']),
    authenticationResults: getH(['Authentication-Results', 'X-Authentication-Results', 'ARC-Authentication-Results']),
    dkimSignature: getH(['DKIM-Signature', 'X-DKIM-Signature']),
    receivedSpf: getH(['Received-SPF', 'X-Received-SPF']),
  };
}

function addHeader(headers, receivedHeaders, name, value) {
  const lowerName = name.toLowerCase();
  if (lowerName === 'received') {
    receivedHeaders.push(value);
  }
  // Store with original case
  if (headers[name]) {
    if (Array.isArray(headers[name])) {
      headers[name].push(value);
    } else {
      headers[name] = [headers[name], value];
    }
  } else {
    headers[name] = value;
  }
}

/**
 * Parse email address field like "John Doe <john@example.com>"
 */
export function parseAddressField(field) {
  if (!field) return { name: '', email: '', raw: '' };

  const match = field.match(/^"?([^"<]*)"?\s*<([^>]+)>/);
  if (match) {
    return { name: match[1].trim(), email: match[2].trim().toLowerCase(), raw: field };
  }

  const emailOnly = field.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (emailOnly) {
    return { name: '', email: emailOnly[1].toLowerCase(), raw: field };
  }

  return { name: field.trim(), email: '', raw: field };
}

/**
 * Extract all IP addresses from Received headers
 */
export function extractIPs(receivedHeaders) {
  const ips = [];
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;

  for (const header of receivedHeaders) {
    const v4matches = header.match(ipRegex) || [];
    const v6matches = header.match(ipv6Regex) || [];

    for (const ip of [...v4matches, ...v6matches]) {
      if (!isPrivateIP(ip) && !ips.includes(ip)) {
        ips.push(ip);
      }
    }
  }

  return ips;
}

/**
 * Check if an IP is private/reserved
 */
export function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;

  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 0) ||
    (parts[0] === 169 && parts[1] === 254)
  );
}

/**
 * Reconstruct SMTP relay path from Received headers
 */
export function reconstructRelayPath(receivedHeaders) {
  const hops = [];

  // Received headers are in reverse order (latest first)
  const reversed = [...receivedHeaders].reverse();

  for (let i = 0; i < reversed.length; i++) {
    const header = reversed[i];
    const hop = parseReceivedHeader(header);
    hop.hopNumber = i + 1;
    hops.push(hop);
  }

  return hops;
}

/**
 * Parse a single Received header
 */
function parseReceivedHeader(header) {
  const fromMatch = header.match(/from\s+([^\s(]+)/i);
  const byMatch = header.match(/by\s+([^\s(]+)/i);
  const withMatch = header.match(/with\s+(\S+)/i);
  const dateMatch = header.match(/;\s*(.+)$/);
  const ipMatch = header.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  const ipMatch2 = header.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);

  return {
    from: fromMatch ? fromMatch[1] : 'unknown',
    by: byMatch ? byMatch[1] : 'unknown',
    protocol: withMatch ? withMatch[1] : 'SMTP',
    timestamp: dateMatch ? dateMatch[1].trim() : '',
    ip: ipMatch ? ipMatch[1] : (ipMatch2 ? ipMatch2[1] : ''),
    raw: header,
  };
}

/**
 * Detect header anomalies
 */
export function detectHeaderAnomalies(parsedEmail) {
  const anomalies = [];

  // Check From vs Return-Path mismatch
  if (parsedEmail.returnPath && parsedEmail.from.email) {
    const returnPathEmail = parseAddressField(parsedEmail.returnPath).email;
    if (returnPathEmail && returnPathEmail !== parsedEmail.from.email) {
      const returnDomain = returnPathEmail.split('@')[1];
      const fromDomain = parsedEmail.from.email.split('@')[1];
      if (returnDomain !== fromDomain) {
        anomalies.push({
          type: 'FROM_RETURN_PATH_MISMATCH',
          severity: 'high',
          description: `From domain (${fromDomain}) does not match Return-Path domain (${returnDomain})`,
          details: { from: parsedEmail.from.email, returnPath: returnPathEmail }
        });
      }
    }
  }

  // Check Reply-To mismatch
  if (parsedEmail.replyTo) {
    const replyToEmail = parseAddressField(parsedEmail.replyTo).email;
    if (replyToEmail && parsedEmail.from.email) {
      const replyDomain = replyToEmail.split('@')[1];
      const fromDomain = parsedEmail.from.email.split('@')[1];
      if (replyDomain !== fromDomain) {
        anomalies.push({
          type: 'REPLY_TO_MISMATCH',
          severity: 'high',
          description: `Reply-To domain (${replyDomain}) differs from From domain (${fromDomain})`,
          details: { from: parsedEmail.from.email, replyTo: replyToEmail }
        });
      }
    }
  }

  // Check for X-Originating-IP (often indicates webmail)
  if (parsedEmail.xOriginatingIp) {
    anomalies.push({
      type: 'X_ORIGINATING_IP',
      severity: 'info',
      description: `Email originated from IP: ${parsedEmail.xOriginatingIp.replace(/[\[\]]/g, '')}`,
      details: { ip: parsedEmail.xOriginatingIp }
    });
  }

  // Check for too many hops (possible relay chain manipulation)
  if (parsedEmail.receivedHeaders.length > 10) {
    anomalies.push({
      type: 'EXCESSIVE_HOPS',
      severity: 'medium',
      description: `Unusually long relay chain (${parsedEmail.receivedHeaders.length} hops)`,
      details: { hopCount: parsedEmail.receivedHeaders.length }
    });
  }

  // Check for missing essential headers
  if (!parsedEmail.messageId) {
    anomalies.push({
      type: 'MISSING_MESSAGE_ID',
      severity: 'medium',
      description: 'Missing Message-ID header — common in spoofed or auto-generated emails',
    });
  }

  // Check if From uses a display name that looks like an email
  if (parsedEmail.from.name && parsedEmail.from.name.includes('@')) {
    anomalies.push({
      type: 'DISPLAY_NAME_EMAIL',
      severity: 'high',
      description: 'Display name contains an email address — common impersonation technique',
      details: { displayName: parsedEmail.from.name, actualEmail: parsedEmail.from.email }
    });
  }

  return anomalies;
}
