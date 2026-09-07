/**
 * Relay Tracer: Analyzes Received: headers and reconstructs SMTP relay hops
 */

// Regex helpers for IPv4 and IPv6
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const IPV6_REGEX = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*/;

export function isPrivateIP(ip) {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

/**
 * Parses and orders the Received headers in chronological order (hop 1 = origin, hop N = final recipient MX)
 */
export function traceRelayHops(rawHeadersMap, headerLines = []) {
  // Received headers in rawHeadersMap are top-to-bottom (newest to oldest).
  // In SMTP, newest hop is prepended at the top.
  // Therefore, chronologically: bottom = first hop (origin), top = last hop.
  
  let receivedHeaders = [];
  
  if (rawHeadersMap['received']) {
    receivedHeaders = [...rawHeadersMap['received']];
  } else if (headerLines.length > 0) {
    receivedHeaders = headerLines
      .filter(h => h.key.toLowerCase() === 'received')
      .map(h => h.line.replace(/^received:\s*/i, ''));
  }

  // Reverse to chronological order (Hop 1 = origin)
  const chronological = [...receivedHeaders].reverse();

  const hops = chronological.map((rec, index) => {
    return parseSingleReceivedHeader(rec, index + 1);
  });

  // Calculate transit delay between consecutive hops
  for (let i = 0; i < hops.length; i++) {
    if (i === 0) {
      hops[i].transitDelaySeconds = 0;
    } else {
      const prev = hops[i - 1];
      const curr = hops[i];
      if (prev.timestamp && curr.timestamp) {
        const diffMs = curr.timestamp.getTime() - prev.timestamp.getTime();
        hops[i].transitDelaySeconds = Math.max(0, Math.round(diffMs / 1000));
      } else {
        hops[i].transitDelaySeconds = null;
      }
    }
  }

  // Identify observed / claimed earlier origin IP
  // Note (Phase 1): Header fields such as X-Originating-IP or early Received entries
  // represent claims present in uploaded data and are UNVERIFIED.
  let originatingIP = null;
  let originSource = 'earliest_received_hop';
  let isUnverifiedHeaderClaim = true;

  const xOriginatingIP = rawHeadersMap['x-originating-ip']?.[0] || 
                         rawHeadersMap['x-sender-ip']?.[0] ||
                         rawHeadersMap['x-client-ip']?.[0];

  if (xOriginatingIP) {
    const match = xOriginatingIP.match(IPV4_REGEX);
    if (match && !isPrivateIP(match[0])) {
      originatingIP = match[0];
      originSource = 'unverified_x_originating_header';
      isUnverifiedHeaderClaim = true;
    }
  }

  // If not found, find the earliest public IP recorded in the Received chain
  if (!originatingIP) {
    for (const hop of hops) {
      if (hop.ip && !hop.isPrivate) {
        originatingIP = hop.ip;
        hop.isOriginHop = true;
        break;
      }
    }
  } else {
    // Mark the hop matching originating IP if present
    const matchedHop = hops.find(h => h.ip === originatingIP);
    if (matchedHop) matchedHop.isOriginHop = true;
  }

  // Earliest trustworthy sending infrastructure is the earliest public hop observed
  // in the Received chain (not blindly trusting synthetic X-Originating-IP)
  const earliestPublicHop = hops.find(h => h.ip && !h.isPrivate);
  const earliestTrustworthySendingInfrastructure = earliestPublicHop ? earliestPublicHop.ip : (hops[0]?.ip || 'Unknown');

  // Total transit time calculation
  let totalTransitTimeSeconds = 0;
  if (hops.length >= 2) {
    const firstHop = hops[0];
    const lastHop = hops[hops.length - 1];
    if (firstHop.timestamp && lastHop.timestamp) {
      totalTransitTimeSeconds = Math.max(0, Math.round((lastHop.timestamp.getTime() - firstHop.timestamp.getTime()) / 1000));
    }
  }

  const resolvedOrigin = originatingIP || (hops[0]?.ip || 'Unknown');

  return {
    totalHops: hops.length,
    originatingIP: resolvedOrigin, // Retained for backward compatibility
    claimedOriginatingIP: resolvedOrigin,
    originatingIPStatus: 'UNVERIFIED',
    originatingIPLabel: 'Claimed Earlier Origin (UNVERIFIED)',
    originSource,
    isUnverifiedHeaderClaim,
    earliestTrustworthySendingInfrastructure,
    totalTransitTimeSeconds,
    hops
  };
}

function parseSingleReceivedHeader(raw, hopNumber) {
  // Typical RFC format: "from mail.example.com (mail.example.com [198.51.100.1]) by mx.google.com with ESMTPS id ... for <victim@domain.com>; Wed, 5 Sep 2026 06:12:00 +0000"
  let fromHost = '';
  let byHost = '';
  let protocol = 'SMTP';
  let dateStr = '';
  let ip = null;
  let tlsCipher = null;
  let queueId = null;

  // Extract date after semicolon
  const semiIndex = raw.lastIndexOf(';');
  if (semiIndex !== -1) {
    dateStr = raw.substring(semiIndex + 1).trim();
  }

  // Extract from
  const fromMatch = raw.match(/from\s+([^\s;()]+)(?:\s*\(([^)]+)\))?/i);
  if (fromMatch) {
    fromHost = fromMatch[1];
    const bracketContent = fromMatch[2] || '';
    // Look for IP in the bracket content or from segment
    const ipMatch = bracketContent.match(IPV4_REGEX) || bracketContent.match(IPV6_REGEX);
    if (ipMatch) {
      ip = ipMatch[0];
    }
  }

  // If no IP found in from bracket, search raw line
  if (!ip) {
    const anyIpMatch = raw.match(IPV4_REGEX) || raw.match(IPV6_REGEX);
    if (anyIpMatch) ip = anyIpMatch[0];
  }

  // Extract by
  const byMatch = raw.match(/by\s+([^\s;()]+)/i);
  if (byMatch) {
    byHost = byMatch[1];
  }

  // Extract with
  const withMatch = raw.match(/with\s+([A-Za-z0-9_-]+)/i);
  if (withMatch) {
    protocol = withMatch[1].toUpperCase();
  }

  // Extract TLS info
  const tlsMatch = raw.match(/(using\s+TLS[^\s;,)]+|version=TLS[^\s;,)]+)/i);
  if (tlsMatch) {
    tlsCipher = tlsMatch[1];
  } else if (protocol.includes('ESMTPS') || protocol.includes('TLS')) {
    tlsCipher = 'TLS Encrypted';
  }

  // Extract queue id
  const idMatch = raw.match(/id\s+([^\s;]+)/i);
  if (idMatch) {
    queueId = idMatch[1];
  }

  // Parse Date
  let timestamp = null;
  if (dateStr) {
    const d = new Date(dateStr);
    if (!isNaN(d.getTime())) {
      timestamp = d;
    }
  }

  const isPrivate = isPrivateIP(ip);

  return {
    hopNumber,
    rawText: raw.trim(),
    fromHost: fromHost || 'Unknown',
    byHost: byHost || 'Unknown',
    ip: ip || null,
    isPrivate,
    protocol,
    tlsCipher,
    queueId,
    timestamp,
    timestampISO: timestamp ? timestamp.toISOString() : null,
    isOriginHop: false
  };
}
