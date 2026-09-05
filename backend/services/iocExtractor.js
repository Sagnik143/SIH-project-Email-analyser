/**
 * IoC Extractor: Extracts Indicators of Compromise (URLs, Domains, IPs, Hashes)
 */

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
  '.work', '.click', '.live', '.shop', '.icu', '.monster', '.rest',
  '.sbs', '.cyou', '.cfd', '.download', '.kim', '.zip', '.mov'
];

export function extractIoCs(email) {
  const textContent = (email.body?.text || '') + ' ' + (email.body?.html || '');
  
  // Extract all URLs
  const rawUrls = findUrls(textContent);
  const anchorPairs = extractHtmlAnchorPairs(email.body?.html || '');

  const urls = [];
  const domains = new Set();
  const suspiciousUrls = [];

  for (const rawUrl of rawUrls) {
    try {
      const parsed = new URL(rawUrl);
      const hostname = parsed.hostname.toLowerCase();
      domains.add(hostname);

      const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
      const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
      const isShortener = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'rb.gy'].includes(hostname);
      
      const flags = [];
      if (isIpHost) flags.push('Direct IP Address in URL (High Risk - Common in Phishing)');
      if (hasSuspiciousTld) flags.push(`Suspicious TLD (${hostname.substring(hostname.lastIndexOf('.'))}) frequently abused by spammers`);
      if (isShortener) flags.push('URL Shortener Used (Hides True Destination)');
      if (parsed.protocol === 'http:' && !isLocalhost(hostname)) flags.push('Unencrypted Insecure HTTP Protocol for Credential Endpoint');

      // Check if anchor text was deceptive
      const anchor = anchorPairs.find(a => a.href === rawUrl);
      if (anchor && anchor.text) {
        const textUrlMatch = anchor.text.match(/https?:\/\/([^\s/]+)/i);
        if (textUrlMatch) {
          const textDomain = textUrlMatch[1].toLowerCase();
          if (textDomain !== hostname) {
            flags.push(`Deceptive Anchor Text: Display shows "${textDomain}" but link directs to "${hostname}"`);
          }
        }
      }

      const isSuspicious = flags.length > 0;
      const defanged = defangUrl(rawUrl);

      const urlObj = {
        original: rawUrl,
        defanged,
        protocol: parsed.protocol,
        hostname,
        pathname: parsed.pathname,
        isIpHost,
        hasSuspiciousTld,
        isShortener,
        isSuspicious,
        flags
      };

      urls.push(urlObj);
      if (isSuspicious) suspiciousUrls.push(urlObj);
    } catch (e) {
      // Invalid URL format
    }
  }

  // Deduplicate URLs by original
  const uniqueUrls = Array.from(new Map(urls.map(u => [u.original, u])).values());

  // Sender / Relay IPs
  const ips = new Set();
  if (email.relay?.originatingIP && email.relay.originatingIP !== 'Unknown') {
    ips.add(email.relay.originatingIP);
  }
  if (email.relay?.hops) {
    for (const h of email.relay.hops) {
      if (h.ip && !h.isPrivate) ips.add(h.ip);
    }
  }

  // Attachments IoCs
  const attachmentIoCs = (email.attachments || []).map(att => ({
    filename: att.filename,
    contentType: att.contentType,
    size: att.size,
    sha256: att.sha256,
    md5: att.md5,
    isDangerous: att.isDangerous,
    extension: att.extension,
    threatFlags: att.isDangerous ? [`Exec / Macro / Script Extension (.${att.extension})`] : []
  }));

  return {
    urls: uniqueUrls,
    domains: Array.from(domains),
    ips: Array.from(ips),
    attachments: attachmentIoCs,
    totalUrls: uniqueUrls.length,
    suspiciousUrlsCount: uniqueUrls.filter(u => u.isSuspicious).length,
    dangerousAttachmentsCount: attachmentIoCs.filter(a => a.isDangerous).length
  };
}

function findUrls(text) {
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
  const matches = text.match(urlRegex) || [];
  return [...new Set(matches.map(u => u.replace(/[.,;!]+$/, '')))];
}

function extractHtmlAnchorPairs(html) {
  if (!html) return [];
  const pairs = [];
  const regex = /<a\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = regex.exec(html)) !== null) {
    pairs.push({
      href: match[1],
      text: match[2].replace(/<[^>]+>/g, '').trim()
    });
  }
  return pairs;
}

export function defangUrl(url) {
  return url
    .replace(/^http:\/\//, 'hxxp://')
    .replace(/^https:\/\//, 'hxxps://')
    .replace(/\./g, '[.]');
}

function isLocalhost(host) {
  return host === 'localhost' || host === '127.0.0.1';
}
