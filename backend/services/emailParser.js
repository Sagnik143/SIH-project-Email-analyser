import { simpleParser } from 'mailparser';
import crypto from 'crypto';

/**
 * Parses raw email string or buffer into a structured email object
 * @param {string|Buffer} rawInput 
 */
export async function parseEmail(rawInput) {
  const rawString = typeof rawInput === 'string' ? rawInput : rawInput.toString('utf-8');
  
  // Calculate cryptographic hashes of the raw email for chain of custody
  const sha256 = crypto.createHash('sha256').update(rawString).digest('hex');
  const md5 = crypto.createHash('md5').update(rawString).digest('hex');

  // Parse using mailparser
  let parsed;
  try {
    parsed = await simpleParser(rawString);
  } catch (err) {
    console.warn('mailparser error, falling back to manual parser:', err);
    parsed = manualFallbackParser(rawString);
  }

  // Extract raw headers list and structured map
  const rawHeadersMap = {};
  const rawHeadersList = [];

  if (parsed.headerLines) {
    for (const h of parsed.headerLines) {
      rawHeadersList.push({ key: h.key, line: h.line });
      if (!rawHeadersMap[h.key.toLowerCase()]) {
        rawHeadersMap[h.key.toLowerCase()] = [];
      }
      rawHeadersMap[h.key.toLowerCase()].push(h.line.replace(new RegExp(`^${h.key}:\\s*`, 'i'), ''));
    }
  } else {
    // extract via regex
    const headerSection = rawString.split(/\r?\n\r?\n/)[0] || '';
    const lines = headerSection.split(/\r?\n(?=[^\s])/);
    for (const line of lines) {
      const match = line.match(/^([^:]+):\s*([\s\S]*)$/);
      if (match) {
        const key = match[1].trim();
        const val = match[2].trim();
        rawHeadersList.push({ key, line });
        const lower = key.toLowerCase();
        if (!rawHeadersMap[lower]) rawHeadersMap[lower] = [];
        rawHeadersMap[lower].push(val);
      }
    }
  }

  // Process attachments
  const attachments = (parsed.attachments || []).map((att) => {
    const content = att.content || Buffer.from('');
    const attSha256 = crypto.createHash('sha256').update(content).digest('hex');
    const attMd5 = crypto.createHash('md5').update(content).digest('hex');
    const ext = (att.filename || '').split('.').pop().toLowerCase();
    
    // Check danger
    const dangerousExtensions = ['exe', 'scr', 'vbs', 'bat', 'cmd', 'ps1', 'js', 'hta', 'iso', 'img', 'jar', 'xlsm', 'docm', 'wsf', 'dll'];
    const isDangerous = dangerousExtensions.includes(ext);

    return {
      filename: att.filename || 'unnamed_attachment',
      contentType: att.contentType || 'application/octet-stream',
      size: att.size || content.length,
      md5: attMd5,
      sha256: attSha256,
      isDangerous,
      extension: ext
    };
  });

  // Extract from, to, cc, subject, date, messageId, replyTo
  const fromText = parsed.from?.text || (rawHeadersMap['from'] ? rawHeadersMap['from'][0] : '');
  const fromValue = parsed.from?.value?.[0] || extractAddressParts(fromText);

  const toText = parsed.to?.text || (rawHeadersMap['to'] ? rawHeadersMap['to'][0] : '');
  const subject = parsed.subject || (rawHeadersMap['subject'] ? rawHeadersMap['subject'][0] : '(No Subject)');
  const date = parsed.date || (rawHeadersMap['date'] ? new Date(rawHeadersMap['date'][0]) : new Date());
  const messageId = parsed.messageId || (rawHeadersMap['message-id'] ? rawHeadersMap['message-id'][0] : '');
  
  const replyToText = parsed.replyTo?.text || (rawHeadersMap['reply-to'] ? rawHeadersMap['reply-to'][0] : '');
  const replyToValue = parsed.replyTo?.value?.[0] || (replyToText ? extractAddressParts(replyToText) : null);

  const returnPath = rawHeadersMap['return-path'] ? rawHeadersMap['return-path'][0] : '';

  return {
    integrity: {
      sha256,
      md5,
      rawBytes: Buffer.byteLength(rawString, 'utf-8'),
      analyzedAt: new Date().toISOString()
    },
    envelope: {
      from: {
        raw: fromText,
        name: fromValue?.name || '',
        address: fromValue?.address || '',
        domain: (fromValue?.address || '').split('@')[1] || ''
      },
      to: toText,
      replyTo: replyToValue ? {
        raw: replyToText,
        name: replyToValue?.name || '',
        address: replyToValue?.address || '',
        domain: (replyToValue?.address || '').split('@')[1] || ''
      } : null,
      returnPath: returnPath.replace(/[<>]/g, '').trim(),
      subject,
      date: date instanceof Date && !isNaN(date) ? date.toISOString() : date,
      messageId
    },
    body: {
      text: parsed.text || '',
      html: parsed.html || '',
      snippet: (parsed.text || parsed.html || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').slice(0, 500)
    },
    attachments,
    headers: rawHeadersMap,
    headerLines: rawHeadersList,
    rawText: rawString
  };
}

function extractAddressParts(str) {
  if (!str) return { name: '', address: '' };
  const match = str.match(/(?:^"?(.*?)"?\s*<([^>]+)>|([^\s<]+@[^\s>]+))/);
  if (match) {
    if (match[2]) {
      return { name: match[1]?.trim() || '', address: match[2].trim() };
    }
    return { name: '', address: match[3]?.trim() || str.trim() };
  }
  return { name: '', address: str.trim() };
}

function manualFallbackParser(rawString) {
  const parts = rawString.split(/\r?\n\r?\n/);
  const headerSection = parts[0] || '';
  const bodyText = parts.slice(1).join('\n\n');
  return {
    headerLines: [],
    text: bodyText,
    html: '',
    attachments: []
  };
}
