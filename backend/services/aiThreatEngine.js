import { OpenRouter } from '@openrouter/sdk';
import dotenv from 'dotenv';
dotenv.config();

const API_KEY = process.env.OPENROUTER_API_KEY;
const PRIMARY_MODEL = process.env.OPENROUTER_MODEL || 'minimax/minimax-m3:free';
const FALLBACK_MODELS = (process.env.FALLBACK_MODELS || 'minimax/minimax-m2.7:free,liquid/lfm-2.5-2.6b:free,nvidia/nemotron-3.5-lightning:free').split(',');

const openrouter = new OpenRouter({
  apiKey: API_KEY
});

/**
 * Analyzes parsed email telemetry with OpenRouter LLM (Minimax-M3 / fallback)
 */
export async function analyzeEmailThreatWithAI(emailData, relayData, authData, iocData, geoData) {
  const forensicPrompt = buildForensicPrompt(emailData, relayData, authData, iocData, geoData);
  const modelsToTry = [PRIMARY_MODEL, ...FALLBACK_MODELS];

  let rawAiResponse = '';
  let modelUsed = PRIMARY_MODEL;
  let reasoningTokens = null;

  for (const model of modelsToTry) {
    try {
      console.log(`[AI Engine] Attempting forensic analysis with model: ${model}`);
      const stream = await openrouter.chat.send({
        chatRequest: {
          model,
          messages: [
            {
              role: 'system',
              content: 'You are an elite Digital Forensics & Incident Response (DFIR) AI Analyst and Email Security Engineer. Your job is to rigorously evaluate email telemetry, headers, authentication results, relay hops, and body text to detect cyber threats, social engineering, impersonation, and fraudulent infrastructure. Always respond strictly in valid JSON format matching the schema requested.'
            },
            {
              role: 'user',
              content: forensicPrompt
            }
          ],
          stream: true
        }
      });

      let accumulated = '';
      for await (const chunk of stream) {
        const content = chunk.choices[0]?.delta?.content;
        if (content) {
          accumulated += content;
        }
        if (chunk.usage?.completionTokensDetails?.reasoningTokens) {
          reasoningTokens = chunk.usage.completionTokensDetails.reasoningTokens;
        }
      }

      if (accumulated && accumulated.trim().length > 0) {
        rawAiResponse = accumulated;
        modelUsed = model;
        console.log(`[AI Engine] Successfully generated analysis with model: ${model}`);
        break;
      }
    } catch (err) {
      console.warn(`[AI Engine] Model ${model} failed: ${err.message}. Retrying fallback...`);
    }
  }

  // Parse JSON response from LLM
  if (rawAiResponse) {
    const parsed = parseLLMJsonResponse(rawAiResponse);
    if (parsed) {
      return {
        ...parsed,
        modelUsed,
        reasoningTokens: reasoningTokens || 0,
        rawAiOutput: rawAiResponse,
        engineSource: 'LLM_OPENROUTER'
      };
    }
  }

  // If LLM was unavailable due to upstream rate limits, use Heuristic DFIR Expert Engine
  console.log('[AI Engine] Utilizing Heuristic DFIR Expert System fallback');
  return generateHeuristicForensicAssessment(emailData, relayData, authData, iocData, geoData);
}

function buildForensicPrompt(email, relay, auth, iocs, geo) {
  return `
Analyze the following email technical telemetry and classify its threat level and forensic profile.

=== EMAIL ENVELOPE ===
From: "${email.envelope.from.name}" <${email.envelope.from.address}>
Domain: ${email.envelope.from.domain}
To: ${email.envelope.to}
Reply-To: ${email.envelope.replyTo ? email.envelope.replyTo.address : 'Not set'}
Subject: ${email.envelope.subject}
Date: ${email.envelope.date}

=== SENDER AUTHENTICATION ===
SPF Status: ${auth.spf.status} (${auth.spf.details})
DKIM Status: ${auth.dkim.status} (${auth.dkim.details})
DMARC Status: ${auth.dmarc.status} (${auth.dmarc.details})
Display Name Spoofing: ${auth.displayNameAnalysis.isSpoofed ? 'YES' : 'NO'}
${auth.displayNameAnalysis.flags.map(f => '- ' + f).join('\n')}
Domain Lookalike / Punycode: ${auth.domainAnalysis.isLookalike ? 'YES (' + auth.domainAnalysis.targetBrand + ')' : 'NO'}
${auth.domainAnalysis.flags.map(f => '- ' + f).join('\n')}
Reply-To / Return-Path Mismatch: ${auth.alignmentAnalysis.hasReplyToDiscrepancy ? 'YES' : 'NO'}
${auth.alignmentAnalysis.flags.map(f => '- ' + f).join('\n')}

=== TRANSMISSION RELAY & GEO-ORIGIN ===
Total Hops: ${relay.totalHops}
Originating Client IP: ${relay.originatingIP}
Origin Geolocation: ${geo.city}, ${geo.country} (${geo.countryCode})
Origin ISP / ASN: ${geo.isp} / ${geo.asn}
Threat Flags on IP: ${geo.threatFlags.join(', ') || 'None'}
Relay Transit Time: ${relay.totalTransitTimeSeconds} seconds

=== EXTRACTED INDICATORS OF COMPROMISE (IoCs) ===
Extracted URLs (${iocs.totalUrls}):
${iocs.urls.slice(0, 8).map(u => `- ${u.defanged} (Suspicious: ${u.isSuspicious ? 'YES - ' + u.flags.join(', ') : 'NO'})`).join('\n') || 'None'}
Extracted Attachments (${iocs.attachments.length}):
${iocs.attachments.map(a => `- ${a.filename} (${a.extension}, Danger: ${a.isDangerous ? 'HIGH RISK' : 'LOW'}, SHA256: ${a.sha256.slice(0, 16)}...)`).join('\n') || 'None'}

=== EMAIL BODY CONTENT (SNIPPET) ===
"${email.body.snippet}"

=== INSTRUCTIONS ===
Provide a comprehensive forensic evaluation strictly in this JSON format without backticks or markdown preamble:
{
  "threatClassification": "Legitimate" | "Suspicious" | "Impersonation (BEC)" | "Phishing / Credential Theft" | "Financial Fraud / Extortion" | "Malware Delivery",
  "threatLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "riskScore": <integer 0 to 100>,
  "confidenceScore": <integer 0 to 100>,
  "socialEngineeringTactics": ["<tactic 1>", "<tactic 2>"],
  "executiveSummary": "<2-3 sentence executive synopsis for SOC leaders>",
  "forensicHypothesis": "<Detailed technical hypothesis explaining threat actor infrastructure, impersonation tactic, and attack vector>",
  "threatActorPersona": "<Probable threat actor profile, e.g., 'Organized BEC Syndicate', 'Commodity Phishing Kit Operator', 'Nation-State Spear-Phisher', or 'Benign Business Communicator'>",
  "recommendedActions": [
    "<Mitigation step 1>",
    "<Mitigation step 2>",
    "<Mitigation step 3>"
  ]
}
`;
}

function parseLLMJsonResponse(raw) {
  try {
    // Strip markdown fences ```json ... ```
    let clean = raw.trim();
    if (clean.startsWith('```')) {
      clean = clean.replace(/^```[a-zA-Z]*\n?/, '').replace(/```$/, '').trim();
    }
    const parsed = JSON.parse(clean);
    if (parsed.threatClassification && parsed.threatLevel) {
      return parsed;
    }
  } catch (err) {
    // Try regex extraction of JSON object
    const match = raw.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        const parsed = JSON.parse(match[0]);
        if (parsed.threatClassification) return parsed;
      } catch (e) {}
    }
  }
  return null;
}

/**
 * Deterministic Heuristic DFIR Assessment Engine
 */
function generateHeuristicForensicAssessment(email, relay, auth, iocs, geo) {
  let riskScore = 10;
  const tactics = [];
  const actions = [];
  let threatClassification = 'Legitimate';
  let threatLevel = 'LOW';
  let threatActorPersona = 'Legitimate Sender';

  // 1. Check Authentication & Spoofing
  if (auth.displayNameAnalysis.isSpoofed) {
    riskScore += 40;
    tactics.push('Display-Name Spoofing', 'Authority Impersonation');
    threatClassification = 'Impersonation (BEC)';
  }

  if (auth.domainAnalysis.isLookalike) {
    riskScore += 45;
    tactics.push('Typosquatting / Lookalike Domain', 'Brand Identity Spoofing');
    threatClassification = 'Phishing / Credential Theft';
  }

  if (auth.alignmentAnalysis.hasReplyToDiscrepancy) {
    riskScore += 25;
    tactics.push('Reply-To Hijacking / Redirection');
  }

  if (auth.spf.status === 'FAIL') {
    riskScore += 30;
    tactics.push('SPF Authentication Failure (Forged Sender MTA)');
  }

  if (auth.dkim.status === 'FAIL') {
    riskScore += 25;
    tactics.push('DKIM Cryptographic Integrity Breach');
  }

  // 2. Check URLs
  if (iocs.suspiciousUrlsCount > 0) {
    riskScore += 35;
    tactics.push('Malicious/Obfuscated Link Lure');
    if (threatClassification === 'Legitimate') {
      threatClassification = 'Phishing / Credential Theft';
    }
  }

  // 3. Check Attachments
  if (iocs.dangerousAttachmentsCount > 0) {
    riskScore += 45;
    tactics.push('Executable / Weaponized Script Payload');
    threatClassification = 'Malware Delivery';
  }

  // 4. Body keyword heuristics
  const body = ((email.envelope.subject || '') + ' ' + (email.body.snippet || '')).toLowerCase();
  if (/wire\s+transfer|gift\s+card|invoice\s+attached|urgent\s+action|account\s+suspended|verify\s+your\s+password|immediate\s+payment/i.test(body)) {
    riskScore += 20;
    tactics.push('Psychological Urgency & Pressure Cue');
    if (/wire|transfer|payment|invoice|gift\s+card/i.test(body) && threatClassification.includes('Impersonation')) {
      threatClassification = 'Financial Fraud / Extortion';
    }
  }

  // 5. Geolocation / IP reputation
  if (geo.threatFlags && geo.threatFlags.length > 0) {
    riskScore += 15;
  }

  riskScore = Math.min(100, Math.max(0, riskScore));

  if (riskScore >= 75) {
    threatLevel = 'CRITICAL';
    threatActorPersona = 'Sophisticated Threat Actor / BEC Syndicate';
  } else if (riskScore >= 50) {
    threatLevel = 'HIGH';
    threatActorPersona = 'Cybercriminal Phishing Kit Operator';
  } else if (riskScore >= 25) {
    threatLevel = 'MEDIUM';
    threatActorPersona = 'Unverified External Communicator';
  } else {
    threatLevel = 'LOW';
    threatClassification = 'Legitimate';
    threatActorPersona = 'Authorized Corporate Communicator';
  }

  // Action suggestions
  if (threatLevel === 'CRITICAL' || threatLevel === 'HIGH') {
    actions.push('Quarantine email across all mailboxes immediately');
    actions.push(`Block originating IP (${relay.originatingIP}) on perimeter edge firewall`);
    if (iocs.urls.length > 0) {
      actions.push(`Add ${iocs.urls.length} extracted domains/URLs to company DNS-level sinkhole`);
    }
    actions.push('Initiate user security debrief and reset compromised sessions');
  } else if (threatLevel === 'MEDIUM') {
    actions.push('Tag email with [EXTERNAL / SUSPICIOUS] subject banner');
    actions.push('Request manual analyst review before releasing attachments');
  } else {
    actions.push('Allow normal delivery to inbox; headers verify valid authentication');
  }

  return {
    threatClassification,
    threatLevel,
    riskScore,
    confidenceScore: 92,
    socialEngineeringTactics: tactics.length > 0 ? tactics : ['Standard Business Correspondence'],
    executiveSummary: `The email was inspected with an overall risk score of ${riskScore}/100 and classified as ${threatClassification}. Originating from ${geo.city}, ${geo.country} via ${geo.isp}.`,
    forensicHypothesis: `The email displays ${tactics.join(', ') || 'no suspicious indicators'}. Analysis of the relay chain indicates message originated from ${relay.originatingIP} (${geo.country}) with ${auth.spf.status} SPF and ${auth.dkim.status} DKIM status.`,
    threatActorPersona,
    recommendedActions: actions,
    engineSource: 'HEURISTIC_DFIR_EXPERT'
  };
}
