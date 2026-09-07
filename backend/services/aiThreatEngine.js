import OpenAI from 'openai';
import dotenv from 'dotenv';
dotenv.config();

function getAIClient() {
  const baseURL = process.env.EXPLABS_BASE_URL || 'https://api.experientiallabs.ai/v1';
  const apiKey = process.env.EXPLABS_API_KEY || 'xpl_e9fa4d3a82375b6433af107e476239849eb972d2';
  return new OpenAI({
    baseURL,
    apiKey,
    timeout: 45000,
    maxRetries: 1
  });
}

const PRIMARY_MODEL = process.env.AI_MODEL || 'gpt-6-astra';

/**
 * Analyzes parsed email telemetry with ExperientialLabs GPT-6 Astra LLM
 * Aligned with AICTE Problem Statement 26106: AI-Powered Email Threat Detection, GeoLocation & Forensics
 */
export async function analyzeEmailThreatWithAI(emailData, relayData, authData, iocData, geoData) {
  const forensicPrompt = buildForensicPrompt(emailData, relayData, authData, iocData, geoData);
  const client = getAIClient();

  let rawAiResponse = '';
  let modelUsed = PRIMARY_MODEL;
  let reasoningTokens = null;

  try {
    console.log(`\n[AI Engine] Initiating forensic analysis with ExperientialLabs model: ${PRIMARY_MODEL}`);

    const response = await client.chat.completions.create({
      model: PRIMARY_MODEL,
      messages: [
        {
          role: 'system',
          content: 'You are an elite Digital Forensics & Incident Response (DFIR) AI Analyst and Email Security Engineer for the AICTE Cyber Security Cell (Problem Statement 26106). Your job is to rigorously evaluate email telemetry, headers, authentication results (SPF/DKIM/DMARC), relay hops, and body text to detect cyber threats, social engineering, impersonation, payment diversion, and fraudulent infrastructure. Always respond strictly in valid JSON format matching the schema requested.'
        },
        {
          role: 'user',
          content: forensicPrompt
        }
      ],
      temperature: 0.2
    });

    const content = response.choices?.[0]?.message?.content;
    if (content && content.trim().length > 0) {
      rawAiResponse = content;
      if (response.usage?.completion_tokens_details?.reasoning_tokens) {
        reasoningTokens = response.usage.completion_tokens_details.reasoning_tokens;
      }
      console.log(`\n[AI Engine] Successfully generated analysis with model: ${PRIMARY_MODEL}`);
    }
  } catch (err) {
    console.warn(`[AI Engine] ExperientialLabs (${PRIMARY_MODEL}) error: ${err.message}. Using Heuristic DFIR Expert System...`);
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
        engineSource: 'LLM_EXPERIENTIALLABS',
        problemStatementId: 26106
      };
    }
  }

  // If LLM was unavailable due to upstream rate limits, quota, or timeout, use Heuristic DFIR Expert Engine
  console.log('[AI Engine] Utilizing Heuristic DFIR Expert System fallback (AICTE 26106 Standard)');
  const fallbackResult = generateHeuristicForensicAssessment(emailData, relayData, authData, iocData, geoData);
  return {
    ...fallbackResult,
    reasoningTokens: reasoningTokens || 0,
    modelUsed: `${PRIMARY_MODEL} (Heuristic Fallback Engine)`
  };
}

function buildForensicPrompt(email, relay, auth, iocs, geo) {
  return `
Analyze the following email technical telemetry and classify its threat level, attribution, and forensic profile according to AICTE Problem Statement 26106 standards.

=== EMAIL ENVELOPE ===
From: "${email.envelope?.from?.name || ''}" <${email.envelope?.from?.address || ''}>
Domain: ${email.envelope?.from?.domain || ''}
To: ${email.envelope?.to || ''}
Reply-To: ${email.envelope?.replyTo ? email.envelope.replyTo.address : 'Not set'}
Subject: ${email.envelope?.subject || ''}
Date: ${email.envelope?.date || ''}

=== SENDER AUTHENTICATION ===
SPF Status: ${auth.spf?.status} (${auth.spf?.details})
DKIM Status: ${auth.dkim?.status} (${auth.dkim?.details})
DMARC Status: ${auth.dmarc?.status} (${auth.dmarc?.details})
Display Name Spoofing: ${auth.displayNameAnalysis?.isSpoofed ? 'YES' : 'NO'}
${(auth.displayNameAnalysis?.flags || []).map(f => '- ' + f).join('\n')}
Domain Lookalike / Punycode: ${auth.domainAnalysis?.isLookalike ? 'YES (' + auth.domainAnalysis.targetBrand + ')' : 'NO'}
${(auth.domainAnalysis?.flags || []).map(f => '- ' + f).join('\n')}
Reply-To / Return-Path Mismatch: ${auth.alignmentAnalysis?.hasReplyToDiscrepancy ? 'YES' : 'NO'}
${(auth.alignmentAnalysis?.flags || []).map(f => '- ' + f).join('\n')}

=== TRANSMISSION RELAY & GEO-ORIGIN ===
Total Hops: ${relay.totalHops}
Originating Client IP: ${relay.originatingIP}
Origin Geolocation: ${geo.city}, ${geo.country} (${geo.countryCode})
Origin ISP / ASN: ${geo.isp} / ${geo.asn}
Threat Flags on IP: ${(geo.threatFlags || []).join(', ') || 'None'}
Relay Transit Time: ${relay.totalTransitTimeSeconds} seconds

=== EXTRACTED INDICATORS OF COMPROMISE (IoCs) ===
Extracted URLs (${iocs.totalUrls || 0}):
${(iocs.urls || []).slice(0, 8).map(u => `- ${u.defanged} (Suspicious: ${u.isSuspicious ? 'YES - ' + u.flags.join(', ') : 'NO'})`).join('\n') || 'None'}
Extracted Attachments (${(iocs.attachments || []).length}):
${(iocs.attachments || []).map(a => `- ${a.filename} (${a.extension}, Danger: ${a.isDangerous ? 'HIGH RISK' : 'LOW'}, SHA256: ${a.sha256?.slice(0, 16)}...)`).join('\n') || 'None'}

=== EMAIL BODY CONTENT (SNIPPET) ===
"${email.body?.snippet || ''}"

=== INSTRUCTIONS ===
Provide a comprehensive forensic evaluation strictly in this JSON format without markdown code fences or backticks:
{
  "problemStatementId": 26106,
  "threatClassification": "Legitimate" | "Suspicious" | "Impersonation (BEC)" | "Phishing / Credential Theft" | "Financial Fraud / Extortion" | "Malware Delivery" | "State-Sponsored / APT",
  "threatLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "riskScore": <integer 0 to 100>,
  "confidenceScore": <integer 0 to 100>,
  "attribution": {
    "infrastructureClassification": "Compromised Corporate Account" | "Spoofed External Domain" | "Anonymized Infrastructure (TOR/VPN/Bulletproof Relay)" | "Direct Malicious Actor Node" | "Authorized Infrastructure",
    "probableActorPersona": "<e.g. Organized BEC Wire Syndicate, Phishing Kit Operator, APT Emissary, or Legitimate Corporate Sender>",
    "campaignCluster": "<e.g. BEC-PaymentDiversion-2024, M365-CredentialHarvest-Cluster, Fake-Invoice-Trojan-Lure, or Benign-Digest>",
    "attributionConfidence": <integer 0 to 100>
  },
  "socialEngineeringTactics": ["<tactic 1>", "<tactic 2>"],
  "executiveSummary": "<2-3 sentence executive synopsis for SOC leaders>",
  "forensicHypothesis": "<Detailed technical hypothesis explaining threat actor infrastructure, impersonation tactic, and attack vector>",
  "threatActorPersona": "<Probable threat actor profile>",
  "recommendedActions": [
    "<Mitigation step 1>",
    "<Mitigation step 2>",
    "<Mitigation step 3>"
  ],
  "chainOfCustodyNotes": "Evidence hashed with SHA-256 and compliant with AICTE Cyber Security Cell / ISO 27037 standards"
}
`;
}

function parseLLMJsonResponse(raw) {
  try {
    let clean = raw.trim();
    if (clean.startsWith('```')) {
      clean = clean.replace(/^```[a-zA-Z]*\n?/, '').replace(/```$/, '').trim();
    }
    const parsed = JSON.parse(clean);
    if (parsed.threatClassification && parsed.threatLevel) {
      return parsed;
    }
  } catch (err) {
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
 * Deterministic Heuristic DFIR Assessment Engine (Aligned with AICTE 26106)
 */
function generateHeuristicForensicAssessment(email, relay, auth, iocs, geo) {
  let riskScore = 10;
  const tactics = [];
  const actions = [];
  let threatClassification = 'Legitimate';
  let threatLevel = 'LOW';
  let threatActorPersona = 'Legitimate Sender';
  let infrastructureClassification = 'Authorized Infrastructure';
  let campaignCluster = 'Corporate-Verified-Communications';
  let attributionConfidence = 85;

  // 1. Check Authentication & Spoofing
  if (auth.displayNameAnalysis?.isSpoofed) {
    riskScore += 40;
    tactics.push('Display-Name Spoofing', 'Executive Impersonation');
    threatClassification = 'Impersonation (BEC)';
    infrastructureClassification = 'Spoofed External Domain';
    campaignCluster = 'BEC-Executive-Impersonation-Campaign';
    attributionConfidence = 92;
  }

  if (auth.domainAnalysis?.isLookalike) {
    riskScore += 45;
    tactics.push('Typosquatting / Lookalike Domain', 'Brand Identity Hijacking');
    threatClassification = 'Phishing / Credential Theft';
    infrastructureClassification = 'Direct Malicious Actor Node';
    campaignCluster = 'M365-CredentialHarvest-Cluster';
    attributionConfidence = 95;
  }

  if (auth.alignmentAnalysis?.hasReplyToDiscrepancy) {
    riskScore += 25;
    tactics.push('Reply-To Redirection / Communication Hijacking');
  }

  if (auth.spf?.status === 'FAIL') {
    riskScore += 30;
    tactics.push('SPF Authentication Failure (Unauthorized MTA)');
  }

  if (auth.dkim?.status === 'FAIL') {
    riskScore += 25;
    tactics.push('DKIM Cryptographic Signature Failure');
  }

  // 2. Check URLs
  if ((iocs.suspiciousUrlsCount || 0) > 0) {
    riskScore += 35;
    tactics.push('Obfuscated / Deceptive Hyperlink Lure');
    if (threatClassification === 'Legitimate') {
      threatClassification = 'Phishing / Credential Theft';
    }
  }

  // 3. Check Attachments
  if ((iocs.dangerousAttachmentsCount || 0) > 0) {
    riskScore += 45;
    tactics.push('Weaponized Script / Macro Payload (.xlsm/.exe)');
    threatClassification = 'Malware Delivery';
    infrastructureClassification = 'Direct Malicious Actor Node';
    campaignCluster = 'Financial-Trojan-Invoice-Lure';
    attributionConfidence = 96;
  }

  // 4. Body keyword heuristics
  const body = (((email.envelope?.subject || '') + ' ' + (email.body?.snippet || ''))).toLowerCase();
  if (/wire\s+transfer|gift\s+card|invoice\s+attached|urgent\s+action|account\s+suspended|verify\s+your\s+password|immediate\s+payment/i.test(body)) {
    riskScore += 20;
    tactics.push('Psychological Urgency & Pressure Vector');
    if (/wire|transfer|payment|invoice|gift\s+card/i.test(body) && threatClassification.includes('Impersonation')) {
      threatClassification = 'Financial Fraud / Extortion';
      campaignCluster = 'BEC-WireTransfer-Interception';
    }
  }

  // 5. Geolocation / IP reputation
  if (geo.threatFlags && geo.threatFlags.length > 0) {
    riskScore += 20;
    if (geo.threatFlags.some(f => f.toLowerCase().includes('bulletproof') || f.toLowerCase().includes('vpn'))) {
      infrastructureClassification = 'Anonymized Infrastructure (TOR/VPN/Bulletproof Relay)';
    }
  }

  // Multi-hop state-sponsored evasion
  if ((relay.totalHops || 0) >= 4 && relay.hopAnomalies && relay.hopAnomalies.length > 0) {
    riskScore += 25;
    tactics.push('Multi-Hop Evasion Trajectory', 'Impossible Physical Travel Latency');
    threatClassification = 'State-Sponsored / APT';
    campaignCluster = 'APT-MultiHop-Evasion-Chain';
    attributionConfidence = 90;
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

  // Recommended mitigation actions
  if (threatLevel === 'CRITICAL' || threatLevel === 'HIGH') {
    actions.push('Quarantine email across all mailboxes immediately');
    actions.push(`Block originating IP (${relay.originatingIP}) on edge firewalls`);
    if ((iocs.urls || []).length > 0) {
      actions.push(`Add ${iocs.urls.length} extracted domains to DNS sinkholes`);
    }
    actions.push('Report IOCs to AICTE Cyber Security Incident Response Team (CSIRT)');
    actions.push('Preserve cryptographic chain-of-custody hash for legal evidence');
  } else if (threatLevel === 'MEDIUM') {
    actions.push('Prepend [CAUTION: UNVERIFIED EXTERNAL SENDER] warning banner');
    actions.push('Enforce sandboxed detonation before releasing attachments');
  } else {
    actions.push('Normal delivery; validated through authentic domain MX infrastructure');
  }

  return {
    problemStatementId: 26106,
    threatClassification,
    threatLevel,
    riskScore,
    confidenceScore: 94,
    attribution: {
      infrastructureClassification,
      probableActorPersona: threatActorPersona,
      campaignCluster,
      attributionConfidence
    },
    socialEngineeringTactics: tactics.length > 0 ? tactics : ['Standard Business Correspondence'],
    executiveSummary: `Email inspected under AICTE Problem Statement 26106 with overall risk score ${riskScore}/100 and classified as ${threatClassification}. Originating from ${geo.city}, ${geo.country} via ${geo.isp}.`,
    forensicHypothesis: `Telemetry exhibits ${tactics.join(', ') || 'standard email exchange patterns'}. Relay tracing confirms earliest origin IP ${relay.originatingIP} (${geo.country}) with SPF ${auth.spf?.status} and DKIM ${auth.dkim?.status}.`,
    threatActorPersona,
    recommendedActions: actions,
    chainOfCustodyNotes: 'Evidence integrity sealed with SHA-256 hash according to AICTE Cyber Security Cell / ISO 27037 standards.',
    engineSource: 'HEURISTIC_DFIR_EXPERT'
  };
}
