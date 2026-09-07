import OpenAI from 'openai';
import dotenv from 'dotenv';
import { validateAndSanitizeAiResponse, createSafeFallback } from './aiResponseValidator.js';
dotenv.config();

function getAIClient() {
  const baseURL = process.env.EXPLABS_BASE_URL || 'https://api.experientiallabs.ai/v1';
  const apiKey = process.env.EXPLABS_API_KEY || 'xpl_e9fa4d3a82375b6433af107e476239849eb972d2';
  return new OpenAI({
    baseURL,
    apiKey,
    timeout: 10000,
    maxRetries: 1
  });
}

const PRIMARY_MODEL = process.env.AI_MODEL || 'gpt-6-astra';
const AI_TIMEOUT_MS = 8000;

/**
 * Analyzes parsed email telemetry with AI Assistant (Phase 6)
 * 
 * Strict Architectural Boundary:
 * The AI is strictly an EXPLANATION & HYPOTHESIS layer over deterministic forensic findings.
 * It is NOT the source of forensic truth.
 * All outputs are strictly validated against deterministic findings before return.
 */
export async function analyzeEmailThreatWithAI(emailData, relayData, authData, iocData, geoData, findings = [], riskData = null, options = {}) {
  // Build authoritative deterministic context
  const deterministicFindings = Array.isArray(findings) ? findings : [];
  const deterministicRisk = riskData && typeof riskData.score === 'number'
    ? riskData
    : { score: 10, level: 'LOW', contributingSignals: [] };

  const deterministicContext = {
    findings: deterministicFindings,
    evidence: emailData?.evidence || [],
    indicators: iocData || {},
    authentication: authData || {},
    relay: relayData || {},
    originGeo: geoData || {},
    risk: deterministicRisk
  };

  const client = getAIClient();
  const forensicPrompt = buildAiInvestigationPrompt(deterministicContext, emailData);

  let rawAiResponse = '';

  try {
    console.log(`\n[AI Engine] Initiating forensic analysis with AI Assistant (Timeout: ${AI_TIMEOUT_MS}ms)`);

    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`AI assistant timed out after ${AI_TIMEOUT_MS}ms`)), AI_TIMEOUT_MS)
    );

    const callPromise = client.chat.completions.create({
      model: PRIMARY_MODEL,
      messages: [
        {
          role: 'system',
          content: [
            'You are an analyst-assistance layer for an email forensic investigation platform.',
            'Deterministic evidence and findings supplied to you are authoritative.',
            'Do NOT invent evidence. Do NOT create new findings. Do NOT create new IoCs.',
            'Do NOT invent authentication results.',
            'Do NOT identify an attacker or human identity. Do NOT assert campaign attribution.',
            'Do NOT infer human physical location from IP geolocation.',
            'Do NOT convert heuristic scores into statistical probabilities.',
            'Do NOT override deterministic findings or the deterministic risk score.',
            'Explain the established findings, identify investigative hypotheses, and recommend next steps.'
          ].join(' ')
        },
        {
          role: 'user',
          content: forensicPrompt
        }
      ],
      temperature: 0.1
    });

    const response = await Promise.race([callPromise, timeoutPromise]);
    const content = response.choices?.[0]?.message?.content;
    if (content && content.trim().length > 0) {
      rawAiResponse = content;
      console.log(`[AI Engine] Successfully received AI response`);
    }
  } catch (err) {
    console.warn(`[AI Engine] AI service error (${err.message}). Utilizing safe heuristic assistant...`);
  }

  // Parse and validate LLM output
  if (rawAiResponse) {
    const parsed = parseLLMJsonResponse(rawAiResponse);
    if (parsed) {
      const validated = validateAndSanitizeAiResponse(parsed, deterministicContext);
      return {
        ...validated,
        engineSource: 'AI_ASSISTED_ANALYSIS',
        available: true,
        status: 'available',
        problemStatementId: 26106
      };
    }
  }

  // Safe heuristic fallback if AI was unavailable, timed out, or returned invalid format
  console.log('[AI Engine] Utilizing Heuristic DFIR Assistant fallback (AICTE 26106 Standard)');
  const heuristicAssessment = generateHeuristicForensicAssessment(
    emailData,
    relayData,
    authData,
    iocData,
    geoData,
    deterministicFindings,
    deterministicRisk
  );

  const validatedFallback = validateAndSanitizeAiResponse(heuristicAssessment, deterministicContext);
  return {
    ...validatedFallback,
    engineSource: 'HEURISTIC_DFIR_ENGINE',
    available: true,
    status: 'heuristic_fallback',
    problemStatementId: 26106
  };
}

/**
 * Builds minimal, structured prompt conforming to AI input contract.
 * Raw email body bytes are NEVER sent. Only minimal structured context is provided.
 */
function buildAiInvestigationPrompt(ctx, email) {
  const { findings, authentication, relay, originGeo, indicators, risk } = ctx;

  const findingsSummary = findings.length > 0
    ? findings.map(f => `- [${f.id}] (${f.severity.toUpperCase()}) ${f.title}: ${f.summary}`).join('\n')
    : 'None (Baseline legitimate communication patterns)';

  const auth = authentication || {};
  const geo = originGeo || {};
  const iocs = indicators || {};

  return `
Analyze the following email technical telemetry and provide an analyst-friendly explanation based strictly on the authoritative deterministic findings.

=== AUTHORITATIVE DETERMINISTIC FORENSIC FINDINGS ===
${findingsSummary}
Authoritative Deterministic Heuristic Risk Score: ${risk.score}/100 (${risk.level})
Contributing Signals: ${(risk.contributingSignals || []).join(', ') || 'None'}

=== EMAIL ENVELOPE METADATA ===
From: "${email?.envelope?.from?.name || ''}" <${email?.envelope?.from?.address || ''}>
Sender Domain: ${email?.envelope?.from?.domain || ''}
To: ${email?.envelope?.to || ''}
Reply-To: ${email?.envelope?.replyTo?.address || 'Not set'}
Subject: ${email?.envelope?.subject || ''}

=== REPORTED SENDER AUTHENTICATION ===
Reported SPF Status: ${auth.spf?.status || 'none'}
Reported DKIM Status: ${auth.dkim?.status || 'none'}
Reported DMARC Status: ${auth.dmarc?.status || 'none'}
Display Name Spoofing: ${auth.displayNameAnalysis?.isSpoofed ? 'YES' : 'NO'}
Domain Lookalike: ${auth.domainAnalysis?.isLookalike ? 'YES' : 'NO'}
Reply-To Discrepancy: ${auth.alignmentAnalysis?.hasReplyToDiscrepancy ? 'YES' : 'NO'}

=== TRANSMISSION RELAY INFRASTRUCTURE ===
Total Observed Hops: ${relay?.totalHops || 0}
Earliest Trustworthy Sending Infrastructure: ${relay?.earliestTrustworthySendingInfrastructure || relay?.originatingIP || 'Unknown'}
Infrastructure Country: ${geo.country || 'Unknown'} (${geo.countryCode || 'N/A'})
Infrastructure ISP: ${geo.isp || 'Unknown'}
Relay Transit Time: ${relay?.totalTransitTimeSeconds || 0} seconds

=== EXTRACTED INDICATORS OF COMPROMISE (IoCs) ===
Extracted URLs: ${(iocs.urls || []).slice(0, 5).map(u => u.defanged || u.url).join(', ') || 'None'}
Extracted Attachments: ${(iocs.attachments || []).map(a => `${a.filename} (SHA-256: ${a.sha256?.slice(0, 12)}...)`).join(', ') || 'None'}

=== INSTRUCTIONS & FORENSIC CONSTRAINTS ===
- You are an analyst-assistance layer. The provided findings and evidence are authoritative.
- Do NOT invent evidence, findings, IoCs, or authentication results.
- Do NOT identify an attacker or human identity. Do NOT assert campaign attribution.
- Do NOT infer human physical location from IP geolocation.
- Do NOT convert heuristic scores into probabilities.
- Do NOT override deterministic findings or risk score.

Provide an objective forensic evaluation strictly in JSON format matching this schema:
{
  "executiveSummary": "<2-3 sentence executive synopsis for SOC leaders grounded in findings>",
  "priorityAssessment": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "keyObservations": [
    "<Concise bullet point 1>",
    "<Concise bullet point 2>"
  ],
  "explanationByFinding": [
    {
      "findingId": "<Exact ID from findings, e.g. F-001>",
      "explanation": "<Clear explanation of why this finding was flagged>"
    }
  ],
  "investigativeHypotheses": [
    {
      "hypothesis": "<Investigative hypothesis explaining observed indicators without asserting actor identity>",
      "supportingFindingIds": ["<Exact ID from findings>"],
      "confidence": "low" | "medium" | "high"
    }
  ],
  "recommendedNextSteps": [
    "<Actionable mitigation or verification step 1>",
    "<Actionable mitigation or verification step 2>"
  ],
  "limitations": [
    "AI provides investigative hypotheses and natural-language summaries based on deterministic evidence.",
    "IP geolocation describes network infrastructure and does not establish physical sender identity."
  ]
}
`;
}

function parseLLMJsonResponse(raw) {
  try {
    let clean = raw.trim();
    if (clean.startsWith('```')) {
      clean = clean.replace(/^```[a-zA-Z]*\n?/, '').replace(/```$/, '').trim();
    }
    return JSON.parse(clean);
  } catch (err) {
    const match = raw.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch (e) {}
    }
  }
  return null;
}

/**
 * Deterministic Heuristic DFIR Assistant
 * Provides safe, grounded explanation when LLM is offline.
 */
function generateHeuristicForensicAssessment(email, relay, auth, iocs, geo, findings = [], riskData = null) {
  const riskScore = riskData && typeof riskData.score === 'number' ? riskData.score : 10;
  const threatLevel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW';

  const threatClassification = riskScore >= 75
    ? (auth.displayNameAnalysis?.isSpoofed ? 'Impersonation (BEC)' : 'High Risk Telemetry')
    : (riskScore >= 50 ? 'Suspicious / Elevated Risk' : 'Legitimate');

  const keyObservations = [];
  const explanations = [];
  const actions = [];

  for (const f of findings) {
    keyObservations.push(`${f.title}: ${f.summary}`);
    explanations.push({
      findingId: f.id,
      explanation: f.summary
    });
  }

  if (keyObservations.length === 0) {
    keyObservations.push('Standard email communication telemetry observed');
  }

  if (riskScore >= 50) {
    actions.push('Inspect extracted URLs and attachments in an isolated sandbox environment.');
    actions.push(`Review earliest observed sending infrastructure (${relay?.originatingIP || 'MTA'}) on security gateways.`);
    actions.push('Verify sender authenticity through out-of-band communication.');
  } else {
    actions.push('Standard delivery; sender telemetry aligns with expected patterns.');
  }

  const hypothesis = findings.length > 0
    ? `Observed telemetry exhibits ${findings.length} forensic finding(s). Earliest trustworthy sending infrastructure records ${relay?.originatingIP || 'MTA'} (${geo?.country || 'Unknown'}) with reported SPF ${auth?.spf?.status || 'none'} and DKIM ${auth?.dkim?.status || 'none'}.`
    : 'Standard email exchange consistent with authentic business communications.';

  return {
    problemStatementId: 26106,
    threatClassification,
    threatLevel,
    priorityAssessment: threatLevel,
    riskScore,
    confidenceScore: 88,
    keyObservations,
    observedTactics: keyObservations,
    explanationByFinding: explanations,
    investigativeHypotheses: [
      {
        hypothesis,
        supportingFindingIds: findings.slice(0, 3).map(f => f.id),
        confidence: 'medium'
      }
    ],
    forensicHypothesis: hypothesis,
    investigativeHypothesis: hypothesis,
    threatActorPersona: 'Investigative Profile: Pattern analysis based on observable email artifacts',
    recommendedNextSteps: actions,
    recommendedActions: actions,
    limitations: [
      'Available email evidence does not establish the identity of a specific actor or campaign.',
      'IP geolocation describes network infrastructure and does not establish physical sender identity.'
    ],
    attribution: {
      status: 'Attribution not established',
      hypothesis: 'Investigative Profile: Pattern analysis based on observable email artifacts',
      infrastructureClassification: 'Observed Network Infrastructure',
      campaignCluster: 'Unclustered (Observable Indicator Grouping)',
      disclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.'
    },
    attributionDisclaimer: 'Available email evidence does not establish the identity of a specific actor or campaign.',
    engineSource: 'HEURISTIC_DFIR_ASSISTANT'
  };
}
