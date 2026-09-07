import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import { parseEmail } from './services/emailParser.js';
import { traceRelayHops } from './services/relayTracer.js';
import { lookupIP, calculateDistanceKm } from './services/geoService.js';
import { validateAuthentication } from './services/authValidator.js';
import { extractIoCs } from './services/iocExtractor.js';
import { analyzeEmailThreatWithAI } from './services/aiThreatEngine.js';
import { analyzeAttributionAndGraph } from './services/attributionEngine.js';
import { SAMPLE_EMAILS } from './data/samples.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

// Middlewares
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Multer memory storage for .eml file uploads
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    engine: 'Email Threat Forensic Intelligence Engine v1.0',
    problemStatementId: 26106,
    problemTitle: 'AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform',
    organization: 'All India Council for Technical Education (Cyber Security Cell)',
    openrouterKeyConfigured: !!(process.env.EXPLABS_API_KEY || process.env.OPENROUTER_API_KEY),
    aiKeyConfigured: !!process.env.EXPLABS_API_KEY,
    primaryModel: process.env.AI_MODEL || process.env.OPENROUTER_MODEL || 'gpt-6-astra'
  });
});

// Get sample threat emails
app.get('/api/samples', (req, res) => {
  const summaries = SAMPLE_EMAILS.map(s => ({
    id: s.id,
    title: s.title,
    category: s.category,
    riskIndicator: s.riskIndicator,
    description: s.description
  }));
  res.json({ samples: summaries });
});

app.get('/api/samples/:id', (req, res) => {
  const sample = SAMPLE_EMAILS.find(s => s.id === req.params.id);
  if (!sample) {
    return res.status(404).json({ error: 'Sample not found' });
  }
  res.json(sample);
});

// Primary Forensic Analysis Endpoint
app.post('/api/analyze', upload.single('emailFile'), async (req, res) => {
  try {
    let rawContent = '';

    if (req.file) {
      rawContent = req.file.buffer.toString('utf-8');
    } else if (req.body.rawEmail) {
      rawContent = req.body.rawEmail;
    } else {
      return res.status(400).json({ error: 'No raw email or file provided' });
    }

    if (!rawContent || rawContent.trim().length === 0) {
      return res.status(400).json({ error: 'Email content cannot be empty' });
    }

    console.log(`[Analyzer] Processing email (${Buffer.byteLength(rawContent)} bytes)...`);

    // 1. Ingest and parse email structure
    const parsedEmail = await parseEmail(rawContent);

    // 2. Trace relay hops from Received: headers
    const relayData = traceRelayHops(parsedEmail.headers, parsedEmail.headerLines);

    // 3. Geolocation & IP resolution for each hop
    const enrichedHops = relayData.hops.map((hop) => {
      const geo = lookupIP(hop.ip);
      return {
        ...hop,
        geo
      };
    });

    // Determine originating IP & its Geo
    const originatingIP = relayData.originatingIP;
    const originGeo = lookupIP(originatingIP);

    // 4. Trace route trajectory and calculate hop distances / impossible travel
    const trajectory = [];
    const hopAnomalies = [];

    for (let i = 0; i < enrichedHops.length; i++) {
      const hop = enrichedHops[i];
      if (hop.geo && hop.geo.resolved && hop.geo.latitude !== 0) {
        trajectory.push({
          hopNumber: hop.hopNumber,
          ip: hop.ip,
          hostname: hop.fromHost,
          city: hop.geo.city,
          country: hop.geo.country,
          countryCode: hop.geo.countryCode,
          lat: hop.geo.latitude,
          lon: hop.geo.longitude,
          delaySeconds: hop.transitDelaySeconds,
          isOrigin: hop.isOriginHop || hop.ip === originatingIP
        });
      }

      // Check impossible travel between hop i-1 and hop i
      if (i > 0) {
        const prev = enrichedHops[i - 1];
        const curr = enrichedHops[i];
        if (prev.geo?.latitude && curr.geo?.latitude) {
          const distKm = calculateDistanceKm(prev.geo.latitude, prev.geo.longitude, curr.geo.latitude, curr.geo.longitude);
          const delaySec = curr.transitDelaySeconds || 0;
          // If distance > 1000km and delay < 5 seconds, flag as anomalous physical transit
          if (distKm > 1000 && delaySec > 0 && delaySec < 5) {
            hopAnomalies.push({
              fromHop: prev.hopNumber,
              toHop: curr.hopNumber,
              distanceKm: distKm,
              delaySeconds: delaySec,
              speedKmPerSec: Math.round(distKm / delaySec),
              alert: `Impossible transit speed: ${distKm}km traversed in only ${delaySec}s between ${prev.geo.city} and ${curr.geo.city}`
            });
          }
        }
      }
    }

    const relayAnalysis = {
      ...relayData,
      hops: enrichedHops,
      originGeo,
      trajectory,
      hopAnomalies
    };

    // 5. Sender Authentication & Domain Lookalike Validation
    const authData = validateAuthentication({
      ...parsedEmail,
      relay: relayAnalysis
    });

    // 6. Indicators of Compromise (IoC) Extraction
    const iocData = extractIoCs({
      ...parsedEmail,
      relay: relayAnalysis
    });

    // 7. AI Threat Intelligence Assessment (ExperientialLabs GPT-6 Astra)
    const aiAssessment = await analyzeEmailThreatWithAI(
      parsedEmail,
      relayAnalysis,
      authData,
      iocData,
      originGeo
    );

    // 8. Identity Correlation, Attribution & Graph Relationship Engine (AICTE 26106)
    const attributionAndGraph = analyzeAttributionAndGraph(
      parsedEmail,
      relayAnalysis,
      authData,
      iocData,
      originGeo,
      aiAssessment
    );

    // 9. Assemble unified forensic dossier
    const forensicDossier = {
      dossierId: `DFIR-AICTE-26106-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      problemStatementId: 26106,
      timestamp: new Date().toISOString(),
      integrity: parsedEmail.integrity,
      envelope: parsedEmail.envelope,
      bodySnippet: parsedEmail.body.snippet,
      bodyText: parsedEmail.body.text,
      bodyHtml: parsedEmail.body.html,
      attachments: parsedEmail.attachments,
      relay: relayAnalysis,
      originGeo,
      authentication: authData,
      iocs: iocData,
      aiThreatIntelligence: aiAssessment,
      attributionAndGraph,
      rawHeaders: parsedEmail.headers,
      headerLines: parsedEmail.headerLines
    };

    console.log(`[Analyzer] Analysis complete: Risk ${aiAssessment.riskScore}/100 [${aiAssessment.threatClassification}]`);
    res.json(forensicDossier);

  } catch (error) {
    console.error('[Analyzer] Analysis error:', error);
    res.status(500).json({
      error: 'Failed to complete forensic email analysis',
      message: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`⚡ Email Threat Forensic & GeoLocation Server running`);
  console.log(`🚀 API Port: http://localhost:${PORT}`);
  console.log(`🛡️ AI Model: ${process.env.AI_MODEL || 'gpt-6-astra'} (ExperientialLabs)`);
  console.log(`======================================================\n`);
});
