# AegisMail DFIR — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![React](https://img.shields.io/badge/Frontend-React%20%7C%20TailwindCSS%20%7C%20Vite-blue)](https://react.dev/)
[![Node.js](https://img.shields.io/badge/Backend-Node.js%20%7C%20Express-green)](https://nodejs.org/)
[![AI Engine](https://img.shields.io/badge/AI%20Engine-AI--Assisted%20Threat%20Assessment-purple)](https://github.com/Sagnik143/SIH-project-Email-analyser)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A comprehensive Digital Forensics and Incident Response (DFIR) platform** for email threat analysis, SMTP relay hop reconstruction, geolocation trajectory mapping, sender authentication verification, and AI-driven social engineering detection.

---

## Key Capabilities

- **Deep RFC 5322 Ingestion & Parsing:** Extracts structured headers, MIME multipart boundaries, attachment signatures, and calculates cryptographic evidentiary hashes (SHA-256 / MD5).
- **SMTP Relay Hop Trajectory & Delay Analysis:** Reconstructs the observable relay path from Received: headers, identifying hop transit latency deltas and timestamp/routing inconsistency between observed infrastructure nodes.
- **Infrastructure Geolocation & ASN Intelligence:** Resolves intermediate relay nodes to network infrastructure locations (country, city, ASN, ISP). IP geolocation describes network infrastructure and does not establish the physical location or identity of the human sender.
- **Interactive Geo Relay Map:** Visualizes observable relay path across world coordinates with Leaflet and infrastructure markers.
- **Reported Authentication Matrix:** Evaluates SPF, DKIM, and DMARC claims as reported by receiving mail system headers.
- **Identity Deception Detection:** Flags Display-Name spoofing, authority impersonation, and typosquatted/lookalike domains using Levenshtein distance, visual homoglyphs, and Punycode (IDN homographs).
- **AI-Assisted Threat Intelligence:** Performs semantic evaluation of language urgency, coercion pretexts, and credential lures, outputting heuristic risk scores (0-100), observed behavioral tactics, evidence-supported investigative hypotheses, and mitigation recommendations.
- **Indicators of Compromise (IoC) Vault:** Automatically extracts defanged URLs (`hxxp[://]...`), detects deceptive anchor text, isolates domains and IPs, and hashes file attachments.
- **Evidentiary Forensic Dossier:** Exportable forensic dossier in JSON and printable PDF format with full chain-of-custody metadata.

---

## Architecture Overview

```
+---------------------------------------------------------------------------------------+
|                               FRONTEND (React + Tailwind CSS)                         |
|  - Heuristic Risk Score & Assessment Gauge (0-100)                                    |
|  - Interactive Leaflet Geo Relay Map (Observed Infrastructure Path)                   |
|  - Observable Relay Sequence & Node Timeline                                          |
|  - AI-Assisted Security Assessment & Observed Tactics                                 |
|  - IoC Threat Table (Extracted URLs, Domains, IPs, SHA-256 Hashes)                    |
|  - Live Raw Header Inspector with RFC Annotation & Reported Authentication Badges     |
|  - Evidentiary Export (Forensic PDF / JSON Dossier with Hash Fingerprint)             |
+-------------------------------------------+-------------------------------------------+
                                            | REST API (Port 5001)
+-------------------------------------------v-------------------------------------------+
|                               BACKEND (Node / Express)                                |
|  1. Ingestion & MIME Parser (RFC 822/5322 Engine)                                     |
|  2. Relay Path Tracer (Observable Received hop sequence, delay delta, TLS & MTA)      |
|  3. Reported Auth Evaluator (Reported SPF, DKIM, DMARC, Return-Path vs From)           |
|  4. Domain Forensics (Levenshtein lookalike, punycode homoglyphs, brand spoof)        |
|  5. Infrastructure Geo & Threat Engine (City, Country, Lat/Lon, ASN, ISP)            |
|  6. IoC Extractor (Defanged URLs, suspicious TLDs, attachment hashes & risks)         |
|  7. AI Threat Engine (Backend LLM Integration + Heuristic DFIR Fallback Engine)       |
|  8. Forensic Report & Evidentiary Hash Generator (SHA-256 integrity check)            |
+---------------------------------------------------------------------------------------+
```

---

## Quick Start

### 1. Prerequisites
- Node.js (v18+)
- npm or yarn

### 2. Backend Setup
```bash
cd backend
npm install
cp .env.example .env
# Edit .env with your API Key if configuring LLM enrichment
npm start
```
*Backend runs on `http://localhost:5001`.*

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
*Frontend runs on `http://localhost:5173`.*

---

## Pre-Loaded Forensic Threat Datasets
The platform includes realistic forensic email samples for instant demonstration:
1. **Executive BEC Wire Transfer Fraud:** CEO display-name spoofing with reply-to redirection targeting CFO for an urgent international wire transfer.
2. **Microsoft 365 Credential Harvester:** Deceptive account suspension notice using typosquatted domain `micros0ft-portal.xyz` with IP credential lure.
3. **Financial Trojan Invoice with Weaponized Macro:** Fake QuickBooks overdue remittance with malicious `.xlsm` script attachment from bulletproof relay.
4. **Multi-Hop Relay Chain with Timing Anomalies:** Multi-hop relay path traversing infrastructure in multiple jurisdictions, demonstrating timestamp/routing inconsistency analysis.
5. **Verified Corporate Engineering Newsletter:** Benign corporate digest showing full reported SPF PASS, DKIM PASS, and DMARC PASS.

---

## License
MIT License. Created for Digital Forensics and Incident Response teams, fraud analysts, and cybersecurity researchers.
