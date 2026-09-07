# AegisMail DFIR — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![React](https://img.shields.io/badge/Frontend-React%20%7C%20TailwindCSS%20%7C%20Vite-blue)](https://react.dev/)
[![Node.js](https://img.shields.io/badge/Backend-Node.js%20%7C%20Express-green)](https://nodejs.org/)
[![AI Engine](https://img.shields.io/badge/AI%20Engine-ExperientialLabs%20%28GPT--6%20Astra%29-purple)](https://experientiallabs.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A comprehensive Digital Forensics and Incident Response (DFIR) platform** for email threat analysis, SMTP relay hop reconstruction, geolocation trajectory mapping, sender authentication verification, and AI-driven social engineering detection.

---

## Key Capabilities

- **Deep RFC 5322 Ingestion & Parsing:** Extracts structured headers, MIME multipart boundaries, attachment signatures, and calculates cryptographic evidentiary hashes (SHA-256 / MD5).
- **SMTP Relay Hop Trajectory & Delay Analysis:** Reconstructs the complete chronological path of mail servers from originating client IP to destination MX, detecting hop transit latency deltas and impossible physical travel speeds.
- **Global IP Geolocation & ASN Intelligence:** Resolves each intermediate relay node to country, city, ASN, ISP, and identifies hosting/bulletproof/cloud droplet infrastructure.
- **Interactive Dark Matter Geo Hop Map:** Visualizes email transit across world coordinates with Leaflet, animated vectors, and origin crosshairs.
- **Sender Authentication Verification Matrix:** Validates SPF records, DKIM cryptographic signatures, and DMARC domain policies.
- **Identity Deception Detection:** Flags Display-Name spoofing, authority impersonation, and typosquatted/lookalike domains using Levenshtein distance, visual homoglyphs, and Punycode (IDN homographs).
- **AI Threat Intelligence (ExperientialLabs GPT-6 Astra):** Performs semantic NLP analysis on language urgency, financial coercion, and credential lures, outputting structured SOC threat scores (0-100), attacker personas, and actionable mitigation playbooks.
- **Indicators of Compromise (IoC) Vault:** Automatically extracts defanged URLs (`hxxp[://]...`), detects deceptive anchor text, isolates domains and IPs, and hashes file attachments.
- **Evidentiary Forensic Dossier:** Exportable forensic dossier in JSON and printable PDF format with full chain-of-custody metadata.

---

## Architecture Overview

```
+---------------------------------------------------------------------------------------+
|                               FRONTEND (React + Tailwind CSS)                         |
|  - Threat Radar & Confidence Gauge (0-100 Score)                                      |
|  - Interactive Leaflet Geo Hop Map (CartoDB Dark Matter)                              |
|  - SMTP Relay Hop Visual Timeline & Node Graph                                        |
|  - AI Forensic Investigator Report (ExperientialLabs GPT-6 Astra)                     |
|  - IoC Threat Table (Extracted URLs, Domains, IPs, SHA-256 Hashes)                    |
|  - Live Raw Header Inspector with RFC Annotation & Authentication Badges              |
|  - Evidentiary Export (Forensic PDF / JSON Dossier with Hash Fingerprint)             |
+-------------------------------------------+-------------------------------------------+
                                            | REST API (Port 5001)
+-------------------------------------------v-------------------------------------------+
|                               BACKEND (Node / Express)                                |
|  1. Ingestion & MIME Parser (RFC 822/5322 Engine)                                     |
|  2. Relay Path Tracer (Received hop sequence, delay delta, TLS & MTA analysis)        |
|  3. Auth Verifier (SPF, DKIM, DMARC, Return-Path vs From alignment)                   |
|  4. Domain Forensics (Levenshtein lookalike, punycode homoglyphs, brand spoof)        |
|  5. IP Geo & Threat Engine (City, Country, Lat/Lon, ASN, ISP, VPN/Hosting flag)       |
|  6. IoC Extractor (Defanged URLs, suspicious TLDs, attachment hashes & risks)         |
|  7. ExperientialLabs AI Engine (OpenAI SDK + GPT-6 Astra + Heuristic DFIR Fallback)   |
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
# Edit .env with your ExperientialLabs API Key (EXPLABS_API_KEY)
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
4. **State-Sponsored / APT Relay Chain:** Multi-hop evasion path traversing St. Petersburg, Bucharest, Frankfurt, and Virginia with impossible travel detection.
5. **Verified Corporate Engineering Newsletter:** Benign corporate digest showing full SPF PASS, DKIM PASS, and DMARC PASS.

---

## License
MIT License. Created for Digital Forensics and Incident Response teams, fraud analysts, and cybersecurity researchers.
