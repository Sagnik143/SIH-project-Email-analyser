# MAILGUARD
### AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.10%2B-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-React%2019%20%7C%20Vite-61DAFB.svg?style=flat&logo=react)](https://react.dev)
[![Mapping](https://img.shields.io/badge/Mapping-Leaflet.js%20%7C%20OpenStreetMap-199900.svg?style=flat&logo=leaflet)](https://leafletjs.com)
[![Database](https://img.shields.io/badge/Database-TinyDB%20(Thread--Safe%20JSON)-FFA000.svg?style=flat)](https://tinydb.readthedocs.io)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Document Overview & Purpose

This document serves two distinct functions:
1. **Section A — Technical Developer Guide**: Complete setup instructions, environment dependencies, API documentation, and architecture for developers running and maintaining the repository.
2. **Section B — SIH Presentation Content**: A structured, slide-by-slide, presentation-ready reference designed specifically for the team to directly extract text, diagrams, tables, and talking points for the **Smart India Hackathon (SIH)** PPT.

---

# SECTION A: TECHNICAL DEVELOPER MANUAL

## ⚡ Quick Start (Developer Setup)

### Prerequisites
- **Python**: Version 3.10 or higher (`python --version`)
- **Node.js**: Version 18 or higher (`node --version`)
- **Package Managers**: `pip` (Python) and `npm` (Node.js)

---

### Step 1: Install Dependencies

#### Backend (Python FastAPI)
```bash
cd backend
pip install -r requirements.txt
cd ..
```
*Dependencies installed*: `fastapi>=0.115.0`, `uvicorn[standard]>=0.30.0`, `pydantic>=2.8.0`, `requests>=2.32.0`, `tinydb>=4.8.0`, `python-multipart>=0.0.9`, `httpx>=0.27.0`.

#### Frontend (React Vite)
```bash
cd frontend
npm install
cd ..
```
*Dependencies installed*: `react^19.2.8`, `react-dom^19.2.8`, `react-router-dom^7.18.3`, `leaflet^1.9.4`, `react-leaflet^5.0.0`, `chart.js^4.5.1`, `react-chartjs-2^5.3.1`, `vite^8.2.2`.

---

### Step 2: Running the Application

#### Option 1: One-Click Launcher (Windows)
Double-click `start_both.bat` located in the root directory. This launches:
1. The FastAPI backend server on `http://localhost:8000`
2. The Vite React frontend dev server on `http://localhost:5173`

#### Option 2: Manual Terminal Commands

**Terminal 1 — Python Backend:**
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — React Frontend:**
```bash
cd frontend
npm run dev
```

---

### Step 3: Verified Working Endpoints

| Service | Address | Description |
|---|---|---|
| **Web UI** | [http://localhost:5173](http://localhost:5173) | Primary Analyst Dashboard & Forensic UI |
| **API Server** | [http://localhost:8000](http://localhost:8000) | Root health check & API server |
| **Swagger UI** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive OpenAPI / Swagger test harness |
| **ReDoc UI** | [http://localhost:8000/redoc](http://localhost:8000/redoc) | Alternative schema documentation |

---

## 📂 Codebase File Organization

```
MailGuard/
├── start_both.bat               # Windows batch script to launch full stack
├── start_backend.bat            # Windows batch script for Python backend
├── start_frontend.bat           # Windows batch script for React frontend
├── package.json                 # Root npm project definition
├── README.md                    # Single Source of Truth documentation
│
├── backend/                     # Python FastAPI Backend
│   ├── main.py                  # App entry point, CORS middleware, router registration
│   ├── config.py                # Server port, host, storage paths, CORS configuration
│   ├── requirements.txt         # Pinned backend dependencies
│   ├── data/
│   │   ├── database.py          # TinyDB database manager (thread-safe CRUD)
│   │   └── threat_patterns.py   # Pattern libraries for phishing, BEC, TLDs, brands
│   ├── engine/                  # Core Intelligence & Forensic Engines
│   │   ├── header_parser.py     # RFC 822 email parser, relay path extraction, anomalies
│   │   ├── auth_validator.py    # SPF, DKIM, and DMARC alignment & validation logic
│   │   ├── nlp_analyzer.py      # Linguistic analysis: urgency, BEC, sentiment, phishing
│   │   ├── link_analyzer.py     # URL parsing, typosquatting, punycode, IP-in-URL
│   │   ├── ip_intelligence.py   # Asynchronous IP-API query, VPN/Proxy/Cloud hosting flags
│   │   ├── domain_intelligence.py# Levenshtein typosquatting, TLD abuse, disposable domains
│   │   └── threat_scorer.py     # Multi-vector heuristic threat aggregation formula
│   ├── models/
│   │   ├── request_models.py    # Pydantic input schemas (EmailAnalyzeRequest, etc.)
│   │   └── response_models.py   # Pydantic response models
│   ├── routers/
│   │   ├── analyze.py           # POST /api/analyze — Full forensic analysis pipeline
│   │   ├── geolocation.py       # POST /api/geo/lookup & /api/geo/batch
│   │   ├── cases.py             # CRUD /api/cases — Incident tracking
│   │   └── reports.py           # GET/DELETE /api/reports — Stored forensic records
│   └── storage/
│       └── db.json              # TinyDB JSON persistence file for cases and reports
│
└── frontend/                    # React 19 + Vite Frontend
    ├── index.html               # Main HTML entry point
    ├── vite.config.js           # Vite config with reverse proxy (/api -> :8000)
    ├── package.json             # Frontend package definitions
    └── src/
        ├── main.jsx             # React DOM root render
        ├── App.jsx              # React Router structure and global layout
        ├── index.css            # Dark cyber theme, CSS custom properties, responsive layout
        ├── components/          # Reusable UI widgets (Leaflet map, gauges, badges, charts)
        ├── context/
        │   └── EmailContext.jsx # Central state management (current email, cases, history)
        ├── pages/
        │   ├── Dashboard.jsx    # Metric cards, attack distribution charts, recent scans
        │   ├── EmailAnalyzer.jsx# Email header/body input, sample selector, tabbed forensic views
        │   ├── GeoTracer.jsx    # Leaflet world map with hop lines and IP markers
        │   ├── CaseManagement.jsx# Investigation case tracking, status updates, notes
        │   └── ForensicReport.jsx# Printable forensic evidence report
        ├── services/
        │   └── api.js           # Frontend client wrapper for backend REST calls
        └── data/
            ├── sampleEmails.js  # Curated real-world email samples for instant demonstration
            └── threatPatterns.js# Frontend threat constants and reference lists
```

---

# 📊 SIH PRESENTATION CONTENT
> **Notice for SIH Team Members**: All subsections below (1 through 24) are curated, fact-checked, and formatted for direct translation into slides, speaker notes, and demonstration walkthroughs.

---

## 1. Problem Statement

- **Problem Statement ID**: To be filled from the official SIH problem statement
- **Official Problem Statement Title**: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
- **Problem Domain**: Cyber Security / Digital Forensics / Incident Response (DFIR)
- **Why the Problem Matters**:
  - Email continues to be the primary attack vector for cyber espionage, ransomware delivery, credential theft, and financial fraud.
  - Organizations and individuals lose billions annually to Business Email Compromise (BEC) and sophisticated spear-phishing that easily bypass basic keyword spam filters.
- **Who Faces the Problem**:
  - Security Operations Center (SOC) analysts experiencing alert fatigue.
  - Cyber crime investigators and forensic examiners seeking verifiable digital trails.
  - Enterprise IT administrators needing rapid email triage tools.
  - Employees and general citizens targeted by deceptive social engineering.
- **Current Pain Points**:
  - **Tool Fragmentation**: Analysts must manually use 4–6 separate utilities (one for header parsing, one for WHOIS, one for IP geolocation, one for URL unshortening, one for SPF checks).
  - **Single-Signal Blindness**: Tools that only check body text miss header spoofing; tools that only check SPF/DKIM miss lookalike domains and urgent social engineering.
  - **Lack of Explainability**: Black-box filters flag emails as "Spam" without providing concrete, evidence-based reasoning or relay path visualization.
- **What Gap MailGuard Addresses**:
  - MailGuard bridges the gap between raw RFC 822 email headers and human-understandable forensic intelligence by providing a unified, multi-vector analysis pipeline that links **content semantics, sender authentication, transport headers, embedded links, and observable infrastructure geolocation** into a single explainable report.

---

## 2. Problem Analysis

Traditional email security systems fail because modern email attacks exploit multi-layered seams in email protocols and human psychology:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      THE MULTI-VECTOR ATTACK DILEMMA                            │
├───────────────────────┬─────────────────────────────────┬───────────────────────┤
│ Attack Vector         │ Why Single-Point Check Fails    │ MailGuard Correlated  │
│                       │                                 │ Defense Approach      │
├───────────────────────┼─────────────────────────────────┼───────────────────────┤
│ Deceptive Content &   │ Text looks like normal business │ NLP sentiment, fear,  │
│ Social Engineering    │ dialogue; lacks known virus     │ urgency & financial   │
│                       │ signatures.                     │ intent analysis.      │
├───────────────────────┼─────────────────────────────────┼───────────────────────┤
│ Display Name          │ SPF/DKIM pass because attacker  │ Checks From vs Reply- │
│ Spoofing              │ sends from their own authorized │ To vs Return-Path and │
│                       │ domain with a forged name.      │ brand keywords.       │
├───────────────────────┼─────────────────────────────────┼───────────────────────┤
│ Typosquatting /       │ Looks identical to human eye    │ Levenshtein distance  │
│ Lookalike Domains     │ (e.g., paypa1.com, micros0ft)   │ algorithmic matching  │
│                       │ and passes basic DNS lookups.   │ against trusted brands│
├───────────────────────┼─────────────────────────────────┼───────────────────────┤
│ Evasive Network       │ Origin hidden behind multiple   │ Hop-by-hop Received   │
│ Infrastructure        │ forwarders or bulletproof hosts │ chain parsing and     │
│                       │ in foreign jurisdictions.       │ IP-API enrichment.    │
└───────────────────────┴─────────────────────────────────┴───────────────────────┘
```

### Why Checking Single Dimensions Is Insufficient:
1. **Checking only Email Body is Insufficient**: Attackers use clean, polite text with zero vulgarity or typical spam phrases to execute high-value wire fraud.
2. **Checking only SPF/DKIM/DMARC is Insufficient**: An attacker can configure valid SPF/DKIM on a newly registered malicious lookalike domain (`evil-bank.com`), resulting in a technically "authenticated" malicious email.
3. **Checking only URLs is Insufficient**: Many sophisticated BEC attacks contain no links whatsoever; they request direct wire transfers or phone calls.
4. **Checking only Headers is Insufficient**: A legitimate newsletter might have multiple forwarding hops that look complex without being malicious.

**Core Thesis**: A reliable email threat assessment requires combining:
$$\text{CONTENT} + \text{AUTHENTICATION} + \text{HEADERS} + \text{LINKS} + \text{DOMAIN} + \text{INFRASTRUCTURE IP}$$

---

## 3. Proposed Solution

**MailGuard** is a hybrid cyber intelligence and forensic investigation platform that ingests raw email text or `.eml` files and performs an automated, 360-degree forensic examination.

### The Hybrid Architecture Paradigm:
MailGuard deliberately merges four distinct technical disciplines:
1. **Deterministic Forensic Analysis**: Strict verification of RFC 822 headers, `Received:` relay hop chains, and cryptographic SPF/DKIM/DMARC alignment.
2. **AI / NLP Heuristic Intelligence**: Natural language analysis evaluating urgency, coercive sentiment, executive impersonation, and payment diversion patterns.
3. **Infrastructure & Geolocation Intelligence**: Asynchronous lookup of public IP routing, ASN ownership, hosting provider detection, and Levenshtein domain typosquatting.
4. **Explainable Multi-Vector Scoring**: A transparent, weighted formula aggregating all findings into an explainable 0–100 threat score with clear analyst recommendations.

---

## 4. AI / NLP Intelligence

MailGuard implements intelligent linguistic and algorithmic detection without relying on external opaque cloud AI services or generating unverified hallucinations.

### Implemented AI & Intelligent Analysis Capabilities:

| Engine / Module | Source File | Implemented Mechanism | Signals Detected |
|---|---|---|---|
| **Linguistic Urgency & Pressure** | `backend/engine/nlp_analyzer.py` | Pattern matching, regex intensity scoring, exclamation & capital case density | "immediate action", "within 24 hours", "account suspended", "act now", excessive exclamation marks, ALL CAPS words |
| **Phishing Language & Credential Intent** | `backend/engine/nlp_analyzer.py` | Semantic intent classification and credential harvesting heuristics | "confirm your identity", "validate your credentials", "update payment", "security verification required", "enter your password" |
| **Executive & Brand Impersonation** | `backend/engine/nlp_analyzer.py` | Brand-to-domain mapping, title regex matching, and display name spoofing checks | Executive titles (CEO, CFO, CTO, Director), IT department, Helpdesk, HR/Payroll, brand names in display name with mismatched sender domain |
| **BEC & Financial Fraud Detection** | `backend/engine/nlp_analyzer.py` | Financial vocabulary extraction & wire transfer diversion heuristics | "wire transfer", "bank transfer", "update bank details", "new payment instructions", "gift cards", "payroll routing" |
| **Cognitive Manipulation Profiling** | `backend/engine/nlp_analyzer.py` | Sub-category sentiment scoring | Computes 4 individual psychological scores: **Fear Score**, **Urgency Score**, **Authority Score**, and **Reward Score** |
| **Domain Typosquatting AI** | `backend/engine/domain_intelligence.py` | Levenshtein string distance algorithm & brand root containment | Measures edit distance against protected brands (PayPal, Microsoft, Google, SBI, Chase, etc.); flags similarity $\ge 70\%$ and distance $\le 3$ |
| **Punycode & Homoglyph Detection** | `backend/engine/link_analyzer.py` | Internationalized Domain Name (IDN) parsing | Identifies `xn--` prefixes and homoglyphs used to deceive users |

> **Key Presentation Distinction**: MailGuard uses **deterministic heuristics and specialized NLP pattern-based sentiment scoring**, NOT deep neural networks or generative LLMs. This guarantees zero hallucination, sub-second execution times, and 100% explainable evidence.

---

## 5. Key Features

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         MAILGUARD FEATURE MATRIX                                 │
├──────────────────────────┬─────────────────────────────┬─────────────────────────┤
│ Feature                  │ Technical Operation         │ Forensic Value          │
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ RFC 822 Header Parsing   │ Structured header extraction│ Uncovers From/Reply-To/ │
│                          │ via regex & MIME parser     │ Return-Path mismatches  │
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ SMTP Relay               │ Reconstructs chronological  │ Identifies true origin  │
│ Reconstruction           │ hop sequence from Received: │ MTA and transmission lag│
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ Auth Verification        │ Parses Received-SPF, DKIM-  │ Proves whether sender is│
│ (SPF / DKIM / DMARC)     │ Signature, Auth-Results     │ authorized by domain DNS│
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ NLP Psychological        │ Computes Fear, Urgency,     │ Flags cognitive coercion│
│ Profiling                │ Authority & Reward scores   │ and social engineering  │
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ Link & Typosquatting     │ Scans body URLs, IP-links,  │ Prevents credential     │
│ Inspection               │ shorteners, suspicious TLDs │ harvesting via lookalike│
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ GeoTracer IP Mapping     │ Asynchronous IP-API queries │ Visualizes physical     │
│                          │ rendered on Leaflet.js map  │ network hop journey     │
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ Case Management          │ Thread-safe TinyDB storage  │ Enables ongoing triage  │
│                          │ for tagging & analyst notes │ and incident management │
├──────────────────────────┼─────────────────────────────┼─────────────────────────┤
│ Forensic Report          │ Synthesizes full dossier    │ Exportable, structured  │
│ Generation               │ with SHA-256 evidence logs  │ audit record            │
└──────────────────────────┴─────────────────────────────┴─────────────────────────┘
```

---

## 6. Technical Approach

### Architecture Layers & Stack

```
Frontend (React 19 + Vite)
  ├── UI & Routing: React Router v7, Vanilla Cyber CSS (Dark theme)
  ├── Visualization: Leaflet.js + OpenStreetMap, Chart.js (Threat Gauges & Distribution)
  └── Services: Fetch API client with Vite reverse proxy (/api -> :8000)
       │
       ▼ REST (JSON)
Backend (Python 3.10+ FastAPI)
  ├── ASGI Web Server: Uvicorn with auto-reload
  ├── Framework: FastAPI with Pydantic request/response validation
  ├── Forensic Core:
  │    ├── RFC 822 Header Parser & Anomaly Detection
  │    ├── Cryptographic & Alignment Authentication Validator
  │    ├── NLP Manipulation & Intent Analyzer
  │    ├── Link & URL Obfuscation Inspector
  │    └── Heuristic Threat Scoring Engine
  ├── External Intelligence: IP-API (Geolocation, ASN, Proxy/Hosting detection)
  └── Storage: TinyDB (Lightweight, serverless, thread-safe JSON document database)
```

---

## 7. System Workflow

```mermaid
flowchart TD
    A["User Submits Raw Email / .EML"] --> B["FastAPI Endpoint: POST /api/analyze"]
    
    subgraph S1["Parsing & Extraction"]
        B --> C["RFC 822 Parser: Extract Headers, Body, MIME"]
        C --> D["Extract Received Relay Chain & IPs"]
        C --> E["Extract Embedded URLs & Hyperlinks"]
    end
    
    subgraph S2["Multi-Vector Intelligence Engines"]
        D --> F["Header Anomaly Detector"]
        C --> G["Auth Validator: SPF, DKIM, DMARC"]
        C --> H["NLP Analyzer: Urgency, BEC, Manipulation"]
        E --> I["Link & Typosquatting Scanner"]
        D --> J["IP Intelligence & Geolocation Service"]
        C --> K["Domain Intelligence & TLD Analysis"]
    end
    
    subgraph S3["Correlation & Scoring"]
        F --> L["Threat Scorer: Weighted Multi-Vector Engine"]
        G --> L
        H --> L
        I --> L
        J --> L
        K --> L
        L --> M["Calculates Score (0-100), Level & Confidence"]
    end
    
    subgraph S4["Persistence & Output"]
        M --> N["Auto-Save to TinyDB Database (reports table)"]
        N --> O["Deliver JSON Response to Frontend"]
        O --> P["Frontend Updates: Threat Gauge, Map, Evidence Tables"]
    end
```

---

## 8. Threat Scoring Methodology

MailGuard implements a transparent, weighted aggregation algorithm in [`backend/engine/threat_scorer.py`](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/threat_scorer.py).

### Exact Mathematical Formula:
$$\text{ThreatScore} = \text{round}\left(\min\left(100, \sum_{i=1}^{6} (S_i \times W_i)\right)\right)$$

### Component Weights ($W_i$) and Formulas:

| Vector Component ($i$) | Weight ($W_i$) | Component Score Calculation ($S_i$) | File Reference |
|---|---|---|---|
| **Natural Language Processing (NLP)** | **0.30 (30%)** | `nlp_result["nlpScore"]` (weighted sum of urgency, phishing, BEC, impersonation, sentiment) | `backend/engine/nlp_analyzer.py` |
| **Sender Authentication** | **0.20 (20%)** | `100 - auth_result["overallScore"]` (inverts auth score: failing SPF/DKIM/DMARC yields high threat) | `backend/engine/auth_validator.py` |
| **Header Anomalies** | **0.15 (15%)** | `min(100, len(header_anomalies) * 20)` (20 points per detected header anomaly) | `backend/engine/header_parser.py` |
| **Link & URL Risk** | **0.15 (15%)** | `link_result["overallScore"]` (average risk of extracted links) | `backend/engine/link_analyzer.py` |
| **Domain Risk** | **0.10 (10%)** | `100 - domain_result["reputationScore"]` (penalizes disposable, typosquatted, or abusive TLDs) | `backend/engine/domain_intelligence.py` |
| **IP Infrastructure Risk** | **0.10 (10%)** | Max risk score across relay IPs: Proxy (+40), Hosting (+20), Critical/High Risk flags (+25 to +40) | `backend/engine/threat_scorer.py` |

### Threat Classifications & Risk Thresholds:

| Threat Score | Risk Level | Threat Classification Logic | Analyst Recommendation |
|---|---|---|---|
| **75 – 100** | `critical` | BEC score > 30 ➡️ **Fraud**<br>Impersonation > 30 ➡️ **Impersonation**<br>Score $\ge 65$ ➡️ **Phishing** | **BLOCK & QUARANTINE**: Highly malicious. Isolate links and sender. |
| **55 – 74** | `high` | Phishing / Suspicious | **FLAG & WARN**: Suspicious email. Quarantine pending admin review. |
| **35 – 54** | `medium` | Suspicious | **EXERCISE CAUTION**: Moderate risk. Verify identity via out-of-band channel. |
| **15 – 34** | `low` | Legitimate | **DELIVER NORMALLY**: Standard verification checks passed. |
| **0 – 14** | `minimal` | Legitimate | **DELIVER NORMALLY**: Clean telemetry. |

---

## 9. Forensic Intelligence

In forensic investigations, evidence integrity is paramount. MailGuard strictly separates **observable facts** from **analytical deductions**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       EVIDENCE LEVEL HIERARCHY IN MAILGUARD                     │
├──────────────────────┬──────────────────────────────────────────────────────────┤
│ Level 1: Observed    │ - Exact unedited RFC 822 headers                         │
│ Digital Evidence     │ - Hop-by-hop Received: timestamps and IP strings         │
│ (Tamper-Evident)     │ - Raw cryptographic signature headers (DKIM-Signature)   │
│                      │ - Unaltered email body text and exact raw hyperlinks     │
├──────────────────────┼──────────────────────────────────────────────────────────┤
│ Level 2: Technical   │ - SPF record authorization status (pass/fail/softfail)   │
│ Analysis Verdicts    │ - DMARC domain alignment confirmation                    │
│                      │ - Levenshtein distance string similarity score           │
│                      │ - Geolocation coordinates of observed relay servers      │
├──────────────────────┼──────────────────────────────────────────────────────────┤
│ Level 3: Evaluative  │ - NLP cognitive manipulation rating (Fear/Urgency)       │
│ Assessment           │ - Aggregate Threat Score (0–100)                         │
│                      │ - Triage recommendations (Block / Flag / Caution)        │
└──────────────────────┴──────────────────────────────────────────────────────────┘
```

> **Forensic Integrity Notice for Presentation**: MailGuard tracks **observed sending infrastructure** (mail transfer agents, intermediate relays, hosting providers). It does **not** assert physical human identification of the individual behind the keyboard, which is technically impossible from email headers alone.

---

## 10. Innovation and Uniqueness

| Innovation Area | What Is Different? | Why Is It Useful? |
|---|---|---|
| **1. Multi-Vector Correlation** | Connects 6 disparate layers (Headers + Auth + NLP + Links + Domain + IP) in one automated pass. | Eliminates analyst tool-switching; detects sophisticated multi-stage attacks that appear clean on single checks. |
| **2. Explainable Threat Math** | Every score is directly traceable to transparent arithmetic weights and documented findings. | Builds trust with analysts; provides defendable evidence suitable for organizational incident reports. |
| **3. Integrated Hop-by-Hop GeoTracer** | Parses sequential `Received:` headers and renders them as a chronological relay path on a global map. | Visually pinpoints anomalous routing (e.g., internal company email routing through an unexpected overseas VPS). |
| **4. Psychological Profiling NLP** | Dissects language into distinct cognitive drivers (Urgency, Fear, Authority, Reward). | Accurately catches Business Email Compromise (BEC) and wire fraud that contain zero malicious attachments or links. |
| **5. Lightweight Serverless Stack** | Runs entirely on FastAPI + TinyDB without demanding complex database servers or GPU clusters. | Instant deployment for rapid field triage on laptops, air-gapped forensic workstations, or cloud containers. |

---

## 11. User Journey

```
[ 1. Ingest Email ]
User pastes raw email text or loads a preloaded real-world attack scenario.
       │
       ▼
[ 2. Automated Deep Scan ]
FastAPI backend executes RFC parsing, SPF/DKIM/DMARC validation, NLP, and IP lookup in < 1.5s.
       │
       ▼
[ 3. Triage & Overview ]
Analyst views the radial Threat Gauge, overall risk tier, and key threat summary.
       │
       ▼
[ 4. Technical Inspection ]
Analyst clicks through specialized tabs:
  - Header Forensics: Inspects From vs Return-Path discrepancies.
  - Authentication Matrix: Verifies SPF/DKIM/DMARC status pills.
  - NLP Breakdown: Reviews extracted coercive phrases and sentiment bars.
  - Link Inspector: Audits scanned URLs, IP links, and typosquatted domains.
       │
       ▼
[ 5. Infrastructure Tracing ]
Analyst views the interactive Leaflet map to inspect geographic hops and hosting flags.
       │
       ▼
[ 6. Case Management & Reporting ]
Analyst attaches the investigation to an incident case, records notes, and exports the Forensic Report.
```

---

## 12. Feasibility

- **Open-Source Foundations**: Built using proven open-source technologies (Python FastAPI, React 19, Leaflet, OpenStreetMap, Chart.js, TinyDB).
- **Resource Efficiency**: Requires no heavy database services (e.g., PostgreSQL/MySQL) or GPU instances. Operates comfortably on standard consumer hardware (4GB RAM, dual-core CPU).
- **Extensible Architecture**: Modular engine directory structure (`backend/engine/`) allows plug-and-play addition of new detection algorithms or external threat intelligence feeds.
- **Immediate Deployability**: Pre-configured batch scripts (`start_both.bat`) and self-contained dependencies enable rapid installation on Windows, Linux, and macOS.

---

## 13. Viability

### Target Operational Environments:
1. **Tier-1 / Tier-2 SOC Triage**: Enables junior analysts to rapidly triage incoming user-reported phishing emails with standardized, objective criteria.
2. **Cyber Incident Response Teams (CIRT)**: Accelerates evidence collection during active BEC or corporate impersonation incidents.
3. **Law Enforcement & Forensics**: Generates structured, time-stamped dossiers of email transport paths and header artifacts.
4. **Academic & Cyber Training**: Serves as a hands-on pedagogical tool for demonstrating email protocol mechanics, authentication weaknesses, and social engineering.

---

## 14. Challenges and Limitations

| Challenge / Limitation | Technical Reality | MailGuard Architectural Mitigation |
|---|---|---|
| **Header Forgery** | Attackers can forge `From:` and arbitrary internal `Received:` headers. | MailGuard parses the **entire** Received chain from bottom to top and prioritizes the earliest authenticated public hop recorded by the receiving MTA. |
| **IP Geolocation Accuracy** | IP geolocation identifies the datacenter or ISP exchange point, not a human physical address. | The platform explicitly reports **infrastructure location** and disclaims physical human attribution. |
| **Rate Limits on Free APIs** | Public IP-API endpoints enforce rate limits on high-volume queries. | Built-in fallback handlers gracefully handle timeout/rate-limit exceptions, ensuring the core analysis completes uninterrupted. |
| **Evolving Linguistic Attacks** | Attackers continually adapt phrasing to evade specific keyword dictionaries. | MailGuard combines keyword presence with structural markers (urgency, capital density, punctuation) and structural authentication checks. |

---

## 15. Impact and Benefits

### For Security Analysts
- **Reduced Alert Fatigue**: Reduces manual header copy-pasting across disparate tools from 15 minutes down to seconds.
- **Clear Decision Guidance**: Clear action recommendations ("Block & Quarantine" vs "Exercise Caution").

### For Organizations
- **Financial Fraud Prevention**: Identifies BEC wire transfer scams before accounting teams release funds.
- **Standardized Documentation**: Consistent forensic reports for internal compliance and insurance audits.

### For Investigators
- **Structured Evidence Preservation**: Automatically preserves timestamps, header anomalies, and observable IP hops in an indexed JSON database.

---

## 16. Future Scope (Roadmap)

> **Transparency Note**: These features represent natural extensions of the MailGuard architecture for future development phases:

- 🔮 **Direct Mailbox Connectors**: Microsoft Graph API and Google Workspace integrations for automated inbox scanning.
- 🔮 **Generative AI Analyst Assistant**: Integration with LLM APIs (e.g., Google Gemini) to generate dynamic narrative intelligence briefings.
- 🔮 **Static Attachment Analysis**: File sandboxing and SHA-256 hash checking against threat intelligence databases (VirusTotal/HybridAnalysis).
- 🔮 **SIEM / SOAR Webhooks**: Automated JSON alerting to Splunk, Microsoft Sentinel, or Elasticsearch.
- 🔮 **Campaign Correlation Engine**: Cross-case clustering to detect coordinated phishing campaigns across multiple inboxes.

---

## 17. Security and Privacy

- **Local Execution**: All analysis algorithms (parsing, NLP, regex, scoring) run locally on the backend server; raw email body content is never broadcast to third-party AI services.
- **Input Validation**: Strict Pydantic schema validation on all API endpoints (`backend/models/request_models.py`) prevents malformed payload injection.
- **CORS Protection**: Explicitly configured CORS middleware in `backend/main.py` prevents unauthorized cross-origin browser abuse.
- **Safe Network Calls**: Geolocation queries send **only public IP addresses** to IP-API; no personal email content, subjects, or headers are shared.
- **Thread-Safe Storage**: Database writes are guarded by Python `threading.Lock()` to prevent race conditions or database corruption.

---

## 18. System Architecture

```mermaid
graph TD
    subgraph Client["Frontend Layer (React 19 + Vite)"]
        UI["Analyst UI: Dashboard, Analyzer, GeoTracer, Cases"]
        CTX["EmailContext (State Management)"]
        API_JS["API Client (services/api.js)"]
        UI <--> CTX
        CTX <--> API_JS
    end

    subgraph Server["Backend Layer (FastAPI)"]
        ROUTER["API Routers: /analyze, /geo, /cases, /reports"]
        API_JS -- "HTTP / JSON Proxy :5173 -> :8000" --> ROUTER
        
        subgraph Engines["Forensic Analysis Pipeline"]
            HP["header_parser.py"]
            AV["auth_validator.py"]
            NLP["nlp_analyzer.py"]
            LA["link_analyzer.py"]
            DI["domain_intelligence.py"]
            TS["threat_scorer.py"]
        end
        
        ROUTER --> HP
        HP --> AV & NLP & LA & DI
        AV & NLP & LA & DI --> TS
    end

    subgraph External["External Services"]
        GEO["IP-API (HTTP GET)"]
        LA & HP -.-> GEO
    end

    subgraph Storage["Persistence Layer"]
        DB["TinyDB (backend/storage/db.json)"]
        TS --> DB
        ROUTER <--> DB
    end
```

---

## 19. Project Structure

### Core Backend Modules (`backend/`):
- `main.py`: Configures FastAPI application, CORS rules, and mounts routers.
- `routers/analyze.py`: Coordinates the end-to-end execution of all forensic engines upon receiving an email.
- `routers/cases.py`: Full CRUD endpoints for creating, retrieving, updating, and deleting investigation cases.
- `routers/geolocation.py`: Dedicated endpoints for on-demand IP lookups and batch requests.
- `routers/reports.py`: Management endpoints for saved forensic reports.
- `data/database.py`: TinyDB interface wrapping thread locks around `cases_table` and `reports_table`.
- `engine/threat_scorer.py`: Central scoring orchestrator implementing the weighted multi-vector equation.

### Core Frontend Modules (`frontend/src/`):
- `pages/EmailAnalyzer.jsx`: Primary investigation interface with raw text input, sample selector, and tabbed analysis views.
- `pages/GeoTracer.jsx`: Standalone interactive world map plotting IP locations with Leaflet.js.
- `pages/Dashboard.jsx`: Executive statistics, recent scans list, and threat category distribution charts.
- `pages/CaseManagement.jsx`: Incident case tracking with status toggles (`new`, `in_progress`, `closed`) and tag filters.
- `pages/ForensicReport.jsx`: Printable audit dossier view.

---

## 20. Recommended SIH Demo Scenario

### Step-by-Step Live Presentation Guide:

1. **Step 1: The Hook (Dashboard Overview)**
   - **What to show**: The MailGuard Dashboard ([http://localhost:5173](http://localhost:5173)).
   - **What to say**: *"Security analysts face hundreds of alerts daily. MailGuard provides an instant visual overview of email threat distribution across phishing, BEC, and impersonation."*
   - **Evidence to point at**: The Metric Cards and Threat Distribution Doughnut Chart.

2. **Step 2: Loading the Attack (Email Analyzer)**
   - **What to show**: Navigate to **Email Analyzer**; open the **Sample Emails** dropdown; select **CEO Wire Fraud (BEC)**.
   - **What to say**: *"Here we have a targeted BEC attack pretending to be our CEO demanding an urgent confidential wire transfer. Notice there are no viruses or attachments."*
   - **Action**: Click **Analyze Threat**.

3. **Step 3: The Threat Assessment & Multi-Vector Findings**
   - **What to show**: The radial Threat Gauge jumps into the red (**Malicious**).
   - **What to say**: *"In under two seconds, MailGuard computed a weighted multi-factor threat score. Let's inspect why."*
   - **Evidence to point at**:
     - **Authentication Matrix**: Point to SPF/DMARC status pills showing failed domain alignment.
     - **NLP Tab**: Highlight the extracted urgency phrases (*"immediately"*, *"strictly confidential"*) and the **Authority & Urgency Sentiment** gauges.
     - **Header Forensics**: Show the mismatch between the claimed `From: CEO` display name and the actual unauthorized external return domain.

4. **Step 4: Tracking Infrastructure (GeoTracer)**
   - **What to show**: Switch to the **GeoTracer Map** tab.
   - **What to say**: *"By reconstructing the Received headers, MailGuard maps the email's physical transport hops across the globe, revealing that the connection originated from an overseas cloud hosting provider rather than internal corporate infrastructure."*
   - **Evidence to point at**: The Leaflet map markers, relay arcs, and hosting provider flags.

5. **Step 5: Incident Response (Case Management & Report)**
   - **What to show**: Click **Add to Case**, assign it to an investigation, and navigate to **Forensic Report**.
   - **What to say**: *"The analyst can immediately document the incident, update case notes, and print a courtroom-admissible forensic dossier for executive briefing or law enforcement."*

---

## 21. PPT Content Map (Slide-by-Slide Guide)

| Slide # | Slide Title | Primary Purpose | Recommended Visual | Source Data in README |
|---|---|---|---|---|
| **Slide 1** | **Title Slide** | Project Introduction | MailGuard Logo, Team Name, Problem Statement Title | Header & Section 1 |
| **Slide 2** | **Problem Analysis** | The Phishing & BEC Crisis | Multi-Vector Attack Dilemma comparison table | Section 2 |
| **Slide 3** | **Proposed Solution** | The MailGuard Platform | High-level 4-pillar concept diagram (Hybrid System) | Section 3 |
| **Slide 4** | **Innovation & Uniqueness** | Differentiators from existing tools | Key Innovation comparison table | Section 10 |
| **Slide 5** | **Technical Approach** | System Architecture & Stack | High-level architecture & stack overview | Section 6 & 18 |
| **Slide 6** | **AI / NLP & Cognitive Profiling** | Explaining the AI Component | NLP Sentiment gauges & linguistic signals table | Section 4 |
| **Slide 7** | **Deterministic Forensics & GeoTracer** | Transport & Header Intelligence | Screenshot of Leaflet Map & Relay Hop timeline | Section 5 & 9 |
| **Slide 8** | **Threat Scoring Methodology** | Explainable Mathematical Model | Mathematical formula with weights breakdown table | Section 8 |
| **Slide 9** | **User Journey & Triage Workflow** | Operational demonstration flow | Mermaid workflow flowchart | Section 7 & 11 |
| **Slide 10** | **Feasibility & Viability** | Real-world adoption potential | Target environments & operational viability points | Section 12 & 13 |
| **Slide 11** | **Challenges & Future Scope** | Honest limitations & Roadmap | Two-column layout: Limitations vs Roadmap | Section 14 & 16 |
| **Slide 12** | **Conclusion & References** | Summary & Technical Citations | Key impact takeaways & RFC reference list | Section 15 & 22 |

---

## 22. Research and References

The MailGuard architecture is built upon official internet standards, cybersecurity RFCs, and academic DFIR methodologies:

1. **RFC 5322 (Internet Message Format)** — *Internet Engineering Task Force (IETF)*
   - Defines the standard syntax for email headers, addressing, and message structure.
   - [https://datatracker.ietf.org/doc/html/rfc5322](https://datatracker.ietf.org/doc/html/rfc5322)
2. **RFC 7208 (Sender Policy Framework - SPF)** — *IETF*
   - Protocol authorizing sender IP addresses via DNS.
   - [https://datatracker.ietf.org/doc/html/rfc7208](https://datatracker.ietf.org/doc/html/rfc7208)
3. **RFC 6376 (DomainKeys Identified Mail - DKIM)** — *IETF*
   - Cryptographic signature validation for email message integrity.
   - [https://datatracker.ietf.org/doc/html/rfc6376](https://datatracker.ietf.org/doc/html/rfc6376)
4. **RFC 7489 (Domain-based Message Authentication - DMARC)** — *IETF*
   - Policy and reporting framework for domain alignment and enforcement.
   - [https://datatracker.ietf.org/doc/html/rfc7489](https://datatracker.ietf.org/doc/html/rfc7489)
5. **CISA Phishing Guidance & BEC Technical Reports** — *Cybersecurity and Infrastructure Security Agency*
   - Principles of social engineering detection, executive spoofing, and wire fraud indicators.
   - [https://www.cisa.gov](https://www.cisa.gov)
6. **Levenshtein Metric for Domain Typosquatting** — *Vladimir Levenshtein (1965)*
   - Algorithmic foundation for string distance comparison against protected brand names.

---

## 23. PPT Claim Verification Table

> **CRITICAL FOR PRESENTATION INTEGRITY**: Use this table to ensure team members make accurate, defensible statements during judging Q&A.

| Candidate PPT Claim | Supported by Code? | Exact Source File | Safe, Defensible Wording for Team |
|---|---|---|---|
| *"MailGuard is AI-Powered"* | **YES (Heuristic NLP)** | `backend/engine/nlp_analyzer.py` | *"MailGuard uses specialized NLP algorithms to analyze linguistic urgency, sentiment, and social engineering intent."* |
| *"Uses Deep Learning / Neural Networks"* | ❌ **NO** | N/A | *"Uses deterministic heuristic NLP and rule-based semantic classifiers to guarantee zero hallucination."* |
| *"Uses ChatGPT / Gemini / LLM"* | ❌ **NO** | N/A | *"Does not rely on third-party cloud LLMs; executes rapid, deterministic on-premise heuristic scoring."* |
| *"Detects Business Email Compromise (BEC)"* | **YES** | `backend/engine/nlp_analyzer.py` | *"Detects BEC patterns including wire transfers, invoice changes, and executive title impersonation."* |
| *"Pinpoints Attacker's Physical Home"* | ❌ **NO** | `backend/engine/ip_intelligence.py` | *"Maps the geographic location of the observed sending network infrastructure and mail transfer agents."* |
| *"Reconstructs Email Relay Paths"* | **YES** | `backend/engine/header_parser.py` | *"Parses the sequential Received headers to map the transmission route across intermediate servers."* |
| *"Validates SPF, DKIM, and DMARC"* | **YES** | `backend/engine/auth_validator.py` | *"Inspects authentication header records and verifies domain alignment."* |
| *"Scans for Domain Typosquatting"* | **YES** | `backend/engine/domain_intelligence.py` | *"Uses Levenshtein string distance to detect lookalike brand domains."* |
| *"Generates Forensic Reports"* | **YES** | `backend/routers/reports.py` | *"Produces structured forensic reports summarizing technical indicators and threat scores."* |
| *"Courtroom-Admissible Evidence"* | ⚠️ **PARTIAL** | N/A | *"Provides structured, verifiable technical evidence logs that follow forensic audit standards."* |
| *"Automated Real-Time Triage"* | **YES** | `backend/routers/analyze.py` | *"Completes full multi-vector parsing and scoring in sub-second execution time."* |

---

## 24. Implemented vs. Future Capabilities Audit

| System Capability | Implementation Status | Exact Implementation Evidence |
|---|---|---|
| **Raw Email Parsing (RFC 822)** | ✅ **IMPLEMENTED** | `backend/engine/header_parser.py` |
| **Relay Path Reconstruction** | ✅ **IMPLEMENTED** | `backend/engine/header_parser.py` (`reconstruct_relay_path`) |
| **Header Anomaly Detection** | ✅ **IMPLEMENTED** | `backend/engine/header_parser.py` (`detect_header_anomalies`) |
| **SPF/DKIM/DMARC Analysis** | ✅ **IMPLEMENTED** | `backend/engine/auth_validator.py` (`validate_authentication`) |
| **NLP Urgency & Sentiment** | ✅ **IMPLEMENTED** | `backend/engine/nlp_analyzer.py` (`_analyze_sentiment`, `_detect_urgency`) |
| **BEC & Financial Fraud Intent** | ✅ **IMPLEMENTED** | `backend/engine/nlp_analyzer.py` (`_detect_bec`) |
| **Link & Typosquatting Scanner** | ✅ **IMPLEMENTED** | `backend/engine/link_analyzer.py` (`analyze_links`) |
| **Levenshtein Domain Similarity** | ✅ **IMPLEMENTED** | `backend/engine/domain_intelligence.py` (`_check_typosquatting`) |
| **IP Geolocation & ASN Lookup** | ✅ **IMPLEMENTED** | `backend/engine/ip_intelligence.py` (`lookup_ip` via IP-API) |
| **Leaflet Map Visualization** | ✅ **IMPLEMENTED** | `frontend/src/components/GeoMap.jsx`, `pages/GeoTracer.jsx` |
| **Multi-Vector Threat Scorer** | ✅ **IMPLEMENTED** | `backend/engine/threat_scorer.py` (`calculate_threat_score`) |
| **Case Management (CRUD)** | ✅ **IMPLEMENTED** | `backend/routers/cases.py`, `data/database.py`, `frontend/src/pages/CaseManagement.jsx` |
| **Thread-Safe TinyDB Storage** | ✅ **IMPLEMENTED** | `backend/data/database.py`, `backend/storage/db.json` |
| **Forensic Report Generation** | ✅ **IMPLEMENTED** | `backend/routers/reports.py`, `frontend/src/pages/ForensicReport.jsx` |
| **Direct Mailbox IMAP/Graph Connector** | 🔮 *FUTURE* | Planned roadmap extension |
| **Attachment Malware Sandbox** | 🔮 *FUTURE* | Planned roadmap extension |
| **Generative AI Chat Assistant** | 🔮 *FUTURE* | Planned roadmap extension |
| **SIEM Syslog / Webhook Push** | 🔮 *FUTURE* | Planned roadmap extension |

---

## 📄 License
This project is developed for educational, cybersecurity defense, and research purposes under the **MIT License**.
