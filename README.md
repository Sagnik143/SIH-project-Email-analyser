# 🛡️ MailGuard — AI-Powered Email Threat Detection & Forensic Platform

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20Vite-61DAFB.svg?style=flat&logo=react)](https://react.dev)
[![Leaflet](https://img.shields.io/badge/Mapping-Leaflet%20Maps-199900.svg?style=flat&logo=leaflet)](https://leafletjs.com)
[![Database](https://img.shields.io/badge/Database-TinyDB%20(JSON)-FFA000.svg?style=flat)](https://tinydb.readthedocs.io)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **MailGuard** is an end-to-end cyber intelligence and forensic investigation platform designed for **Smart India Hackathon (SIH)**. It empowers cyber defense analysts, SOC teams, and law enforcement agencies to deconstruct suspicious emails, detect sophisticated phishing/BEC scams, track SMTP relay pathways across the globe on an interactive map, and generate courtroom-admissible forensic dossiers.

---

## 📑 Table of Contents

1. [🌟 Key Features](#-key-features)
2. [🏗️ Architecture & Tech Stack](#️-architecture--tech-stack)
3. [🚀 Beginner Quick Start Guide (Step-by-Step)](#-beginner-quick-start-guide-step-by-step)
4. [📂 Detailed Folder Structure](#-detailed-folder-structure)
5. [🧠 Core Forensic Engine Breakdown](#-core-forensic-engine-breakdown)
6. [🗄️ Database & Persistence Layer (TinyDB)](#️-database--persistence-layer-tinydb)
7. [📡 Complete REST API Reference](#-complete-rest-api-reference)
8. [🖥️ Frontend Pages & Workflows](#️-frontend-pages--workflows)
9. [🧪 Preloaded Attack Samples & Test Scenarios](#-preloaded-attack-samples--test-scenarios)
10. [🔧 Troubleshooting & Common Beginner Errors](#-troubleshooting--common-beginner-errors)
11. [🏆 Hackathon / SIH Demonstration Pitch Guide](#-hackathon--sih-demonstration-pitch-guide)

---

## 🌟 Key Features

- **Deep RFC 822 Header Parsing**: Extracts sender identity, return paths, message IDs, and every intermediate server hop.
- **Hop-by-Hop SMTP Relay Reconstructor**: Traces the chronological journey of an email from origin MTA to recipient mailbox.
- **Full Authentication Triad**: Validates **SPF** (Sender Policy Framework), **DKIM** (DomainKeys Identified Mail), and **DMARC** policy alignment.
- **NLP & Social Engineering Detector**: Scans email content for artificial urgency, executive impersonation (CEO fraud), BEC (Business Email Compromise), payment diversion, and emotional manipulation.
- **Link & Typosquatting Scanner**: Detects punycode attacks, IP-based URLs, lookalike spoofed domains, and credential harvesting landing pages.
- **Real-Time IP Geolocation (GeoTracer)**: Queries public IP intelligence to pinpoint geographic coordinates (latitude/longitude), ISP, Autonomous System (ASN), and flags VPN/Proxy/Cloud hosting infrastructure.
- **Interactive Leaflet Cyber Map**: Renders an animated global map showing exact server hops with curved relay lines.
- **Multi-Vector Threat Scoring**: Blends header anomalies, auth failures, NLP manipulation, link risk, and IP reputation into a normalized score (0–100) and risk level (**Legitimate**, **Suspicious**, **Malicious**).
- **Incident Case Management**: Organize forensic investigations into cases, tag incidents, update case statuses, and attach suspect emails.
- **Courtroom-Ready Forensic Reports**: Export forensic audit reports complete with SHA-256 hashes, evidence logs, and analyst recommendations.

---

## 🏗️ Architecture & Tech Stack

```
                     ┌──────────────────────────────────────────────┐
                     │          React 19 + Vite Frontend            │
                     │  (Tailored Dark UI, Leaflet, Chart.js)      │
                     │          Runs at http://localhost:5173       │
                     └──────────────────────┬───────────────────────┘
                                            │ Reverse Proxy (/api)
                                            ▼
                     ┌──────────────────────────────────────────────┐
                     │            FastAPI Python Backend            │
                     │          Runs at http://localhost:8000       │
                     └──────┬───────────────┬────────────────┬──────┘
                            │               │                │
            ┌───────────────┴────┐   ┌──────┴──────────┐   ┌─┴────────────────┐
            │  Forensic Engines  │   │  IP & Geo API   │   │  Database Layer  │
            │  - RFC Header      │   │  - ip-api.com   │   │  - TinyDB        │
            │  - SPF/DKIM/DMARC  │   │  - ASN & Proxy  │   │  - db.json       │
            │  - NLP & BEC       │   │    Detection    │   │  - Thread-Safe   │
            │  - Link & Typosquat│   └─────────────────┘   └──────────────────┘
            │  - Threat Scorer   │
            └────────────────────┘
```

| Layer | Component | Description |
|---|---|---|
| **Frontend** | React 19 + Vite | Fast, responsive single-page application with modern UI components |
| **Styling** | Vanilla Modern CSS | Custom properties, dark cyber aesthetic, glassmorphism, responsive grid |
| **Mapping** | Leaflet.js + OpenStreetMap | Interactive geospatial visualization of email relay pathways |
| **Analytics** | Chart.js & React-Chartjs-2 | Visual gauges, threat matrices, and statistical breakdowns |
| **Backend** | Python 3.10+ & FastAPI | High-performance asynchronous REST API framework |
| **Web Server** | Uvicorn (ASGI) | Lightning-fast asynchronous server with hot-reloading |
| **Database** | TinyDB | Lightweight, serverless document-oriented JSON database with thread locks |
| **Intelligence** | IP-API / Custom Heuristics | Real-time IP geolocation, proxy/VPN/hosting detection, domain reputation |

---

## 🚀 Beginner Quick Start Guide (Step-by-Step)

Follow these simple steps to run the entire platform on your computer.

### Prerequisites Checklist
Make sure you have installed:
1. **Python** (version 3.10 or higher) — [Download Python](https://www.python.org/downloads/) *(⚠️ Check the box: "Add Python to PATH" during installation)*
2. **Node.js** (version 18 or higher) — [Download Node.js](https://nodejs.org/)
3. **Git** (optional, to clone the repo) — [Download Git](https://git-scm.com/)

---

### Step 1: Clone or Open the Repository
Open PowerShell or Command Prompt and navigate to the project directory:
```bash
cd c:\Users\User\OneDrive\Desktop\SIH\MailGuard
```

---

### Step 2: Install Backend Dependencies
Navigate into the `backend` folder and install the required Python packages:
```bash
cd backend
pip install -r requirements.txt
cd ..
```
*Packages installed: `fastapi`, `uvicorn`, `pydantic`, `requests`, `tinydb`, `python-multipart`, `httpx`.*

---

### Step 3: Install Frontend Dependencies
Navigate into the `frontend` folder and install the Node.js packages:
```bash
cd frontend
npm install
cd ..
```
*Packages installed: `react`, `react-dom`, `vite`, `react-router-dom`, `leaflet`, `react-leaflet`, `chart.js`, `react-chartjs-2`.*

---

### Step 4: Run the Application

#### Option A: One-Click Launcher (Easiest for Windows)
Simply double-click the file:
```
start_both.bat
```
This automatically launches both the backend and frontend in separate command windows!

---

#### Option B: Run Manually via Terminal

**Terminal 1 — Start the Backend:**
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Start the Frontend:**
```bash
cd frontend
npm run dev
```

---

### Step 5: Access the Web Interfaces

| Service | URL | Purpose |
|---|---|---|
| **Frontend Web App** | [http://localhost:5173](http://localhost:5173) | Primary Analyst Dashboard & Forensic UI |
| **Backend API Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive Swagger UI (Test endpoints live) |
| **Alternative Docs** | [http://localhost:8000/redoc](http://localhost:8000/redoc) | Clean ReDoc API reference |
| **Health Check** | [http://localhost:8000/api/health](http://localhost:8000/api/health) | Backend online status indicator |

---

## 📂 Detailed Folder Structure

```
MailGuard/
│
├── start_both.bat               # Windows batch script to launch full stack with one click
├── start_backend.bat            # Windows batch script for Python FastAPI
├── start_frontend.bat           # Windows batch script for React Vite
├── package.json                 # Root npm helper scripts
├── README.md                    # Complete project documentation
│
├── backend/                     # Python FastAPI Backend
│   ├── main.py                  # API entry point, CORS middleware, route registration
│   ├── config.py                # Server port, host, CORS origins, DB file paths
│   ├── requirements.txt         # Python dependencies
│   │
│   ├── data/
│   │   ├── database.py          # TinyDB database engine (thread-safe CRUD for cases & reports)
│   │   └── threat_patterns.py   # Phishing keywords, BEC triggers, trusted domains, disposable TLDs
│   │
│   ├── engine/                  # Core Intelligence & Forensic Engines
│   │   ├── header_parser.py     # RFC 822 email parser, Received header extraction, anomaly detector
│   │   ├── auth_validator.py    # SPF, DKIM, and DMARC alignment & validation logic
│   │   ├── nlp_analyzer.py      # Natural language processing for urgency, fear, and BEC detection
│   │   ├── link_analyzer.py     # URL extractor, typosquatting detector, IP-in-URL checker
│   │   ├── ip_intelligence.py   # IP geolocation (ip-api.com), VPN/Proxy/Cloud hosting detector
│   │   ├── domain_intelligence.py# Domain reputation, Levenshtein distance typosquatting, TLD abuse
│   │   └── threat_scorer.py     # Multi-factor mathematical threat scoring algorithm (0-100)
│   │
│   ├── models/
│   │   ├── request_models.py    # Pydantic schemas for API inputs (Analyze, Geo, Cases, Reports)
│   │   └── response_models.py   # Pydantic response data structures
│   │
│   ├── routers/
│   │   ├── analyze.py           # POST /api/analyze — End-to-end email analysis endpoint
│   │   ├── geolocation.py       # POST /api/geo/lookup & /api/geo/batch
│   │   ├── cases.py             # CRUD endpoints for /api/cases
│   │   └── reports.py           # GET and DELETE endpoints for /api/reports
│   │
│   └── storage/
│       └── db.json              # Local persistent JSON database created by TinyDB
│
└── frontend/                    # React 19 + Vite Frontend
    ├── index.html               # Web application HTML shell
    ├── vite.config.js           # Vite configuration & reverse proxy (/api -> :8000)
    ├── package.json             # Frontend dependencies & build scripts
    │
    └── src/
        ├── main.jsx             # React entry point
        ├── App.jsx              # Routing & application skeleton
        ├── index.css            # Cyber dark-mode design system & typography
        │
        ├── components/          # Reusable UI Components
        │   ├── Navbar.jsx       # Header bar with live backend status indicator
        │   ├── Sidebar.jsx      # Navigation sidebar (Dashboard, Analyzer, GeoTracer, Cases, Reports)
        │   ├── ThreatGauge.jsx  # Radial gauge component displaying threat score & risk level
        │   ├── RelayPath.jsx    # Visual timeline diagram of email hops
        │   ├── GeoMap.jsx       # Interactive Leaflet map plotting IP coordinates
        │   ├── AuthBadge.jsx    # SPF/DKIM/DMARC status pills (Pass/Fail/Neutral)
        │   └── StatCard.jsx     # Dashboard metric card widget
        │
        ├── context/
        │   └── EmailContext.jsx # Global React state for current email, history, cases, and reports
        │
        ├── pages/               # Main Application Views
        │   ├── Dashboard.jsx    # Executive overview, threat distribution, recent scans
        │   ├── EmailAnalyzer.jsx# Email header/body inspector, sample selector, forensic report tab
        │   ├── GeoTracer.jsx    # Standalone interactive IP & relay tracer map
        │   ├── CaseManagement.jsx# Forensic investigation cases with status & note editing
        │   └── ForensicReport.jsx# Printable forensic dossier & evidence summary
        │
        ├── services/
        │   └── api.js           # Client HTTP service wrapper communicating with backend
        │
        └── data/
            ├── sampleEmails.js  # Curated realistic emails (Phishing, BEC, Spoofed, Clean)
            └── threatPatterns.js# Frontend threat constants and reference lists
```

---

## 🧠 Core Forensic Engine Breakdown

### 1. RFC 822 Header Parser (`header_parser.py`)
- Reads raw MIME/RFC 822 email content.
- Extracts standard headers: `From`, `To`, `Subject`, `Date`, `Return-Path`, `Reply-To`, `Message-ID`.
- Reconstructs the complete SMTP **`Received:`** header chain.
- Analyzes header discrepancies:
  - **Mismatched Return-Path**: Flags when the sender address does not match the return envelope.
  - **Suspicious Reply-To**: Catches attackers directing victim replies to external disposable inboxes.
  - **Forged Message-IDs**: Identifies random or non-standard message identifiers.

### 2. Authentication Validator (`auth_validator.py`)
- **SPF (Sender Policy Framework)**: Inspects the originating MTA IP against the declared SPF authorization policy.
- **DKIM (DomainKeys Identified Mail)**: Evaluates cryptographic digital signatures for tampering and domain alignment.
- **DMARC (Domain-based Message Authentication)**: Verifies if both SPF and DKIM pass with identifier alignment (`p=reject`, `p=quarantine`, `p=none`).

### 3. NLP & Cognitive Manipulation Engine (`nlp_analyzer.py`)
Analyzes the subject line and body using cybersecurity-tailored natural language processing:
- **Urgency Scoring**: Detects pressure tactics ("Immediate action required", "Account suspended in 24 hours").
- **Financial & BEC Indicators**: Flags wire transfer requests, payroll updates, gift card schemes, and vendor invoice alterations.
- **Authority & Executive Impersonation**: Detects attempts to pose as the CEO, CFO, HR Director, or IT Support.
- **Manipulation Sentiment Breakdown**: Computes granular sub-scores for Fear, Urgency, Authority, Reward, and Deception.

### 4. Link & Domain Intelligence (`link_analyzer.py` & `domain_intelligence.py`)
- Extracts all URLs and HTML hyperlinks.
- **Punycode / Homograph Detection**: Uncovers Cyrillic or Unicode characters used to impersonate legitimate domains (e.g., `microsоft.com` with Cyrillic `о`).
- **IP-Based URLs**: Flags raw IP address links (e.g., `http://192.168.1.1/login`).
- **Typosquatting Distance**: Calculates Levenshtein string distance against top 100 brands (e.g., `paypa1.com` vs `paypal.com`).
- **TLD Risk Rating**: Flags high-abuse top-level domains (`.xyz`, `.top`, `.tk`, `.ru`, `.click`).

### 5. IP Intelligence & GeoTracer (`ip_intelligence.py`)
- Resolves each intermediate relay hop to:
  - Country, Region, City
  - Geographic Coordinates (Latitude, Longitude)
  - ISP and Autonomous System (ASN)
  - Reverse DNS hostname
- **Anonymization Detection**: Identifies whether the IP belongs to a commercial VPN, TOR exit node, public proxy, or cloud hosting provider (AWS, Azure, DigitalOcean, OVH).

### 6. Multi-Factor Threat Scorer (`threat_scorer.py`)
Combines all vectors using an intelligent weighted scoring algorithm:

$$\text{Final Threat Score} = (W_{\text{auth}} \times S_{\text{auth}}) + (W_{\text{nlp}} \times S_{\text{nlp}}) + (W_{\text{links}} \times S_{\text{links}}) + (W_{\text{headers}} \times S_{\text{headers}}) + (W_{\text{ip}} \times S_{\text{ip}}) + (W_{\text{domain}} \times S_{\text{domain}})$$

| Threat Score Range | Classification | Action Recommended |
|---|---|---|
| **0 – 29** | 🟢 **Legitimate** | Standard delivery, low risk |
| **30 – 69** | 🟡 **Suspicious** | Quarantine, review attachments, warn user |
| **70 – 100** | 🔴 **Malicious (Critical)** | Block sender, isolate workstation, trigger SOC alert |

---

## 🗄️ Database & Persistence Layer (TinyDB)

MailGuard uses **TinyDB**, a lightweight, serverless document database written purely in Python.
- **Location**: [`backend/storage/db.json`](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/storage/db.json)
- **Zero Configuration**: No MySQL, PostgreSQL, or Docker required — works instantly out-of-the-box.
- **Thread Safety**: Uses Python `threading.Lock()` to prevent race conditions during concurrent API requests.

### Database Schema

#### Table 1: `cases`
Stores forensic investigation cases created by analysts:
```json
{
  "id": "CASE-1788855752309",
  "name": "Finance Dept Impersonation Attack",
  "status": "in_progress",
  "emails": ["EMAIL-1788855805583"],
  "notes": "Suspect IP belongs to an offshore bulletproof host.",
  "tags": ["phishing", "bec", "urgent"],
  "createdAt": "2026-09-08T08:22:32Z",
  "updatedAt": "2026-09-08T08:22:56Z"
}
```

#### Table 2: `reports`
Stores full forensic analysis results generated by the `/api/analyze` engine:
```json
{
  "id": "EMAIL-1788855805583",
  "timestamp": "2026-09-08T08:23:25Z",
  "raw": "Received: from ...",
  "parsed": { "from": { "name": "CEO", "email": "ceo@fake.com" }, "subject": "Wire Transfer" },
  "relayPath": [...],
  "authResult": { "spf": "fail", "dkim": "none", "dmarc": "fail" },
  "nlpResult": { "urgency": 85, "sentiment": { "fearScore": 40 } },
  "linkResult": { "highRiskLinks": 2 },
  "ipResults": [...],
  "threatAssessment": {
    "threatScore": 88,
    "classification": "malicious",
    "riskLevel": "high"
  }
}
```

---

## 📡 Complete REST API Reference

The backend provides a fully documented RESTful API. Below are the key endpoints:

### 1. Health Check
- **Endpoint**: `GET /api/health`
- **Description**: Verify backend is alive and healthy.
- **Response**:
```json
{
  "status": "online",
  "service": "MailGuard Forensic Intelligence API",
  "version": "1.0.0",
  "docs": "/docs"
}
```

---

### 2. Email Threat Analysis
- **Endpoint**: `POST /api/analyze`
- **Description**: Submits raw RFC 822 email text for deep forensic examination. Automatically saves the resulting report to TinyDB.
- **Request Body**:
```json
{
  "raw": "Received: from mail.evil.com [198.51.100.4] ...\nFrom: CEO <ceo@company.com>\nSubject: Urgent Wire Transfer\n\nPlease transfer $50,000 immediately."
}
```
- **Response**:
```json
{
  "id": "EMAIL-1788855805583",
  "timestamp": "2026-09-08T08:23:25Z",
  "threatAssessment": {
    "threatScore": 92,
    "classification": "malicious",
    "riskLevel": "high",
    "summary": "Critical threat detected: BEC wire fraud with forged headers and SPF failure."
  },
  "authResult": { "spf": "fail", "dkim": "fail", "dmarc": "fail" },
  "nlpResult": { "urgency": { "score": 90 }, "bec": { "score": 95 } },
  "relayPath": [ ... ]
}
```

---

### 3. IP Geolocation Lookup
- **Endpoint**: `POST /api/geo/lookup`
- **Request Body**:
```json
{
  "ip": "8.8.8.8"
}
```
- **Response**:
```json
{
  "ip": "8.8.8.8",
  "country": "United States",
  "countryCode": "US",
  "city": "Ashburn",
  "lat": 39.03,
  "lon": -77.5,
  "isp": "Google LLC",
  "isProxy": false,
  "isHosting": true,
  "riskIndicators": [
    { "type": "HOSTING_PROVIDER", "severity": "medium", "description": "Cloud infrastructure" }
  ]
}
```

---

### 4. Case Management (CRUD)
- `GET /api/cases` — Retrieve all cases
- `POST /api/cases` — Create a new case
  - Request: `{"name": "Incident #1", "notes": "Initial triage", "tags": ["phishing"]}`
- `GET /api/cases/{case_id}` — Get single case details
- `PUT /api/cases/{case_id}` — Update case status (`new`, `in_progress`, `closed`), notes, or tags
- `DELETE /api/cases/{case_id}` — Delete case from database
- `POST /api/cases/{case_id}/emails` — Link an analyzed email ID to a case

---

### 5. Forensic Reports Management
- `GET /api/reports` — List all stored forensic reports
- `GET /api/reports/{report_id}` — Retrieve specific report
- `DELETE /api/reports/{report_id}` — Delete report

---

## 🖥️ Frontend Pages & Workflows

### 1. Dashboard (`/`)
- **Threat Metric Cards**: Total Analyzed, High Risk Threats, Suspicious Flags, Clean Messages.
- **Threat Breakdown Chart**: Doughnut distribution of attack categories (Phishing, BEC, Spoofing, Spam).
- **Recent Investigations Feed**: Quick links to the latest analyzed emails and active cases.

### 2. Email Analyzer (`/analyzer`)
- **Raw Email Input**: Paste any RFC 822 email header and body.
- **Sample Email Dropdown**: One-click selection of preloaded real-world attack samples.
- **Multi-Tab Forensic Dossier**:
  - **Threat Overview**: Radial threat gauge, risk factors, and actionable analyst recommendations.
  - **Header Forensics**: Color-coded table of sender, return-path, reply-to, and forged anomalies.
  - **Authentication Matrix**: SPF, DKIM, and DMARC alignment badges with RFC explanation.
  - **Relay Path**: Visual hop-by-hop diagram showing transmission delays and hop IP details.
  - **NLP & Social Engineering**: Sentiment bars for fear, urgency, authority, and extracted keywords.
  - **Links & Typosquatting**: Table of URLs scanned, suspicious TLD warnings, and lookalike domains.

### 3. GeoTracer Map (`/geotracer`)
- **Interactive Leaflet World Map**: Dark cartographic tiles displaying every server relay hop.
- **Relay Pathway Arcs**: Animated lines tracing the journey of the email from origin to destination.
- **Interactive Hop Markers**: Click any marker to view City, Country, ISP, Autonomous System, and Anonymizer flags.

### 4. Case Management (`/cases`)
- Create new investigative incident files.
- Track case lifecycle: `New` ➡️ `In Progress` ➡️ `Closed`.
- Add analyst notes, tag attack vectors (`credential-theft`, `ceo-fraud`, `malware`), and associate analyzed emails.

### 5. Forensic Report (`/reports`)
- Comprehensive audit report generated for incident response, HR, or law enforcement.
- Export or print directly to PDF for formal documentation.

---

## 🧪 Preloaded Attack Samples & Test Scenarios

The platform includes built-in realistic email datasets for instant testing (found in the sample dropdown inside the **Email Analyzer**):

1. 🟢 **Legitimate Business Email**:
   - Passed SPF, DKIM, and DMARC.
   - Clean URLs and neutral tone.
   - Result: **Score: 10–25 (Legitimate)**.
2. 🔴 **CEO Impersonation Wire Fraud (BEC)**:
   - Spoofed display name from external domain, high artificial urgency, requesting immediate wire transfer.
   - Result: **Score: 85–95 (Malicious - Critical)**.
3. 🔴 **PayPal Credential Harvesting Phishing**:
   - Link directs to `paypa1-security.com`, forged headers, threatening account suspension.
   - Result: **Score: 90–98 (Malicious - Critical)**.
4. 🟡 **Suspicious Vendor Invoice Alteration**:
   - Mismatched Return-Path, unfamiliar offshore relay MTA.
   - Result: **Score: 50–65 (Suspicious)**.
5. 🟡 **Domain Spoofing (SPF/DMARC Failure)**:
   - Legitimate brand in `From:`, but originating from an unauthorized residential IP.
   - Result: **Score: 60–75 (Suspicious / High Risk)**.

---

## 🔧 Troubleshooting & Common Beginner Errors

### Issue 1: `'vite' is not recognized as an internal or external command`
- **Cause**: Node.js dependencies have not been installed inside the `frontend` directory.
- **Fix**:
  ```bash
  cd frontend
  npm install
  npm run dev
  ```

---

### Issue 2: `ModuleNotFoundError: No module named 'tinydb'`
- **Cause**: Python dependencies have not been installed in your Python environment.
- **Fix**:
  ```bash
  cd backend
  pip install -r requirements.txt
  ```

---

### Issue 3: Port 8000 or 5173 is already in use
- **Cause**: Another program (or a previously running instance of MailGuard) is using the port.
- **Fix for Windows**:
  1. Find the process on port 8000:
     ```powershell
     netstat -ano | findstr :8000
     ```
  2. Kill the process by PID:
     ```powershell
     taskkill /PID <PID_NUMBER> /F
     ```

---

### Issue 4: Frontend cannot connect to backend (`Failed to fetch`)
- **Check**: Ensure Uvicorn is running in your backend terminal (`python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload`).
- **Test**: Open [http://localhost:8000/api/health](http://localhost:8000/api/health) in your browser. If you see `{"status": "online"}`, the backend is functioning properly.

---

## 🏆 Hackathon / SIH Demonstration Pitch Guide

When presenting to judges or evaluating teams, use this recommended **3-Minute Walkthrough Flow**:

1. **Problem Hook (30 sec)**:
   > *"Phishing and Business Email Compromise account for over 80% of cyber security breaches. Standard email filters only flag known spam, but fail to detect targeted social engineering, forged relay headers, and executive spoofing."*

2. **The Solution (30 sec)**:
   > *"MailGuard is an AI-powered forensic threat platform. It combines RFC 822 header inspection, cryptographic SPF/DKIM/DMARC validation, NLP manipulation scoring, and IP geolocation into a unified defense dashboard."*

3. **Live Demo (90 sec)**:
   - Open **Email Analyzer** ([http://localhost:5173/analyzer](http://localhost:5173/analyzer)).
   - Load sample: **CEO Wire Fraud** and click **Analyze Threat**.
   - Show the **Threat Gauge** jump to **Malicious**.
   - Navigate through the **Authentication Matrix** showing SPF/DMARC failure.
   - Highlight the **NLP Breakdown** showing extreme urgency and authority sentiment.
   - Switch to **GeoTracer Map** to show the global relay path pinpointing the attacker's server.
   - Show the **Case Management** screen and how the incident is persisted in the database.

4. **Conclusion & Impact (30 sec)**:
   > *"MailGuard reduces incident triage time from hours to seconds and provides automated, courtroom-admissible forensic documentation for security teams."*

---

## 📄 License
This project is developed for educational, cybersecurity defense, and research purposes under the **MIT License**.
