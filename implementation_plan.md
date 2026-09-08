# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

## Overview
Build a full-featured, premium web application for SIH that enables security analysts to detect phishing/spoofed/fraudulent emails, trace their origin via IP geolocation, analyze email headers forensically, and generate investigative reports — all powered by AI/NLP analysis with a stunning, modern dashboard UI.

## Tech Stack

| Layer | Technology |
|---|---|
| **Framework** | Vite + React (JavaScript) |
| **Styling** | Vanilla CSS with CSS custom properties, glassmorphism, dark theme |
| **Maps** | Leaflet.js (OpenStreetMap tiles) for geolocation visualization |
| **Charts** | Chart.js for threat analytics & statistics |
| **IP Geolocation** | ip-api.com (free, no key required) |
| **AI/NLP Engine** | Client-side heuristic + keyword NLP engine (pattern matching, Bayesian scoring, urgency detection) |
| **Email Parsing** | Custom JavaScript email header parser (RFC 822 compliant) |
| **State Management** | React Context + useReducer |
| **Routing** | React Router v6 |

---

## Proposed Changes

### 1. Project Scaffold

#### [NEW] Project initialization via Vite
- `npm create vite@latest ./ -- --template react` in the SIH PROJECT directory
- Install dependencies: `react-router-dom`, `chart.js`, `react-chartjs-2`, `leaflet`, `react-leaflet`

---

### 2. Design System & Global Styles

#### [NEW] `src/index.css`
- Complete dark-mode design system with CSS custom properties
- Color palette: Deep navy (`#0a0e1a`), electric blue (`#00d4ff`), neon green (`#00ff88`), warning amber (`#ffaa00`), danger red (`#ff4444`)
- Glassmorphism card components with `backdrop-filter`
- Smooth micro-animations (fade-in, slide-up, pulse, glow effects)
- Typography: Google Fonts (Inter + JetBrains Mono for code)
- Responsive grid system

---

### 3. Core Application Structure

#### [NEW] `src/App.jsx`
- Root application with React Router
- Sidebar navigation with animated active states
- Global context providers (EmailContext, ThemeContext)
- Layout with collapsible sidebar + main content area

#### [NEW] `src/context/EmailContext.jsx`
- Global state for analyzed emails, threat reports, case management
- Actions: ADD_EMAIL, ANALYZE_EMAIL, UPDATE_THREAT_SCORE, ADD_TO_CASE, GENERATE_REPORT

#### [NEW] `src/context/ThemeContext.jsx`
- Dark/light mode toggle (default: dark)

---

### 4. Email Analysis Engine (Core Intelligence)

#### [NEW] `src/engine/headerParser.js`
- Parse raw email headers (Received, Return-Path, From, Reply-To, Message-ID, X-Originating-IP)
- Extract all IP addresses from Received chain
- Reconstruct full SMTP relay path (hop-by-hop)
- Detect header anomalies (mismatched From/Return-Path, forged Received headers)

#### [NEW] `src/engine/authValidator.js`
- SPF validation analysis (parse SPF records, check alignment)
- DKIM signature validation (parse DKIM headers, check selector/domain)
- DMARC policy check (alignment mode, policy enforcement)
- Generate authentication score (0-100)

#### [NEW] `src/engine/nlpAnalyzer.js`
- **Urgency Detection**: Scan for urgent language patterns ("immediately", "within 24 hours", "account suspended", "verify now")
- **Impersonation Detection**: Check for brand name spoofing (bank names, CEO titles, IT department)
- **Phishing Indicators**: Detect suspicious URL patterns, credential harvesting keywords, fake login prompts
- **Social Engineering Patterns**: Gift card scams, wire transfer requests, fake invoice language
- **BEC Detection**: Executive impersonation, payment diversion, vendor fraud patterns
- **Sentiment Analysis**: Calculate manipulation score based on fear/urgency/authority language
- **Confidence Scoring**: Weighted multi-factor threat score (0-100)

#### [NEW] `src/engine/linkAnalyzer.js`
- Extract all URLs from email body
- Detect URL obfuscation (IP-based URLs, URL shorteners, Unicode homograph attacks)
- Check for domain lookalikes (typosquatting detection)
- Identify suspicious TLDs
- Flag credential harvesting patterns in URLs

#### [NEW] `src/engine/ipIntelligence.js`
- IP geolocation lookup via ip-api.com
- VPN/Proxy/TOR detection heuristics
- Cloud provider identification (AWS, Azure, GCP, DigitalOcean)
- Known malicious IP range checking
- ISP and organization analysis

#### [NEW] `src/engine/domainIntelligence.js`
- Domain age estimation heuristics
- Typosquatting detection (Levenshtein distance against known brands)
- Free email provider detection
- Domain reputation scoring
- MX record analysis patterns

#### [NEW] `src/engine/threatScorer.js`
- Aggregate all analysis modules into unified threat score
- Category classification: LEGITIMATE, SUSPICIOUS, PHISHING, IMPERSONATION, FRAUD, MALWARE
- Confidence percentage with breakdown by factor
- Generate human-readable threat summary

---

### 5. Pages & Components

#### [NEW] `src/pages/Dashboard.jsx`
- **Hero Stats**: Total emails analyzed, threats detected, active cases, avg threat score
- **Threat Timeline Chart**: Line chart showing threat detections over time (Chart.js)
- **Threat Distribution**: Doughnut chart by category (phishing, spoofing, BEC, etc.)
- **Recent Alerts**: Live-updating list of high-risk emails with severity badges
- **World Map Widget**: Mini Leaflet map showing recent threat origins
- **Top Threat Domains**: Bar chart of most-seen malicious domains

#### [NEW] `src/pages/EmailAnalyzer.jsx`
- **Raw Email Input**: Large textarea for pasting raw email (headers + body)
- **File Upload**: Drag-and-drop .eml file support
- **Sample Emails**: Pre-loaded sample phishing/legitimate emails for demo
- **Analysis Trigger**: "Analyze Email" button with animated loading state
- **Results Panel**: Multi-tab results (Threat Score, Header Analysis, NLP Analysis, Link Analysis, Authentication)

#### [NEW] `src/pages/ThreatReport.jsx`
- Detailed forensic report for a single analyzed email
- **Threat Score Gauge**: Animated circular gauge (0-100)
- **Category Badge**: Color-coded threat classification
- **Header Forensics**: Expandable table of all parsed headers with anomaly highlighting
- **SMTP Relay Path**: Visual hop-by-hop diagram (animated)
- **Authentication Results**: SPF/DKIM/DMARC status cards with pass/fail/none indicators
- **NLP Findings**: Detected patterns with highlighted excerpts from email
- **Link Analysis**: Table of extracted URLs with risk indicators
- **IP Intelligence**: Geolocation data, ISP info, proxy detection for each IP
- **Geolocation Map**: Full Leaflet map with markers for each hop in relay chain, polyline showing email path
- **Attribution Assessment**: Confidence-based assessment of likely threat actor type

#### [NEW] `src/pages/GeoTracer.jsx`
- Full-page interactive Leaflet map
- Input for IP addresses or auto-populated from analysis
- Animated trace line showing email path across world
- Side panel with IP details for selected marker
- Heatmap of frequently seen threat origins

#### [NEW] `src/pages/CaseManagement.jsx`
- Searchable, filterable table of all analyzed emails
- Group related emails into "campaigns" / cases
- Status tracking (New, Investigating, Confirmed Threat, Resolved, False Positive)
- Export case as JSON/PDF forensic report
- Notes and tags per case

#### [NEW] `src/pages/ForensicReport.jsx`
- Printable/exportable forensic report
- Chain-of-custody metadata
- Evidence preservation timestamps
- Structured for legal/compliance review
- PDF-style layout

#### [NEW] `src/components/Sidebar.jsx`
- Animated sidebar with icon + text navigation
- Sections: Dashboard, Analyze Email, Geo Tracer, Cases, Reports, Settings
- Collapse/expand with smooth animation
- Active route highlighting with glow effect

#### [NEW] `src/components/ThreatGauge.jsx`
- Animated SVG circular gauge showing threat score 0-100
- Color gradient (green → yellow → orange → red)
- Animated fill on mount

#### [NEW] `src/components/RelayPath.jsx`
- Visual SMTP relay path diagram
- Animated dots moving along connection lines
- Each hop shows: server name, IP, timestamp, location flag

#### [NEW] `src/components/AuthBadges.jsx`
- SPF / DKIM / DMARC status badges
- Pass (green), Fail (red), None (gray), Soft Fail (amber)
- Tooltip with details

#### [NEW] `src/components/AlertCard.jsx`
- Email threat alert card with severity indicator
- Shows: sender, subject, threat type, score, timestamp
- Click to view full report

#### [NEW] `src/components/StatsCard.jsx`
- Glassmorphism stat card with icon, value, label, trend indicator

#### [NEW] `src/components/WorldMap.jsx`
- Reusable Leaflet map component
- Custom dark-mode map tiles
- Animated markers and trace lines

#### [NEW] `src/components/EmailInput.jsx`
- Rich email input with syntax highlighting for headers
- Drag-and-drop zone
- Sample email selector

---

### 6. Sample Data & Demo Content

#### [NEW] `src/data/sampleEmails.js`
- 5-8 realistic sample emails covering:
  - Legitimate business email
  - PayPal phishing attempt
  - CEO impersonation / BEC
  - Fake invoice with malware attachment
  - Credential harvesting (fake Microsoft login)
  - Nigerian prince / advance fee fraud
  - Domain spoofing attempt
- Each with full headers, body, and expected analysis results

#### [NEW] `src/data/threatPatterns.js`
- Curated lists of phishing keywords, urgency phrases, brand names
- Suspicious TLD list
- Known malicious domain patterns
- BEC indicator phrases

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                   React Frontend                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Dashboard │  │ Analyzer │  │   Geo Tracer     │  │
│  └──────┬───┘  └────┬─────┘  └───────┬──────────┘  │
│         │           │                │              │
│  ┌──────▼───────────▼────────────────▼──────────┐  │
│  │            Email Context (State)              │  │
│  └──────────────────┬───────────────────────────┘  │
│                     │                               │
│  ┌──────────────────▼───────────────────────────┐  │
│  │          Analysis Engine Layer                 │  │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────────┐   │  │
│  │  │ Header  │ │  NLP    │ │    Link      │   │  │
│  │  │ Parser  │ │Analyzer │ │  Analyzer    │   │  │
│  │  └────┬────┘ └────┬────┘ └──────┬───────┘   │  │
│  │  ┌────▼────┐ ┌────▼────┐ ┌──────▼───────┐   │  │
│  │  │  Auth   │ │ Domain  │ │     IP       │   │  │
│  │  │Validator│ │  Intel  │ │ Intelligence │   │  │
│  │  └────┬────┘ └────┬────┘ └──────┬───────┘   │  │
│  │       └───────────┼─────────────┘            │  │
│  │            ┌──────▼──────┐                   │  │
│  │            │   Threat    │                   │  │
│  │            │   Scorer    │                   │  │
│  │            └─────────────┘                   │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │         External API Layer                    │  │
│  │  ┌──────────┐  ┌────────────┐                │  │
│  │  │ ip-api   │  │ DNS/WHOIS  │                │  │
│  │  │ .com     │  │ (simulated)│                │  │
│  │  └──────────┘  └────────────┘                │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## UI Design Philosophy

- **Dark Mode First**: Deep navy/charcoal backgrounds with electric blue and neon green accents
- **Glassmorphism**: Frosted glass cards with subtle borders and backdrop blur
- **Micro-Animations**: Smooth transitions, animated gauges, pulsing threat indicators
- **Data-Dense but Clean**: Analyst-grade density with clear visual hierarchy
- **Map-Centric**: Interactive geolocation maps as a primary visual element
- **Typography**: Inter for UI text, JetBrains Mono for code/headers

---

## Verification Plan

### Automated
- `npm run dev` — ensure dev server starts without errors
- Browser console — check for runtime errors

### Manual
- Navigate all pages and verify rendering
- Test email analysis with sample phishing and legitimate emails
- Verify geolocation map rendering and IP trace visualization
- Check responsive layout on different viewport sizes
- Validate threat scoring produces meaningful differentiation between legitimate and malicious emails

---

## Open Questions

> [!IMPORTANT]
> **API Key Usage**: The provided API key (`xpl_e9fa4d3a82375b6433af107e476239849eb972d2`) appears to be for a threat intelligence service. I'll integrate it where applicable. Could you confirm which service this key belongs to (e.g., a custom API, or a specific platform)?

> [!NOTE]
> **Scope Clarification**: Since this is a frontend-focused SIH demonstration platform, the NLP/ML engine will be implemented as a sophisticated client-side heuristic system with pattern matching, keyword analysis, and Bayesian scoring — not a server-side ML model. This makes the project self-contained and demo-ready without requiring a backend server. The architecture is designed to be extensible for future backend ML integration.
