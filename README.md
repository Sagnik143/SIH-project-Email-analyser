# 🛡️ MailGuard — Forensic Threat Intelligence Platform

An end-to-end cyber intelligence and forensic investigation platform for email threat detection, NLP manipulation analysis, SMTP relay tracking, and IP geolocation intelligence.

---

## 🏗️ Architecture & Project Structure

The project has clean separation between the **React Vite Frontend** and the **Python FastAPI Backend**:

```
SIH PROJECT/
├── frontend/                        # React 19 + Vite Frontend
│   ├── src/
│   │   ├── components/              # UI Widgets, Leaflet Map, Threat Gauges, Relay Diagrams
│   │   ├── context/
│   │   │   └── EmailContext.jsx     # Context with Python Backend API + Resilient Fallback
│   │   ├── pages/                   # Dashboard, EmailAnalyzer, GeoTracer, CaseManagement, ForensicReport
│   │   ├── services/
│   │   │   └── api.js               # REST Client for FastAPI backend
│   │   ├── data/                    # Sample attack emails for live demonstration
│   │   └── index.css                # Modern, user-friendly light theme
│   ├── package.json
│   └── vite.config.js               # Proxies /api requests to http://127.0.0.1:8000
│
├── backend/                         # Python FastAPI Backend
│   ├── main.py                      # FastAPI Application entry point & CORS
│   ├── config.py                    # Server configuration & environment settings
│   ├── requirements.txt             # FastAPI, Uvicorn, Pydantic, TinyDB, HTTPX, Requests
│   ├── routers/
│   │   ├── analyze.py               # POST /api/analyze — Full forensic analysis pipeline
│   │   ├── geolocation.py           # POST /api/geo/lookup & /api/geo/batch
│   │   ├── cases.py                 # CRUD /api/cases — Case management endpoints
│   │   └── reports.py               # GET/DELETE /api/reports — Persistent forensic reports
│   ├── engine/
│   │   ├── header_parser.py         # RFC 822 header extraction, IP parsing & relay reconstruction
│   │   ├── auth_validator.py        # SPF, DKIM, and DMARC alignment validation
│   │   ├── nlp_analyzer.py          # Urgency, phishing, impersonation & BEC NLP detection
│   │   ├── link_analyzer.py         # Malicious link, punycode, typosquatting & IP URL scanning
│   │   ├── ip_intelligence.py       # Geolocation lookup, VPN/Proxy/Cloud identification
│   │   ├── domain_intelligence.py   # Domain reputation, typosquatting distance & TLD abuse
│   │   └── threat_scorer.py         # Multi-vector weighted threat scoring engine
│   ├── data/
│   │   ├── threat_patterns.py       # Curated dictionaries of phishing and attack indicators
│   │   └── database.py              # TinyDB JSON storage for cases and reports
│   └── models/
│       ├── request_models.py        # Pydantic input schemas
│       └── response_models.py       # Pydantic response models
│
├── start_backend.bat                # One-click launcher for FastAPI Backend
├── start_frontend.bat               # One-click launcher for React Frontend
└── README.md
```

---

## ⚡ Quick Start

### 1. Launch Python Backend
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
* **API Server:** http://localhost:8000
* **Interactive Swagger UI:** http://localhost:8000/docs
* **Alternative API ReDoc:** http://localhost:8000/redoc

### 2. Launch React Frontend
```bash
cd frontend
npm run dev
```
* **Web UI:** http://localhost:5173

Or simply double-click `start_backend.bat` and `start_frontend.bat` on Windows!

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check & API status |
| `POST` | `/api/analyze` | Full email parsing, NLP, auth validation, link scan, and threat scoring |
| `POST` | `/api/geo/lookup` | Single IP geolocation & intelligence lookup |
| `POST` | `/api/geo/batch` | Batch IP geolocation lookup (up to 10 IPs) |
| `GET` | `/api/cases` | Retrieve all active cases |
| `POST` | `/api/cases` | Create a new case investigation |
| `GET` | `/api/cases/{id}` | Retrieve single case details |
| `PUT` | `/api/cases/{id}` | Update case status, notes, or tags |
| `DELETE` | `/api/cases/{id}` | Delete case |
| `POST` | `/api/cases/{id}/emails` | Attach analyzed email to case |
| `GET` | `/api/reports` | List all saved forensic analysis reports |
| `GET` | `/api/reports/{id}` | Retrieve individual forensic report |
| `DELETE` | `/api/reports/{id}` | Delete report |
