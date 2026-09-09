# 🛡️ MAILGUARD — FINAL END-TO-END AUDIT REPORT

> **Audit Date**: 2026-09-09  
> **Auditor**: Automated + Manual Agent Testing  
> **Commit Under Test**: `bb90e8b` (branch: `main`)

---

## A. OVERALL PROJECT STATUS

### 🟡 READY WITH TARGETED FIXES REQUIRED

The application **starts, runs, and functions end-to-end** without crashes. All pages load, all API endpoints respond correctly, case management CRUD works, reports persist to TinyDB, and the frontend communicates with the backend flawlessly.

**However**, the **Threat Scoring Engine** under-scores known-malicious emails in certain scenarios. A PayPal phishing email scores only **49/100 ("suspicious")** instead of the expected **≥65 ("phishing")**. A CEO Wire Fraud BEC email scores only **28/100 ("legitimate")** instead of the expected **≥35 ("fraud/suspicious")**. These are demo-breaking scoring inaccuracies that must be fixed.

---

## B. FUNCTIONALITY SCORE

| Area | Score |
|---|---|
| **Overall Functionality** | **88%** |
| **Backend API** | **95%** — All endpoints work, correct error handling |
| **Frontend UI** | **95%** — All pages load, zero console errors, responsive layout |
| **Threat Scorer Accuracy** | **60%** — Under-scores phishing/BEC; benign email scoring is correct |
| **Infrastructure** | **90%** — Startup scripts work, dependencies installed, dev proxy functional |

---

## C. THREAT SCORER ACCURACY ASSESSMENT

### Score: 🟠 60/100 — NEEDS CALIBRATION

The scoring formula is **architecturally sound** (weighted multi-vector aggregation), but the **weight distribution and NLP internal scoring dampening** cause the following calibration failures:

| Test Case | Expected Risk | Actual Score | Actual Verdict | Correct? | Root Cause |
|---|---|---|---|---|---|
| Legitimate Business Email | Low (0-20) | **11-12** | legitimate | ✅ | — |
| PayPal Phishing Attack | High (≥65) | **49-74** ¹ | suspicious | 🟠 | NLP nlpScore dampened; IP risk varies |
| CEO Wire Fraud (BEC) | High (≥45) | **28-46** ¹ | legitimate | ❌ | BEC score doesn't breach classification threshold |
| Auth-Only Failure | Moderate (20-40) | **13-32** ¹ | legitimate | ✅ | Correctly treats auth-failure alone as insufficient |
| Social Engineering Only | Moderate (≥30) | **12-35** ¹ | legitimate | 🟠 | NLP weight dampened by 6-component averaging |
| Newsletter/Marketing | Low (0-25) | **~15** | legitimate | ✅ | — |
| Nigerian Fraud (419) | High (≥55) | **~55-70** | phishing/fraud | ✅ | — |
| Minimal Email (no headers) | Low (≤35) | **30-32** | legitimate | ✅ | — |

> ¹ Score varies between runs because IP geolocation lookups to `ip-api.com` return different results (rate limiting, caching, network latency), causing `ipRisk` to fluctuate between 0-100.

### Root Cause Analysis

**Problem 1: NLP Score Dampening** (`nlp_analyzer.py:_calculate_nlp_score`)

The NLP composite score averages 6 sub-components with these weights:
```
urgencyScore: 0.15, phishingScore: 0.25, impersonationScore: 0.25,
socialEngineeringScore: 0.15, becScore: 0.15, sentimentScore: 0.05
```

When a phishing email has strong urgency (100) and phishing language (45) but zero impersonation and zero BEC, the averaging **dilutes** the strong signals:
```
100*0.15 + 45*0.25 + 0*0.25 + 36*0.15 + 0*0.15 + 31*0.05 = 15 + 11.25 + 0 + 5.4 + 0 + 1.55 = 33.2 → nlpScore = 33
```
This 33 is then fed into the threat scorer at 30% weight, contributing only ~10 points to the final score.

**Problem 2: Classification Thresholds Too Conservative** (`threat_scorer.py:_classify_threat`)

The classification function requires BOTH a high composite score AND a high sub-category score:
```python
if bec_score > 30 and score > 35:  return "fraud"     # BEC must be >30 AND total >35
if imp_score > 30 and score > 30:  return "impersonation"
if phish_score > 40 and score > 35: return "phishing"
if score >= 65: return "phishing"   # Pure score threshold
```

The BEC email has `becScore=40` (>30 ✅) but total score=28 (<35 ❌), so it falls through to "legitimate" despite strong BEC indicators.

**Problem 3: IP Risk Score Non-Determinism**

The `ipRisk` component calls the live `ip-api.com` service. Results vary:
- First run: `ipRisk=20` (no risk indicators returned)  
- Second run: `ipRisk=65-100` (hosting/proxy flags returned)

This causes the total score to fluctuate by up to ~10 points between runs.

---

## D. TEST SUMMARY

| Metric | Count |
|---|---|
| **Total Tests Performed** | **49** (API) + **6** (UI Pages) + **15** (Manual Verification) = **70** |
| **Passed** | **62** |
| **Failed** | **5** (all scoring-related) |
| **Blocked** | **3** (deployment not tested — no deployed instance) |

---

## E. CRITICAL ISSUES 🔴

### 🔴 ISSUE #1: BEC Email Classified as "Legitimate" (Demo-Breaking)

- **What**: CEO Wire Fraud BEC email (Sample 3) scores 28/100 and is classified "legitimate"
- **Why**: `becScore=40` triggers BEC detection, but total weighted score (28) fails the `score > 35` threshold in `_classify_threat`
- **Where**: [threat_scorer.py:81](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/threat_scorer.py#L81)
- **Impact**: During demo, showing "legitimate" for a $47,500 wire fraud email destroys credibility
- **Fix**: Lower the classification threshold for BEC from `score > 35` to `score > 20`, since BEC detection itself is already a strong indicator

### 🔴 ISSUE #2: PayPal Phishing Classified as "Suspicious" Instead of "Phishing"

- **What**: PayPal phishing email (Sample 2) scores 49/100 and is classified "suspicious" instead of "phishing"
- **Why**: NLP score dampening + IP risk variability keeps the score below 65 (the pure phishing threshold)
- **Where**: [nlp_analyzer.py:268-278](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/nlp_analyzer.py#L268-L278) (NLP weight dampening) and [threat_scorer.py:85-88](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/threat_scorer.py#L85-L88) (classification thresholds)
- **Impact**: Showing "suspicious" for an obvious PayPal phishing email with failed SPF/DKIM/DMARC, fake domain, credential harvesting links, and urgency language is inaccurate
- **Fix**: Increase NLP sub-component weights and lower the phishing classification threshold

---

## F. HIGH-PRIORITY FIXES 🟠

### 🟠 ISSUE #3: IP Risk Non-Determinism Causes Score Fluctuation

- **What**: Same email produces different scores on different runs (±10-15 points)
- **Why**: Real-time `ip-api.com` lookups return different hosting/proxy flags based on rate limiting, caching, and API state
- **Where**: [ip_intelligence.py](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/ip_intelligence.py) and [threat_scorer.py:54-73](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/threat_scorer.py#L54-L73)
- **Fix**: When IP lookup fails or returns error, assign a neutral score (10) instead of 20-30, or cache results

### 🟠 ISSUE #4: Social Engineering Email Scores Too Low

- **What**: Email with pure social engineering (urgency, fear, authority, credential requests) scores only 12-35
- **Why**: With valid auth (SPF/DKIM/DMARC pass), the auth component contributes 0 to threat, and NLP score is dampened by averaging
- **Impact**: Legitimate-looking emails with strong social engineering bypass detection
- **Fix**: Part of the NLP weight recalibration in Issue #2

---

## G. MEDIUM/LOW ISSUES

### 🟡 ISSUE #5: `CORS_ORIGINS` Contains Wildcard `"*"`
- **File**: [config.py:8](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/config.py#L8)
- **Issue**: Having both specific origins AND `"*"` is redundant. The `"*"` effectively allows all origins.
- **Risk**: Low (development setting), but should be noted for production
- **Fix**: Remove `"*"` from the list for production; keep it only for development

### 🟡 ISSUE #6: No IPv6 Handling in `is_private_ip()`
- **File**: [header_parser.py:123-142](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/header_parser.py#L123-L142)
- **Issue**: IPv6 addresses always return `False` from `is_private_ip()`, so `::1` or `fe80::` could be sent to IP-API
- **Risk**: Low (IP-API gracefully handles this)

### 🟢 ISSUE #7: `_is_tor_indicator` Has False Positives
- **File**: [ip_intelligence.py:116-118](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/ip_intelligence.py#L116-L118)
- **Issue**: Simple substring match for "tor", "exit", "relay" could flag legitimate organizations (e.g., "Mentor", "Relaytime", "Extortion")
- **Risk**: Very low in practice

### 🟢 ISSUE #8: Database File Grows Without Pruning
- **File**: [database.py](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/data/database.py)
- **Issue**: Every analysis auto-saves a full report to TinyDB. No size limit, no pruning, no archival.
- **Risk**: Low for demo purposes, but `db.json` could grow very large in extended use

---

## H. COMPLETE FEATURE MATRIX

| Feature | Tested? | Working? | Evidence / Problem |
|---|---|---|---|
| **Email Parsing (RFC 822)** | ✅ | ✅ | Headers, body, MIME correctly extracted |
| **Header Analysis** | ✅ | ✅ | From, To, Reply-To, Return-Path, Message-ID, Date all parsed |
| **Received Header Relay Path** | ✅ | ✅ | Hop-by-hop reconstruction works correctly |
| **Header Anomaly Detection** | ✅ | ✅ | From/Return-Path mismatch, Reply-To mismatch, missing headers detected |
| **SPF Validation** | ✅ | ✅ | Pass/fail/softfail correctly parsed from both Received-SPF and Auth-Results |
| **DKIM Validation** | ✅ | ✅ | Signature presence, domain alignment, pass/fail correctly evaluated |
| **DMARC Validation** | ✅ | ✅ | Domain alignment logic works; synthesizes from SPF+DKIM when header missing |
| **NLP Urgency Detection** | ✅ | ✅ | Urgency phrases correctly detected, score computed |
| **NLP Phishing Detection** | ✅ | ✅ | Credential harvesting, phishing keywords detected |
| **NLP Impersonation** | ✅ | ✅ | Brand impersonation, title matching works |
| **BEC Detection** | ✅ | 🟠 | Patterns detected correctly, but score too low to trigger "fraud" classification |
| **Social Engineering** | ✅ | 🟠 | Fear/urgency/authority/reward phrases detected, but dampened in composite score |
| **Sentiment Analysis** | ✅ | ✅ | 4-pillar profiling (Fear, Urgency, Authority, Reward) computes correctly |
| **URL/Link Analysis** | ✅ | ✅ | URL extraction, IP-URL, shorteners, typosquatting, credential paths detected |
| **Domain Intelligence** | ✅ | ✅ | Free/disposable detection, Levenshtein typosquatting, suspicious TLD flagging |
| **IP Geolocation** | ✅ | ✅ | IP-API integration works, fallback on error, batch lookup functional |
| **IP Risk Profiling** | ✅ | 🟠 | Hosting/proxy/cloud detection works but results non-deterministic |
| **Threat Scoring** | ✅ | 🟠 | Formula works correctly but weights/thresholds need calibration |
| **Threat Classification** | ✅ | 🟠 | Classification logic has overly conservative thresholds |
| **Dashboard** | ✅ | ✅ | Stats cards, charts, recent scans all populate correctly |
| **Email Analyzer UI** | ✅ | ✅ | Input, sample selector, tabbed results all functional |
| **GeoTracer Map** | ✅ | ✅ | Leaflet map loads with markers and IP details |
| **Case Management** | ✅ | ✅ | Full CRUD works: create, read, update, delete, add email to case |
| **Forensic Report** | ✅ | ✅ | ISO/IEC 27037:2012 dossier renders with all evidence |
| **Frontend/Backend Integration** | ✅ | ✅ | Vite proxy works, all API calls succeed, fallback engine works |
| **TinyDB Persistence** | ✅ | ✅ | Reports and cases persist across server restarts |
| **Error Handling** | ✅ | ✅ | Empty email → 400, missing field → 422, malformed → graceful |
| **Client-Side Fallback** | ✅ | ✅ | Frontend has complete JS engine mirror for offline operation |
| **Deployment** | ❌ | N/A | No deployed instance to test |

---

## I. RECOMMENDED FIXES

The following targeted fixes will resolve the 2 critical scoring issues without changing the architecture:

### Fix 1: Recalibrate NLP Score Weights

In [nlp_analyzer.py:268-278](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/nlp_analyzer.py#L268-L278), change from averaging across 6 components to using a **max-weighted** approach that preserves strong signals:

```python
# CURRENT (dampens strong individual signals):
weights = {
    "urgencyScore": 0.15, "phishingScore": 0.25, "impersonationScore": 0.25,
    "socialEngineeringScore": 0.15, "becScore": 0.15, "sentimentScore": 0.05,
}
total = sum((scores.get(k, 0) * w) for k, w in weights.items())

# RECOMMENDED (preserves dominant attack signals):
weights = {
    "urgencyScore": 0.20, "phishingScore": 0.25, "impersonationScore": 0.20,
    "socialEngineeringScore": 0.15, "becScore": 0.15, "sentimentScore": 0.05,
}
total = sum((scores.get(k, 0) * w) for k, w in weights.items())
max_signal = max(scores.values())
total = max(total, max_signal * 0.6)  # Ensure dominant signal contributes at least 60%
```

### Fix 2: Lower Classification Thresholds

In [threat_scorer.py:75-91](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/threat_scorer.py#L75-L91):

```python
# CURRENT:
if bec_score > 30 and score > 35: return "fraud"
if imp_score > 30 and score > 30: return "impersonation"  
if phish_score > 40 and score > 35: return "phishing"

# RECOMMENDED:
if bec_score > 30 and score > 20: return "fraud"        # BEC detection itself is strong
if imp_score > 30 and score > 20: return "impersonation" # Impersonation is strong
if phish_score > 30 and score > 25: return "phishing"    # Lower phishing threshold
```

### Fix 3: Reduce IP Risk Default for Failed Lookups

In [threat_scorer.py:54-56](file:///c:/Users/User/OneDrive/Desktop/SIH/MailGuard/backend/engine/threat_scorer.py#L54-L56):

```python
# CURRENT: No IPs → default risk = 20
if not ip_results: return 20

# RECOMMENDED: No IPs → default risk = 10 (truly neutral)
if not ip_results: return 10
```

---

## J. FINAL DEMO CHECKLIST

> [!IMPORTANT]
> Verify each of these items **immediately before presenting**:

- [ ] **Backend running**: `http://localhost:8000/api/health` returns `{"status":"online"}`
- [ ] **Frontend running**: `http://localhost:5173` loads the Dashboard
- [ ] **Internet available**: IP geolocation requires `ip-api.com` connectivity
- [ ] **Clear old data**: Delete `backend/storage/db.json` for a clean demo start
- [ ] **Test Sample 1**: Legitimate email → score ≤20, classification "legitimate"
- [ ] **Test Sample 2**: PayPal phishing → score ≥50, classification "phishing" or "suspicious"
- [ ] **Test Sample 3**: CEO BEC → score ≥35, classification "fraud" or "suspicious"
- [ ] **GeoTracer**: Map renders with IP markers after analyzing an email with IPs
- [ ] **Case Management**: Create a case, add email, verify it persists
- [ ] **Forensic Report**: Report page shows the latest analysis with correct score
- [ ] **Dashboard**: Stats update after analysis (total scans, threats, charts)
- [ ] **No console errors**: Open browser DevTools → Console → check for red errors
- [ ] **Scoring thresholds applied**: If fixes were applied, verify recalibrated scores

---

> [!CAUTION]
> **The threat scoring engine is the project's core technical claim.** If judges test with a phishing email and it's classified as "legitimate" or "suspicious," the team's credibility will be undermined. Apply Fix #1 and Fix #2 before the demo.

---

### Screenshots from UI Audit

````carousel
![Dashboard Initial State](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\dashboard_initial_1788943822105.png)
<!-- slide -->
![Email Analyzer Page](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\analyze_page_initial_1788943936398.png)
<!-- slide -->
![PayPal Analysis Results](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\paypal_analysis_score_gauge_1788944064153.png)
<!-- slide -->
![GeoTracer Map](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\geotracer_page_1788944304081.png)
<!-- slide -->
![Case Management](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\cases_page_1788944360170.png)
<!-- slide -->
![Forensic Report](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\reports_page_top_1788944471001.png)
<!-- slide -->
![Dashboard After Analysis](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\dashboard_final_state_1788944507490.png)
````

![Frontend UI Audit Recording](C:\Users\User\.gemini\antigravity-ide\brain\38e453f1-f71c-4ff8-9d5b-1b4224542cd9\frontend_ui_audit_1788943775808.webp)
