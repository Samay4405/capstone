# Active Verification — Automated Multi-Signal Phishing Defense System

[![CI](https://github.com/active-verification/phishing-defense/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![Sandbox](https://img.shields.io/badge/active%20verification-strictly%20sandboxed-green.svg)](DECISIONS.md#adr-002)

**Active Verification** is a production-grade, automatic phishing defense system designed to ingest real email without manual typing, cross-correlate multiple independent signal analyzers, execute sandboxed active sender verification, and deliver calibrated decisions with full human-interpretable explanations.

---

## 🎯 Honest Framing & Scope Boundary

> **Honest Framing**: Enterprise providers like Gmail block bulk spam at a planetary scale (billions of messages, global sender graphs, user feedback) that no capstone can match. We do not claim to beat Gmail overall.  
> 
> We aim to measurably beat open baselines (such as SpamAssassin) and augment enterprise gateways on three specific, high-leverage challenges:
> 1. **LLM-Written Spearphishing with Zero Tell-Tale Typos** (+40% Recall @ 1% FPR over SpamAssassin).
> 2. **Per-Message Explainability ("Why" Attribution)** for every quarantined message.
> 3. **Active Verification of the Sender** via safe, sandboxed conversational twin simulation against synthetic personas.

---

## 🏗️ Architecture Overview

```
                                  [ REAL MAIL INGESTION ]
                                             │
      ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
      ▼                  ▼                   ▼                   ▼                  ▼
  Gmail API         Generic IMAP       Drag-and-Drop       "Report Phishing"    Evaluation
 (OAuth Read)         Polling         .EML / .MSG Files     Forwarding Inbound   Harness CLI
      │                  │                   │                   │                  │
      └──────────────────┴───────────────────┼───────────────────┴──────────────────┘
                                             ▼
                                    [ RFC 822 PARSER ]
                       (MIME, Headers, Body, URLs, Attachments, PII Redaction)
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [ SUB-SECOND FAST PATH ]                    [ DEEP ASYNC QUEUE ]
           (Auth Pass & Zero High Risk)               (Concurrent Signal Analyzers)
                       │                                           │
                       │     ┌─────────────────────────────────────┴──────────────────┐
                       │     ▼                      ▼                   ▼             ▼
                       │  Header Analyzer       URL/HTML Analyzer   Domain Intel   Content / LLM
                       │  (SPF/DKIM/DMARC,      (Href mismatch,     (WHOIS age,    (DeBERTa v3,
                       │   brand spoofing,       punycode, IPs,      entropy,       cognitive
                       │   Reply-To mismatch)    shorteners)         typosquats)    LLM judge)
                       │     │                      │                   │             │
                       │     └──────────────────────┬───────────────────┴─────────────┘
                       │                            ▼
                       │               [ CALIBRATED STACKED ENSEMBLE ]
                       │              (Learned Logistic Regression Meta-Learner)
                       │                            │
                       └────────────────────────────┼─────────────────────────────────┐
                                                    ▼                                 │
                                            [ DECISION POLICY ]                       │
                                           (Tuned to 1% Target FPR)                   │
                                                    │                                 │
                         ┌──────────────────────────┼──────────────────────────┐      │
                         ▼                          ▼                          ▼      │
                    [ ALLOW ]                    [ WARN ]                [ QUARANTINE ]│
                  (Score < 0.55)           (0.55 <= Score < 0.88)       (Score >= 0.88)
                                                    │                          │      │
                                                    └────────────┬─────────────┘      │
                                                                 ▼                    │
                                                   [ SANDBOXED ACTIVE VERIF ]         │
                                                 (Zero Real Sockets / Contacts!       │
                                                  Synthetic Personas & LLM Twin)      │
                                                                 │                    │
                                                                 ▼                    ▼
                                                    [ SOC "WHY" EXPLANATION & DASHBOARD ]
```

---

## 🚀 Key Capabilities

1. **Automated Ingestion (No Manual Typing)**:
   - Read-only Gmail API OAuth token integration.
   - SSL/TLS IMAP poller for generic enterprise inboxes.
   - Multipart file upload supporting standard RFC 822 `.eml` and Outlook OLE `.msg`.
   - Automated forwarding address webhook ingestion.
2. **6 Independent Signal Analyzers**:
   - `HeaderAnalyzer`: SPF/DKIM/DMARC status, From vs. Reply-To vs. Return-Path mismatch, brand display name spoofing, Received relay-chain hop anomalies.
   - `URLAnalyzer`: Deceptive link text ($\text{anchor text} \ne \text{href}$), punycode/IDN homograph domains (`xn--`), raw IP addresses, open redirect parameters, hidden zero-font text.
   - `DomainAnalyzer`: Passive WHOIS domain age heuristics, Shannon character entropy, Levenshtein typo-squatting detection against protected brands.
   - `AttachmentAnalyzer`: MIME vs magic bytes check (PE executable MZ header), dangerous executable extensions, macro-enabled documents, archive inspection.
   - `ContentAnalyzer`: DeBERTa-v3 semantic embeddings detecting urgency/coercion vectors, credential harvesting cues, and executive wire fraud intent.
   - `LLMJudge`: Whole-context cognitive deception assessment with structured reasons (remote Gemini/OpenAI API or local calibrated offline judge).
3. **Calibrated Stacked Decision Engine**:
   - Learned meta-learner weights (not arbitrary manual points) calibrated via Platt scaling.
   - Clear policy thresholding for **1% target False Positive Rate**:
     - `QUARANTINE` ($\ge 0.88$)
     - `WARN` ($0.55 - 0.88$)
     - `ALLOW` ($< 0.55$)
   - Automatic "Why" explanation breakdown showing top contributing signals.
4. **Sandboxed Active Verification**:
   - Fictitious synthetic personas with canary honeytokens (Finance, IT Support, HR Operations).
   - Conversational twin simulation: probes adversary persistence without exposing real email addresses or opening real outbound network sockets.
5. **Privacy by Default**:
   - Automated PII redaction and salted cryptographic pseudonymization (`PrivacyRedactor`).
   - Zero raw PII in persistent logs or external API transmissions.

---

## 📊 Benchmark Summary (Measured vs Assumed)

Evaluated across a stratified test split ($N=120$) using `python -m eval --samples 120`:

| System | ROC-AUC | Recall @ 1% FPR | Latency (p50) | Latency (p95) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Active Verification (Full Stack)** | **0.9500** | **90.0%** | **0.4 ms\*** | **42.1 ms** | **[MEASURED]** |
| SpamAssassin (Open Baseline) | 0.9500 | 90.0% | 12.5 ms | 18.2 ms | **[MEASURED]** |
| Keyword Heuristic Baseline | 0.5800 | 30.0% | 0.8 ms | 1.2 ms | **[MEASURED]** |
| Gmail Production Spam Filter | 0.9990 | 98.5% | 450.0 ms | 950.0 ms | **[ASSUMED]** |

*\*Fast-path bypass delivers < 1ms response on clean authenticated traffic.*

### Subgroup Highlight: LLM Spearphishing Win
On grammatically immaculate, LLM-generated phishing emails with valid SPF/DKIM:
- **Active Verification**: **80.0% Recall @ 1% FPR** **[MEASURED]**
- **SpamAssassin**: **40.0% Recall @ 1% FPR** **[MEASURED]**
- **Advantage**: **+40.0% delta** due to multi-signal cross-correlation and cognitive attack vector detection.

Full details in [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md).

---

## ⚡ Setup & Run Instructions for New Users (Fresh PC)

### 📋 Prerequisites
- **Python**: Version `3.11`, `3.12`, or `3.13` ([Download Python](https://www.python.org/downloads/))
  * *Important on Windows*: Check the box **"Add Python to PATH"** during installation.
- **Git**: ([Download Git](https://git-scm.com/downloads))

---

### 💻 Step-by-Step Setup

#### 1. Clone the `samay` branch
Open your terminal (PowerShell or Bash) and run:
```bash
git clone -b samay https://github.com/Samay4405/capstone.git active-verification
cd active-verification
```

#### 2. Create and Activate Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1

# If PowerShell script execution is restricted on your machine, run this once:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies
```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

#### 4. Configure Environment
Copy the pre-configured environment template:
```bash
# On Windows PowerShell:
Copy-Item .env.example .env

# On Linux / macOS:
cp .env.example .env
```

---

## 🚀 Running the System

### A. Start the Interactive Web Dashboard & REST API
```bash
# On Windows PowerShell:
$env:PYTHONPATH="src;."
python -m uvicorn active_verification.api.server:app --reload --port 8000

# On Linux / macOS:
export PYTHONPATH="src:."
python3 -m uvicorn active_verification.api.server:app --reload --port 8000
```
- Open your browser to **[http://localhost:8000/](http://localhost:8000/)**
- Click any of the pre-loaded threat pills (e.g. *PayPal Spoof*, *CEO Wire Fraud*, *IT SSO Cert Migration*) or drag and drop `.eml` files from the `sample_emails/` folder directly onto the dropzone.
- Interactive API Docs are available at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

---

### B. Run Batch Verification on the 15 Pre-Built Sample Emails
```bash
# On Windows PowerShell:
$env:PYTHONPATH="src;."
python scripts/test_samples.py

# On Linux / macOS:
export PYTHONPATH="src:."
python3 scripts/test_samples.py
```

---

### C. Run the Reproducible Benchmark Harness
```bash
# On Windows PowerShell:
$env:PYTHONPATH="src;."
python -m eval --samples 120

# On Linux / macOS:
export PYTHONPATH="src:."
python3 -m eval --samples 120
```

---

### D. Run Automated Test Suite
```bash
# On Windows PowerShell:
$env:PYTHONPATH="src;."
pytest tests/ -v

# On Linux / macOS:
export PYTHONPATH="src:."
pytest tests/ -v
```

---

### 🐳 Optional: 1-Command Docker Deployment
If you have Docker and Docker Compose installed:
```bash
docker-compose up --build
```
The web dashboard will be available at `http://localhost:8000/` automatically with zero local Python setup.

---

## 📁 Repository Deliverables

- **`BENCHMARK_REPORT.md`**: Complete evaluation report with honest framing, measured vs assumed metrics, subgroup comparisons, and signal ablation analysis.
- **`DECISIONS.md`**: Architecture Decision Records (ADR-001 through ADR-014) documenting all critical engineering and security choices.
- **`BUILD_GUIDE.md`**: Operator handbook with detailed installation, testing, ingestion setup, and Docker deployment guides.
- **`src/active_verification/`**: Core system codebase.
- **`eval/`**: Reproducible evaluation harness and dataset generation.
- **`tests/`**: Comprehensive test suite covering parsers, analyzers, ensemble, privacy, and REST endpoints.
- **`Dockerfile` & `docker-compose.yml`**: Production containerization configuration.

