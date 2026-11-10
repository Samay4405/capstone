# Active Verification — System Build & Operator Guide (BUILD_GUIDE.md)

Welcome to the **Active Verification** production-grade phishing defense system. This guide provides comprehensive, step-by-step instructions to set up, configure, run, test, benchmark, and deploy the entire active defense pipeline.

---

## 1. Prerequisites

- **Operating System**: Linux, macOS, or Windows
- **Python**: Version `3.11` or `3.12` (compatible with `3.13`)
- **Git** (for version control)
- **Optional**: Docker & Docker Compose (for containerized deployment)

---

## 2. Quickstart Installation

### Step 2.1: Clone the Repository & Create Virtual Environment
```bash
# Clone the repository
git clone <repo-url> active-verification
cd active-verification

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Linux / macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
```

### Step 2.2: Install Package & Dependencies
```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### Step 2.3: Configure Environment Variables
Copy the template configuration file:
```bash
cp .env.example .env
```
Key settings available in `.env`:
- `ACTIVE_VERIFICATION_SANDBOX_STRICT=true` (*Safety invariant: Keep enabled to guarantee zero external socket contact*)
- `QUARANTINE_THRESHOLD=0.88` (*Tuned for 1% target FPR*)
- `WARN_THRESHOLD=0.55`
- `TARGET_FPR=0.01`
- `LLM_API_KEY=` (*Optional: provide Gemini or OpenAI key for cloud LLM judge; offline calibrated judge activates automatically if omitted*)

---

## 3. Running the Test Suite

Run unit and integration tests across parser, privacy redactor, signal analyzers, ensemble engine, and REST API:

```bash
# Set PYTHONPATH if running without editable install:
# Windows PowerShell:
$env:PYTHONPATH="src;."
# Linux/macOS:
export PYTHONPATH="src:."

# Execute pytest with verbose output
pytest tests/ -v
```

Expected output:
- `tests/test_parser.py`: Tests RFC 822 MIME parsing, link extraction, and auth results.
- `tests/test_analyzers.py`: Tests 6 independent analyzers against phishing vs benign emails.
- `tests/test_ensemble_and_api.py`: Tests FastAPI REST endpoints, file uploads, metrics, and fast path.

---

## 4. Running the Reproducible Benchmark

Execute the automated benchmark harness to reproduce ROC-AUC, Recall @ 1% FPR, latency, and ablation metrics:

```bash
python -m eval --samples 120 --seed 42
```

Command line options:
- `--samples <int>`: Total number of emails in the evaluation split (default: 120).
- `--seed <int>`: Random seed for dataset reproducibility (default: 42).
- `--json`: Output full raw results as JSON for programmatic consumption.

This command prints:
1. Overall Model Comparison (Active Verification vs SpamAssassin vs Keyword Heuristic vs Gmail reference baseline).
2. Subgroup Analysis (Classic Phishing vs LLM-written Phishing without typos).
3. Leave-One-Signal-Out Ablation Study.

---

## 5. Starting the Interactive Web UI & API Server

Start the FastAPI application with Uvicorn:

```bash
uvicorn active_verification.api.server:app --host 0.0.0.0 --port 8000 --reload
```

Once running:
- **Interactive Web Dashboard**: Open your browser to `http://localhost:8000/`
  - Drag-and-drop `.eml` or `.msg` files directly from `sample_emails/` into the dropzone.
  - Test pre-loaded attack samples (PayPal Brand Spoof, LLM Phishing without typos, CEO Wire Fraud, or Legitimate Business Mail).
  - Inspect visual signal score progress bars, "Why" explainability breakdown, and sandboxed active verification transcripts.
- **Interactive Swagger REST Docs**: Open `http://localhost:8000/docs`
- **Health Check Endpoint**: `http://localhost:8000/api/v1/health`
- **Live Metrics**: `http://localhost:8000/api/v1/metrics`
- **Quarantine Store**: `http://localhost:8000/api/v1/quarantine`

---

## 5.1 Feeding Pre-Generated Sample Test Files

A structured test corpus is pre-built in `sample_emails/`:
```
sample_emails/
├── phishing_credential_harvest/     (PayPal, Microsoft, Apple account lockouts)
├── phishing_llm_spearphishing/      (CEO wire transfer, IT SSO migration, DocuSign)
├── phishing_malware_attachment/     (.pdf.exe double extension, .docm macros, .zip)
├── spam_bulk_commercial/            (Lottery scams, unsolicited SEO leads, crypto)
└── legitimate_business/             (Team sync, GitHub PR, AWS invoice)
```

Run batch verification on all sample files:
```bash
python scripts/test_samples.py
```

---

## 6. Testing via REST API (cURL Examples)

### Analyze Raw Email Text
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_email": "From: Security <sec@paypa1.com>\nTo: user@target.com\nSubject: Urgent Verify\n\nClick: http://192.168.1.1/login"
  }'
```

### Upload a .EML or .MSG File
```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -F "file=@sample_phish.eml"
```

---

## 7. Containerized Deployment (Docker & Compose)

### Build and Run with Docker Compose
```bash
# Build the container image and launch service
docker-compose up --build -d

# Check service health
docker-compose ps
curl http://localhost:8000/api/v1/health

# View logs
docker-compose logs -f
```

---

## 8. Ingestion Configuration (Real Mail Polling)

### Option A: Gmail OAuth API (Read-Only)
1. In Google Cloud Console, create an OAuth 2.0 Client ID with scope `https://www.googleapis.com/auth/gmail.readonly`.
2. Add your credentials in `.env`:
   ```ini
   GMAIL_CLIENT_ID=your_client_id.apps.googleusercontent.com
   GMAIL_CLIENT_SECRET=your_client_secret
   GMAIL_REFRESH_TOKEN=your_oauth_refresh_token
   GMAIL_POLL_INTERVAL_SECONDS=30
   ```
3. The `active_verification.ingestion.gmail` worker will automatically poll for unread messages.

### Option B: Generic IMAP Mailbox Polling
1. Enable IMAP on your mail server (e.g., corporate Exchange, Dovecot, or ProtonMail Bridge).
2. Configure `.env`:
   ```ini
   IMAP_SERVER=imap.your-company.com
   IMAP_PORT=993
   IMAP_USERNAME=phishing-reports@your-company.com
   IMAP_PASSWORD=your_app_password
   IMAP_USE_SSL=true
   IMAP_MAILBOX=INBOX
   ```
3. Unread messages are fetched, analyzed, and categorized automatically.

---

## 9. Security & Safety Verification

- **Strict Sandbox Verification**: Run `python -c "from active_verification.verification.honeypot import sandboxed_honeypot; sandboxed_honeypot._assert_sandbox_integrity(); print('Sandbox barrier verified intact.')"`
- **PII Redaction Check**: Run `python -c "from active_verification.privacy.redactor import redactor; text, counts = redactor.redact_text('Contact john.doe@example.com at 555-0192'); print(text)"`
  - Output confirms email is replaced with salted cryptographic hash and phone with `[REDACTED_PHONE]`.

