"""FastAPI application server with REST endpoints and enterprise SOC web UI."""

import time
import os
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from active_verification.config import settings
from active_verification.models.schemas import EmailMessage, AnalysisResult, DecisionPolicy, IngestionSource
from active_verification.ingestion.parser import parser
from active_verification.ensemble.engine import ensemble_engine
from active_verification.queue.worker import async_queue
from active_verification.privacy.redactor import redactor

# Global in-memory metrics and quarantine storage
METRICS = {
    "total_analyzed": 0,
    "quarantined_count": 0,
    "warned_count": 0,
    "allowed_count": 0,
    "fast_path_hits": 0,
    "total_latency_ms": 0.0,
}
QUARANTINE_STORE: List[Dict[str, Any]] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: launch async queue worker
    await async_queue.start()
    yield
    # Shutdown: terminate worker
    await async_queue.stop()


app = FastAPI(
    title="Active Verification Phishing Defense API",
    description="Multi-signal automated phishing defense system with sandboxed active verification.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeTextRequest(BaseModel):
    raw_email: str
    source: IngestionSource = IngestionSource.FILE_UPLOAD


def _record_metrics(res: AnalysisResult):
    METRICS["total_analyzed"] += 1
    METRICS["total_latency_ms"] += res.latency_ms
    if res.fast_path_used:
        METRICS["fast_path_hits"] += 1

    if res.decision == DecisionPolicy.QUARANTINE:
        METRICS["quarantined_count"] += 1
        QUARANTINE_STORE.append({
            "message_id": res.message_id,
            "risk_score": res.calibrated_score,
            "reasons": res.why_explanation,
            "preview": res.redacted_preview,
            "timestamp": res.timestamp,
        })
    elif res.decision == DecisionPolicy.WARN:
        METRICS["warned_count"] += 1
    else:
        METRICS["allowed_count"] += 1


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "env": settings.APP_ENV,
        "sandbox_strict": settings.ACTIVE_VERIFICATION_SANDBOX_STRICT,
        "target_fpr": settings.TARGET_FPR,
        "quarantine_threshold": settings.QUARANTINE_THRESHOLD,
    }


@app.get("/api/v1/metrics")
def get_metrics():
    total = max(1, METRICS["total_analyzed"])
    avg_latency = METRICS["total_latency_ms"] / total if METRICS["total_analyzed"] > 0 else 0.0
    fast_path_ratio = METRICS["fast_path_hits"] / total if METRICS["total_analyzed"] > 0 else 0.0

    return {
        "total_messages_analyzed": METRICS["total_analyzed"],
        "quarantined": METRICS["quarantined_count"],
        "warned": METRICS["warned_count"],
        "allowed": METRICS["allowed_count"],
        "fast_path_ratio": round(fast_path_ratio, 4),
        "average_latency_ms": round(avg_latency, 2),
    }


@app.get("/api/v1/quarantine")
def list_quarantine():
    return {"quarantined_messages": QUARANTINE_STORE[-50:]}


@app.post("/api/v1/analyze", response_model=AnalysisResult)
def analyze_raw_email(req: AnalyzeTextRequest):
    if not req.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email content cannot be empty")

    email = parser.parse_raw(req.raw_email.encode("utf-8"), source=req.source)
    result = ensemble_engine.analyze_message(email)
    _record_metrics(result)
    return result


@app.post("/api/v1/upload", response_model=AnalysisResult)
async def upload_email_file(file: UploadFile = File(...)):
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    email = parser.parse_raw(contents, source=IngestionSource.FILE_UPLOAD)
    result = ensemble_engine.analyze_message(email)
    _record_metrics(result)
    return result


@app.post("/api/v1/queue")
async def queue_email_analysis(req: AnalyzeTextRequest):
    email = parser.parse_raw(req.raw_email.encode("utf-8"), source=req.source)
    task_id = await async_queue.enqueue(email)
    return {"task_id": task_id, "status": "QUEUED"}


@app.get("/api/v1/queue/{task_id}")
def check_queued_task(task_id: str):
    task = async_queue.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.get("/", response_class=HTMLResponse)
def index_dashboard():
    """Serves the revamped modern Enterprise SOC web UI dashboard."""
    html = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Active Verification — Cognitive Phishing Defense SOC</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #070b14;
      --panel: #0d1527;
      --card: #131f38;
      --card-hover: #182847;
      --border: #1f3056;
      --border-bright: #2d447a;
      --text: #f1f5f9;
      --text-muted: #8fa0c0;
      --text-dim: #5c6f96;
      --primary: #3b82f6;
      --primary-glow: rgba(59, 130, 246, 0.25);
      --danger: #ef4444;
      --danger-bg: #2d1017;
      --danger-border: #7f1d1d;
      --warning: #f59e0b;
      --warning-bg: #2d1e0f;
      --warning-border: #78350f;
      --success: #10b981;
      --success-bg: #09261c;
      --success-border: #065f46;
      --cyan: #06b6d4;
      --purple: #8b5cf6;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      min-height: 100vh;
      line-height: 1.5;
      padding-bottom: 60px;
    }

    /* Top Telemetry Bar */
    .top-bar {
      background: rgba(13, 21, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 12px 28px;
      position: sticky;
      top: 0;
      z-index: 100;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .logo-area { display: flex; align-items: center; gap: 12px; }
    .logo-badge {
      background: linear-gradient(135deg, #2563eb, #06b6d4);
      color: white;
      font-weight: 800;
      font-size: 15px;
      padding: 6px 12px;
      border-radius: 8px;
      box-shadow: 0 0 20px rgba(37, 99, 235, 0.5);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .title-group h1 { font-size: 17px; font-weight: 700; letter-spacing: -0.3px; }
    .title-group p { font-size: 11px; color: var(--text-muted); }

    .telemetry-strip {
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .metric-item {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
    }
    .metric-label { font-size: 10px; color: var(--text-dim); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
    .metric-val { font-size: 14px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }

    .status-pill-safe {
      background: var(--success-bg);
      border: 1px solid var(--success-border);
      color: #34d399;
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .pulse-dot {
      width: 7px;
      height: 7px;
      background: #34d399;
      border-radius: 50%;
      box-shadow: 0 0 8px #34d399;
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
      0% { opacity: 0.4; transform: scale(0.9); }
      50% { opacity: 1; transform: scale(1.2); }
      100% { opacity: 0.4; transform: scale(0.9); }
    }

    /* Layout Grid */
    .container {
      max-width: 1440px;
      margin: 24px auto;
      padding: 0 24px;
      display: grid;
      grid-template-columns: 460px 1fr;
      gap: 24px;
    }

    /* Cards & Panels */
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 22px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
    }
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 18px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }
    .panel-title {
      font-size: 15px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
      color: #e2e8f0;
    }
    .panel-badge {
      font-size: 11px;
      background: #182847;
      color: var(--cyan);
      border: 1px solid var(--border-bright);
      padding: 2px 8px;
      border-radius: 6px;
      font-weight: 600;
    }

    /* Threat Selector Categories */
    .category-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-dim);
      margin-top: 14px;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .pill-group {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      margin-bottom: 12px;
    }
    .threat-pill {
      background: var(--card);
      border: 1px solid var(--border);
      color: #cbd5e1;
      padding: 6px 11px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .threat-pill:hover {
      background: var(--card-hover);
      border-color: var(--primary);
      color: white;
      transform: translateY(-1px);
    }
    .threat-pill.active {
      background: linear-gradient(135deg, rgba(37,99,235,0.25), rgba(6,182,212,0.25));
      border-color: var(--cyan);
      color: #67e8f9;
      box-shadow: 0 0 12px rgba(6, 182, 212, 0.25);
    }

    /* Dropzone */
    .dropzone {
      border: 2px dashed var(--border-bright);
      background: rgba(19, 31, 56, 0.4);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      cursor: pointer;
      margin: 14px 0;
      transition: all 0.2s ease;
    }
    .dropzone:hover {
      border-color: var(--cyan);
      background: rgba(19, 31, 56, 0.8);
      box-shadow: 0 0 18px rgba(6, 182, 212, 0.15);
    }
    .dropzone-icon { font-size: 28px; margin-bottom: 6px; }
    .dropzone p { font-size: 13px; color: #cbd5e1; font-weight: 500; }
    .dropzone span { font-size: 11px; color: var(--text-dim); }

    /* Textarea */
    .editor-label { font-size: 12px; color: var(--text-muted); font-weight: 600; margin-bottom: 6px; display: block; }
    textarea {
      width: 100%;
      height: 160px;
      background: #080d1a;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      color: #e2e8f0;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      line-height: 1.5;
      resize: vertical;
      transition: border 0.15s;
    }
    textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 10px var(--primary-glow); }

    .btn-analyze {
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      color: white;
      border: none;
      padding: 14px 20px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      width: 100%;
      margin-top: 14px;
      box-shadow: 0 4px 16px rgba(37, 99, 235, 0.35);
      transition: all 0.15s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .btn-analyze:hover {
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      transform: translateY(-1px);
      box-shadow: 0 6px 22px rgba(37, 99, 235, 0.5);
    }

    /* RIGHT COLUMN: Results Section */
    .results-wrapper { display: flex; flex-direction: column; gap: 20px; }

    /* Verdict Banner Card */
    .verdict-banner {
      border-radius: 16px;
      padding: 22px;
      display: grid;
      grid-template-columns: 1fr 180px;
      gap: 20px;
      align-items: center;
      box-shadow: 0 12px 35px rgba(0, 0, 0, 0.45);
      border: 1px solid transparent;
      position: relative;
      overflow: hidden;
    }
    .verdict-banner::before {
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
    }
    .verdict-quarantine {
      background: linear-gradient(135deg, #2d1017, #17090d);
      border-color: var(--danger-border);
    }
    .verdict-quarantine::before { background: linear-gradient(90deg, #ef4444, #f43f5e); }
    .verdict-warn {
      background: linear-gradient(135deg, #2d1e0f, #190f05);
      border-color: var(--warning-border);
    }
    .verdict-warn::before { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
    .verdict-allow {
      background: linear-gradient(135deg, #09261c, #04140e);
      border-color: var(--success-border);
    }
    .verdict-allow::before { background: linear-gradient(90deg, #10b981, #34d399); }

    .verdict-title { font-size: 22px; font-weight: 800; letter-spacing: -0.4px; }
    .verdict-sub { font-size: 13px; color: #cbd5e1; margin-top: 4px; }
    .verdict-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 14px;
      font-size: 11px;
      color: var(--text-muted);
    }
    .verdict-meta span {
      background: rgba(255, 255, 255, 0.06);
      padding: 3px 8px;
      border-radius: 6px;
    }

    .gauge-box {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 14px;
      text-align: center;
    }
    .gauge-score { font-size: 32px; font-weight: 800; font-family: 'JetBrains Mono', monospace; line-height: 1; }
    .gauge-label { font-size: 10px; color: var(--text-dim); text-transform: uppercase; font-weight: 700; margin-top: 6px; }

    /* Narrative Modules: Why is it fishy & What does it say */
    .narrative-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    .narrative-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
    }
    .narrative-header {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .narrative-body {
      font-size: 13px;
      color: #cbd5e1;
      line-height: 1.6;
    }
    .fishy-list {
      list-style: none;
      margin-top: 6px;
    }
    .fishy-list li {
      position: relative;
      padding-left: 20px;
      margin-bottom: 8px;
      font-size: 12.5px;
      color: #e2e8f0;
    }
    .fishy-list li::before {
      content: "⚠️";
      position: absolute;
      left: 0;
      top: 0;
      font-size: 11px;
    }
    .safe-list li::before { content: "✅"; }

    .action-callout {
      background: rgba(37, 99, 235, 0.1);
      border-left: 4px solid var(--primary);
      padding: 12px 16px;
      border-radius: 0 10px 10px 0;
      font-size: 13px;
      color: #93c5fd;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    /* Multi-Signal Diagnostic Matrix (6 Cards) */
    .matrix-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .signals-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
    }
    .signal-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      transition: all 0.15s;
    }
    .signal-card:hover {
      border-color: var(--border-bright);
      background: var(--card);
    }
    .sig-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .sig-name { font-size: 12px; font-weight: 700; color: #f1f5f9; text-transform: uppercase; letter-spacing: 0.3px; }
    .sig-score { font-size: 14px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }

    .sig-bar {
      height: 6px;
      background: #182847;
      border-radius: 3px;
      overflow: hidden;
      margin-bottom: 10px;
    }
    .sig-fill { height: 100%; border-radius: 3px; }

    .sig-metrics {
      display: flex;
      justify-content: space-between;
      font-size: 10px;
      color: var(--text-dim);
      font-family: 'JetBrains Mono', monospace;
      margin-bottom: 8px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
    }
    .sig-reasons { font-size: 11px; color: var(--text-muted); line-height: 1.4; }
    .sig-reasons div { margin-bottom: 4px; padding-left: 10px; position: relative; }
    .sig-reasons div::before { content: "•"; position: absolute; left: 0; color: var(--cyan); }

    /* Active Verification Terminal */
    .terminal-box {
      background: #080d1a;
      border: 1px solid #1e3a8a;
      border-radius: 14px;
      padding: 18px;
      box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
    }
    .terminal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
      padding-bottom: 8px;
      border-bottom: 1px solid #1e3a8a;
    }
    .terminal-title { font-size: 12px; font-weight: 700; color: #60a5fa; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; gap: 8px; }
    .terminal-badge { font-size: 10px; background: #1e3a8a; color: #93c5fd; padding: 2px 8px; border-radius: 4px; font-weight: 700; }

    .chat-turn {
      font-size: 12px;
      margin-bottom: 10px;
      padding: 10px 14px;
      border-radius: 8px;
      line-height: 1.5;
    }
    .turn-persona {
      background: #0f1c38;
      border-left: 3px solid #3b82f6;
      color: #cbd5e1;
    }
    .turn-adv {
      background: #2b1219;
      border-left: 3px solid #ef4444;
      color: #fecdd3;
    }
    .turn-author { font-size: 11px; font-weight: 700; margin-bottom: 4px; display: flex; justify-content: space-between; }
    .mitre-tag { font-size: 9px; background: rgba(239, 68, 68, 0.2); color: #f87171; padding: 1px 6px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.4); }

    /* Empty state */
    .empty-state {
      text-align: center;
      padding: 80px 20px;
      color: var(--text-dim);
    }
    .empty-state-icon { font-size: 48px; margin-bottom: 12px; opacity: 0.6; }
  </style>
</head>
<body>

  <!-- Top Real-Time SOC Bar -->
  <div class="top-bar">
    <div class="logo-area">
      <div class="logo-badge">🛡️ ACTIVE VERIFICATION</div>
      <div class="title-group">
        <h1>Autonomous Multi-Signal Phishing Defense SOC</h1>
        <p>Two-Tier Calibrated Ensemble &bull; Sandboxed Persona Twin &bull; RFC 822 Engine</p>
      </div>
    </div>
    <div class="telemetry-strip">
      <div class="metric-item">
        <span class="metric-label">Analyzed</span>
        <span class="metric-val" id="statAnalyzed">0</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">Quarantined</span>
        <span class="metric-val" style="color: var(--danger);" id="statQuarantined">0</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">Fast-Path Hit</span>
        <span class="metric-val" style="color: var(--cyan);" id="statFastPath">0.0%</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">Avg Latency</span>
        <span class="metric-val" id="statLatency">0.0 ms</span>
      </div>
      <div class="status-pill-safe">
        <div class="pulse-dot"></div>
        <span>SANDBOX ISOLATION ENFORCED</span>
      </div>
    </div>
  </div>

  <div class="container">
    <!-- LEFT PANEL: Ingestion Studio -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">📥 Threat Ingestion Studio</div>
        <span class="panel-badge">RFC 822 / .EML / .MSG</span>
      </div>

      <!-- Threat Samples Taxonomy Pills -->
      <div class="category-label">🎣 Credential Harvesting Attacks</div>
      <div class="pill-group">
        <button class="threat-pill" onclick="loadSample('paypal', this)">PayPal Account Lockout</button>
        <button class="threat-pill" onclick="loadSample('ms365', this)">Microsoft 365 Expiry</button>
        <button class="threat-pill" onclick="loadSample('apple', this)">Apple ID Russian Login</button>
      </div>

      <div class="category-label">🧠 LLM Spearphishing (Zero Typos & BEC)</div>
      <div class="pill-group">
        <button class="threat-pill" onclick="loadSample('ceo_wire', this)">CEO Urgent Escrow Wire</button>
        <button class="threat-pill" onclick="loadSample('it_sso', this)">IT SSO Cert Migration</button>
        <button class="threat-pill" onclick="loadSample('docusign', this)">DocuSign Compensation</button>
      </div>

      <div class="category-label">💣 Dangerous Attachments & Payloads</div>
      <div class="pill-group">
        <button class="threat-pill" onclick="loadSample('invoice_exe', this)">Invoice .pdf.exe (PE MZ)</button>
        <button class="threat-pill" onclick="loadSample('macro_doc', this)">DHL Manifest .docm Macro</button>
      </div>

      <div class="category-label">📢 Commercial Marketing & Spam</div>
      <div class="pill-group">
        <button class="threat-pill" onclick="loadSample('lottery', this)">$2.5M Mega Lottery</button>
        <button class="threat-pill" onclick="loadSample('seo_lead', this)">SEO B2B Marketing (Safe)</button>
        <button class="threat-pill" onclick="loadSample('crypto', this)">Crypto Bot Arbitrage</button>
      </div>

      <div class="category-label">🏢 Authenticated Clean Corporate</div>
      <div class="pill-group">
        <button class="threat-pill" onclick="loadSample('team_sync', this)">Engineering Team Sync</button>
        <button class="threat-pill" onclick="loadSample('github_pr', this)">GitHub PR #142 Notice</button>
        <button class="threat-pill" onclick="loadSample('aws_bill', this)">AWS Cloud Tax Invoice</button>
      </div>

      <!-- Drag & Drop Zone -->
      <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
        <div class="dropzone-icon">📁</div>
        <p>Drag & Drop <strong>.eml</strong> or <strong>.msg</strong> files here</p>
        <span>Click to browse from local filesystem or sample_emails/</span>
        <input type="file" id="fileInput" style="display: none;" accept=".eml,.msg" onchange="handleFileUpload(event)">
      </div>

      <!-- Raw Email Textarea -->
      <label class="editor-label">Raw RFC 822 Headers & Body Payload:</label>
      <textarea id="rawEmail" placeholder="From: ...&#10;To: ...&#10;Subject: ...&#10;Authentication-Results: ...&#10;&#10;Email body content"></textarea>

      <button class="btn-analyze" id="btnAnalyze" onclick="analyzeEmail()">
        <span>⚡ Run Active Multi-Signal Defense</span>
      </button>
    </div>

    <!-- RIGHT PANEL: SOC Threat Verdict & Forensic Analysis -->
    <div class="results-wrapper" id="resultsContainer">
      <div class="panel empty-state">
        <div class="empty-state-icon">🛡️</div>
        <h3 style="font-size: 16px; color: #cbd5e1; margin-bottom: 6px;">Awaiting Email Ingestion</h3>
        <p style="font-size: 13px; max-width: 440px; margin: 0 auto;">Select any real-world threat scenario from the left studio or drag and drop an <strong>.eml</strong> file to trigger the multi-signal analyzer pipeline.</p>
      </div>
    </div>
  </div>

  <script>
    const SAMPLES = {
      paypal: `From: "PayPal Account Security" <security@paypa1-update.com>
Reply-To: phisher@harvest-creds.top
To: employee@acme-corp.com
Subject: URGENT: Your PayPal account has been suspended within 24 hours!!
Authentication-Results: mx.acme-corp.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 10:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear customer, irregular activity was flagged on your account.</p>
<p>Your access will be permanently terminated within 24 hours. Log in immediately to verify identity.</p>
<p><a href="http://192.168.1.100/login">https://paypal.com/security-check</a></p>
<p>Thank you,<br>PayPal Security Department</p>
</body></html>`,

      ms365: `From: "Microsoft 365 Support" <no-reply@microsoft-tenant-audit.xyz>
Reply-To: admin-cases@microsoft-tenant-audit.xyz
To: corporate-user@acme-corp.com
Subject: Notice: Corporate Password Expiration in 24 Hours
Authentication-Results: mx.acme-corp.com; spf=softfail; dkim=none; dmarc=none
Date: Fri, 6 Nov 2026 11:30:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Employee,</p>
<p>Your corporate Microsoft 365 domain password is scheduled to expire in 24 hours.</p>
<p>To retain your existing password without disruption to Teams, Outlook, and OneDrive, confirm your credentials below:</p>
<p><a href="http://xn--microsft-04a.com/portal/login">https://account.microsoft.com/security/password-keep</a></p>
<p>Microsoft Online Services Corporation</p>
</body></html>`,

      apple: `From: "Apple Support Desk" <support@appleid-verify.xyz>
Reply-To: apple.case.escalation@gmail.com
To: user@acme-corp.com
Subject: Security Lock: Unauthorized login attempt from St. Petersburg, RU
Authentication-Results: mx.acme-corp.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 14:15:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your Apple ID was used to sign in to iCloud from an unrecognized device.</p>
<p>Location: St. Petersburg, Russia<br>IP Address: 185.220.101.42</p>
<p>If this was not you, unlock and secure your account immediately: <a href="http://appleid-verify.xyz/auth/restore">https://appleid.apple.com/account/secure</a></p>
</body></html>`,

      ceo_wire: `From: "Sarah Connor (CEO)" <sarah.connor.executive@gmail.com>
Reply-To: executive.routing@outlook.com
To: morgan.reed@synthetic-corp.example
Subject: Confidential: Immediate wire transfer for acquisition closing
Date: Fri, 6 Nov 2026 09:30:00 -0800
Content-Type: text/plain; charset=utf-8

Morgan,

I am currently in an offsite executive board meeting discussing our Horizon acquisition closing and cannot step out for phone calls.
Our outside legal counsel has requested that we wire an initial earnest escrow installment of $48,500 today to satisfy closing covenants.
Please expedite this payment against our primary commercial account.
Wiring instructions are as follows:
Bank: Metropolitan First Commercial
Routing: 021000089
Account: 8849201938
Beneficiary: Horizon Escrow Holdings LLC

Please reply directly with the federal reference wire confirmation number as soon as submitted.
Keep this matter strictly between us until the formal press release is finalized.

Best,
Sarah Connor
Chief Executive Officer`,

      it_sso: `From: "Enterprise Identity Services" <auth-notice@company-sso-sync.org>
Reply-To: identity-support@company-sso-sync.org
To: employee@target-enterprise.com
Subject: Action Required: Mandatory Migration to Enterprise SSO Security Token
Authentication-Results: mx.target-enterprise.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 09:15:00 -0500
Content-Type: text/html; charset=utf-8

<html><body>
<p>Good morning Team,</p>
<p>As part of our periodic ISO 27001 compliance audit, corporate security is transitioning all active directory accounts to hardware-backed identity certificates. To ensure uninterrupted access to internal tools, VPN tunnels, and email routing, please complete the seamless authentication synchronization prior to 17:00 EST today.</p>
<p>You may initiate the single-sign-on verification via our gateway: <a href="https://portal-sso-verify.org/auth/sso">https://sso.target-enterprise.com/cert-sync</a></p>
<p>Failure to synchronize will result in automated credential lock-out per infosec policy.</p>
<p>Sincerely,<br>Identity & Access Governance Team</p>
</body></html>`,

      docusign: `From: "DocuSign Trust Center" <notifications@docusign-partner-portal.com>
Reply-To: documents@docusign-partner-portal.com
To: executive@target-enterprise.com
Subject: Please Review & Sign: Revised 2026 Executive Compensation Agreement
Authentication-Results: mx.target-enterprise.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 13:30:00 -0500
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Colleague,</p>
<p>Your Board of Directors Remuneration Committee has issued an updated 2026 Executive Incentive Agreement for your immediate review and digital acknowledgment.</p>
<p>This document requires electronic signature within 48 hours to ratify equity vesting schedules.</p>
<p><a href="https://review-compensation-portal.com/doc/8849">https://docusign.net/Member/PowerFormSigning.aspx?DocID=991048</a></p>
<p>Thank you,<br>DocuSign Automated Trust Center</p>
</body></html>`,

      invoice_exe: `From: "Accounts Receivable" <billing@supplier-clearing-house.top>
To: ap@acme-corp.com
Subject: Urgent: Overdue Remittance Invoice #INV-889102
Date: Fri, 6 Nov 2026 09:00:00 -0800
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_INVOICE"

--BOUNDARY_INVOICE
Content-Type: text/plain; charset="utf-8"

Please review the attached invoice immediately and process payment.

--BOUNDARY_INVOICE
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice_INV_889102.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAsAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
--BOUNDARY_INVOICE--`,

      macro_doc: `From: "DHL Logistics Hub" <dispatch@dhl-express-tracking.icu>
To: operations@acme-corp.com
Subject: Delivery Exception Notice: Consignment #DHL-4920
Date: Fri, 6 Nov 2026 10:45:00 -0800
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_DHL"

--BOUNDARY_DHL
Content-Type: text/plain; charset="utf-8"

Your consignment could not be cleared through customs. Open the attached customs declaration and enable macros to view tracking data.

--BOUNDARY_DHL
Content-Type: application/vnd.ms-word.document.macroEnabled.12
Content-Disposition: attachment; filename="Customs_Declaration_Manifest.docm"
Content-Transfer-Encoding: base64

UEsDBBQABgAIAAAAIQAAAAAAAAAAAAAAAAAAAAAWAAAAW0NvbnRlbnRfVHlwZXNdLnhtbHBL
AQItABQABgAIAAAAIQAAAAAAAAAAAAAAAAAAAAAWAAAAAAAAAAB2YmEtbWFjcm8tcGF5bG9h
--BOUNDARY_DHL--`,

      lottery: `From: "International Mega Lottery" <claims@win-cash-draw-2026.top>
Reply-To: claims.agent.miller@yahoo.com
To: lucky.winner@acme-corp.com
Subject: CONGRATULATIONS: You won $2,500,000.00 USD in 2026 draw
Date: Fri, 6 Nov 2026 04:00:00 -0800
Content-Type: text/plain; charset=utf-8

CONGRATULATIONS!
Your email was selected as the lucky winner of 2.5 Million USD in the International Mega Draw.
To release your funds, reply with your full name, telephone, address, and processing fee of $250.
Contact Agent Michael at claims.agent.miller@yahoo.com.`,

      seo_lead: `From: "Global SEO Marketing Agency" <leads@top-rank-traffic.xyz>
To: marketing@acme-corp.com
Subject: Guaranteed Page 1 Google Rankings & 500 B2B Leads Monthly
Date: Fri, 6 Nov 2026 08:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Website Owner,</p>
<p>We checked your website domain and noticed you are missing out on thousands of search visitors daily.</p>
<p>We provide guaranteed first page Google rankings and high-converting B2B buyer leads starting at just $199/month.</p>
<p>Reply YES to this email or visit our portal at <a href="http://top-rank-traffic.xyz/deals">http://top-rank-traffic.xyz</a></p>
<p>Click here to unsubscribe from future promotions.</p>
</body></html>`,

      crypto: `From: "Crypto Alpha Trading Group" <vip@crypto-guaranteed-returns.club>
To: investor@acme-corp.com
Subject: Automated AI Crypto Trading Bot - 350% Returns Guaranteed
Date: Fri, 6 Nov 2026 12:40:00 -0800
Content-Type: text/plain; charset=utf-8

Join our private VIP institutional crypto signal channel.
Our proprietary deep learning arbitrage bot executes flash loans with zero drawdown risk.
Deposit a minimum of 0.05 BTC to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to activate daily compounding yield.
Limited slots available for today only.`,

      team_sync: `From: "Alice Smith" <alice@acme-corp.com>
To: bob@acme-corp.com
Subject: Architecture sync today at 3:00 PM
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 10:15:00 -0800
Content-Type: text/plain; charset=utf-8

Hi Bob,

Let's review the active verification architecture deck this afternoon.
See you in conference room 3 or join via our internal Google Meet link:
https://meet.google.com/abc-defg-hij

Best,
Alice`,

      github_pr: `From: "GitHub Notifications" <notifications@github.com>
To: dev-team@acme-corp.com
Subject: [acme/core-engine] Pull request #142 opened: Add calibrator for ensemble
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 11:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>@reviewer, @contributor opened pull request #142: "Add calibrator for ensemble".</p>
<p>View the diff and run CI checks: <a href="https://github.com/acme/core-engine/pull/142">https://github.com/acme/core-engine/pull/142</a></p>
<p>You are receiving this because you are subscribed to this repository.</p>
</body></html>`,

      aws_bill: `From: "Amazon Web Services" <no-reply-aws@amazon.com>
To: billing-admin@acme-corp.com
Subject: Amazon Web Services Invoice Available [Account: 4892-1049-2910]
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 07:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Greetings from Amazon Web Services,</p>
<p>Your latest billing statement for account 4892-1049-2910 is now available in the AWS Management Console.</p>
<p>You can view and download your tax invoice at: <a href="https://console.aws.amazon.com/billing/home">https://console.aws.amazon.com/billing/home</a></p>
<p>Thank you for using AWS.</p>
</body></html>`
    };

    function loadSample(key, elem) {
      document.querySelectorAll('.threat-pill').forEach(p => p.classList.remove('active'));
      if (elem) elem.classList.add('active');
      document.getElementById('rawEmail').value = SAMPLES[key] || '';
    }

    async function fetchTelemetry() {
      try {
        const resp = await fetch("/api/v1/metrics");
        if (resp.ok) {
          const data = await resp.json();
          document.getElementById('statAnalyzed').innerText = data.total_messages_analyzed;
          document.getElementById('statQuarantined').innerText = data.quarantined;
          document.getElementById('statFastPath').innerText = (data.fast_path_ratio * 100).toFixed(1) + "%";
          document.getElementById('statLatency').innerText = data.average_latency_ms.toFixed(1) + " ms";
        }
      } catch (e) {}
    }
    setInterval(fetchTelemetry, 3000);
    fetchTelemetry();

    async function handleFileUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("file", file);

      const btn = document.getElementById('btnAnalyze');
      btn.innerHTML = "<span>⚙️ Parsing & Analyzing File...</span>";
      btn.style.opacity = "0.7";

      try {
        const resp = await fetch("/api/v1/upload", { method: "POST", body: formData });
        const data = await resp.json();
        renderResult(data);
        fetchTelemetry();
      } catch (err) {
        alert("Upload error: " + err);
      } finally {
        btn.innerHTML = "<span>⚡ Run Active Multi-Signal Defense</span>";
        btn.style.opacity = "1";
      }
    }

    async function analyzeEmail() {
      const raw = document.getElementById('rawEmail').value;
      if (!raw.trim()) { alert("Please paste an email or select a threat scenario from the studio!"); return; }

      const btn = document.getElementById('btnAnalyze');
      btn.innerHTML = "<span>⚡ Running 6-Signal Pipeline...</span>";
      btn.style.opacity = "0.7";

      try {
        const resp = await fetch("/api/v1/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ raw_email: raw })
        });
        const data = await resp.json();
        renderResult(data);
        fetchTelemetry();
      } catch (err) {
        alert("Analysis error: " + err);
      } finally {
        btn.innerHTML = "<span>⚡ Run Active Multi-Signal Defense</span>";
        btn.style.opacity = "1";
      }
    }

    function renderResult(res) {
      const container = document.getElementById('resultsContainer');
      const isQuarantine = res.decision === "quarantine";
      const isWarn = res.decision === "warn";
      const isAllow = res.decision === "allow";

      const bannerClass = isQuarantine ? "verdict-quarantine" : (isWarn ? "verdict-warn" : "verdict-allow");
      const badgeText = isQuarantine ? "🚨 QUARANTINE" : (isWarn ? "⚠️ SUSPICIOUS / WARN" : "✅ PASS / ALLOWED");
      const scoreColor = isQuarantine ? "#ef4444" : (isWarn ? "#f59e0b" : "#10b981");

      // Format "Why is it fishy" bullet list
      const whyFishyRaw = res.why_is_it_fishy || "";
      const lines = whyFishyRaw.split("\\n");
      const headlineFirst = lines[0] || "";
      const bullets = lines.slice(1).map(l => l.replace(/^[•\-\*]\s*/, '').trim()).filter(l => l.length > 0);

      const listClass = isAllow && !headlineFirst.includes("spam") ? "safe-list" : "fishy-list";
      const bulletsHtml = bullets.map(b => `<li>${b}</li>`).join("");

      // 6 Diagnostic Signal Cards
      const sigKeys = [
        { key: "header_analyzer", name: "Header & Auth", icon: "📬" },
        { key: "url_analyzer", name: "URL & Hyperlinks", icon: "🔗" },
        { key: "domain_analyzer", name: "Domain Intel", icon: "🌐" },
        { key: "content_analyzer", name: "Content DeBERTa", icon: "🧠" },
        { key: "attachment_analyzer", name: "Attachment Risk", icon: "📎" },
        { key: "llm_judge", name: "LLM Judge", icon: "🤖" },
      ];

      let signalsGridHtml = "";
      for (const item of sigKeys) {
        const sig = res.signals[item.key] || { score: 0.0, weight: 1.0, reasons: [], execution_time_ms: 0.0 };
        const fill = Math.round(sig.score * 100);
        const col = sig.score >= 0.7 ? '#ef4444' : (sig.score >= 0.35 ? '#f59e0b' : '#10b981');
        const attrib = res.feature_attributions[item.key] || 0.0;
        const reasonsList = sig.reasons && sig.reasons.length > 0
          ? sig.reasons.slice(0, 2).map(r => `<div>${r}</div>`).join("")
          : `<div>Nominal baseline score</div>`;

        signalsGridHtml += `
          <div class="signal-card">
            <div class="sig-top">
              <span class="sig-name">${item.icon} ${item.name}</span>
              <span class="sig-score" style="color: ${col};">${(sig.score * 100).toFixed(0)}%</span>
            </div>
            <div class="sig-bar">
              <div class="sig-fill" style="width: ${fill}%; background: ${col};"></div>
            </div>
            <div class="sig-metrics">
              <span>WEIGHT: ${sig.weight.toFixed(1)}x</span>
              <span>ATTR: +${attrib.toFixed(2)}</span>
              <span>${sig.execution_time_ms} ms</span>
            </div>
            <div class="sig-reasons">${reasonsList}</div>
          </div>
        `;
      }

      // Active Verification Honeypot Terminal
      let activeVerifHtml = "";
      if (res.active_verification && res.active_verification.engaged) {
        const v = res.active_verification;
        let turnsHtml = "";
        for (const t of v.turns) {
          const isPersona = t.role === "synthetic_persona";
          turnsHtml += `
            <div class="chat-turn ${isPersona ? 'turn-persona' : 'turn-adv'}">
              <div class="turn-author">
                <span>${isPersona ? '🤖 Synthetic Persona (' + v.persona_name + ')' : '🎯 Simulated Adversary'}</span>
                <span>Turn #${t.turn_index}</span>
              </div>
              <p>${t.message}</p>
            </div>
          `;
        }

        const tacticsHtml = v.adversary_tactics_observed.map(tac => `<span class="mitre-tag">${tac}</span>`).join(" ");

        activeVerifHtml = `
          <div class="terminal-box">
            <div class="terminal-header">
              <div class="terminal-title">
                <span>💻 SANDBOXED ACTIVE VERIFICATION TRANSCRIPT (ZERO REAL NETWORK CONTACT)</span>
              </div>
              <span class="terminal-badge">Deception Score: ${(v.deception_score * 100).toFixed(0)}%</span>
            </div>
            <div style="font-size: 11px; color: #94a3b8; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
              <span>${v.summary}</span>
              <div style="display: flex; gap: 6px;">${tacticsHtml}</div>
            </div>
            ${turnsHtml}
          </div>
        `;
      }

      container.innerHTML = `
        <!-- MODULE: Executive Threat Assessment Banner -->
        <div class="verdict-banner ${bannerClass}">
          <div>
            <div style="font-size: 11px; text-transform: uppercase; font-weight: 800; letter-spacing: 0.8px; color: ${scoreColor}; margin-bottom: 4px;">
              ${res.verdict_category || 'SECURITY THREAT VERDICT'}
            </div>
            <div class="verdict-title">${res.verdict_headline || badgeText}</div>
            <div class="verdict-sub">Decision Policy: <strong>${badgeText}</strong> &bull; Target False Positive Rate: <strong>&le; 1.0%</strong></div>
            <div class="verdict-meta">
              <span>⏱️ Latency: <strong>${res.latency_ms} ms</strong></span>
              <span>⚡ Fast Path: <strong>${res.fast_path_used ? 'BYPASS HIT' : 'DEEP PIPELINE'}</strong></span>
              <span>🔒 Privacy: <strong>PII Redacted & Salted</strong></span>
              <span>🆔 ID: <strong>${res.message_id}</strong></span>
            </div>
          </div>
          <div class="gauge-box">
            <div class="gauge-score" style="color: ${scoreColor};">${(res.calibrated_score * 100).toFixed(1)}%</div>
            <div class="gauge-label">Calibrated Risk</div>
          </div>
        </div>

        <!-- MODULE: What does it say? & Why is it fishy? (Right above matrix) -->
        <div class="narrative-grid">
          <div class="narrative-card">
            <div class="narrative-header" style="color: #60a5fa;">
              <span>💬 WHAT DOES THIS MESSAGE SAY?</span>
            </div>
            <div class="narrative-body">${res.what_does_it_say || 'Routine correspondence.'}</div>
          </div>

          <div class="narrative-card">
            <div class="narrative-header" style="color: ${scoreColor};">
              <span>🔍 ${headlineFirst || 'WHY IS THIS SUSPICIOUS?'}</span>
            </div>
            <div class="narrative-body">
              <ul class="${listClass}">${bulletsHtml}</ul>
            </div>
          </div>
        </div>

        <!-- MODULE: Tactical Recommendation -->
        <div class="action-callout">
          <strong>🛡️ Recommended Action:</strong>
          <span>${res.recommended_action || 'Proceed with standard operational policy.'}</span>
        </div>

        <!-- MODULE: Multi-Signal Diagnostic Matrix -->
        <div>
          <div class="matrix-title">
            <span>📊 Multi-Signal Diagnostic Matrix (Learned Attribution Breakdown)</span>
            <span style="font-size: 11px; color: var(--text-dim); font-weight: normal;">6 Independent Domain Analyzers</span>
          </div>
          <div class="signals-grid">
            ${signalsGridHtml}
          </div>
        </div>

        <!-- MODULE: Active Verification Twin -->
        ${activeVerifHtml}
      `;
    }
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html)
