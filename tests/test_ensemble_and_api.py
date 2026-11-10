import pytest
from fastapi.testclient import TestClient
from active_verification.api.server import app
from active_verification.models.schemas import DecisionPolicy

client = TestClient(app)

PHISHING_EML = """From: "PayPal Security" <security@paypa1-update.com>
Reply-To: phisher@harvest-creds.top
To: victim@example.com
Subject: URGENT: Your PayPal account has been suspended within 24 hours!!
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 10:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear customer, urgent action required!</p>
<p>Log in immediately to restore account.</p>
<p><a href="http://192.168.1.100/login">https://paypal.com/security-check</a></p>
</body></html>"""

BENIGN_EML = """From: "Alice Smith" <alice@acme-corp.com>
To: bob@acme-corp.com
Subject: Architecture sync today at 3:00 PM
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 10:15:00 -0800
Content-Type: text/plain; charset=utf-8

Hi Bob,
Let's review the active verification architecture deck this afternoon.
See you in conference room 3.
Best,
Alice"""


def test_api_health():
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["sandbox_strict"] is True


def test_api_analyze_phishing():
    resp = client.post("/api/v1/analyze", json={"raw_email": PHISHING_EML})
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] in ["quarantine", "warn"]
    assert data["calibrated_score"] >= 0.70
    assert len(data["why_explanation"]) > 0
    assert "header_analyzer" in data["signals"]
    assert "url_analyzer" in data["signals"]
    assert data["active_verification"] is not None


def test_api_analyze_benign():
    resp = client.post("/api/v1/analyze", json={"raw_email": BENIGN_EML})
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert data["calibrated_score"] < 0.50
    assert data["fast_path_used"] is True


def test_api_upload_file():
    files = {"file": ("test.eml", PHISHING_EML.encode("utf-8"), "message/rfc822")}
    resp = client.post("/api/v1/upload", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] in ["quarantine", "warn"]


def test_api_metrics():
    resp = client.get("/api/v1/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_messages_analyzed"] >= 1

