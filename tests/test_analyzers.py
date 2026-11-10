import pytest
from active_verification.ingestion.parser import parser
from active_verification.analyzers.header_analyzer import header_analyzer
from active_verification.analyzers.url_analyzer import url_analyzer
from active_verification.analyzers.domain_analyzer import domain_analyzer
from active_verification.analyzers.attachment_analyzer import attachment_analyzer
from active_verification.analyzers.content_analyzer import content_analyzer
from active_verification.analyzers.llm_judge import llm_judge

PHISHING_EML = b"""From: "PayPal Account Security" <support@paypa1-update.com>
Reply-To: phisher@harvest-creds.top
To: employee@acme-corp.com
Subject: URGENT: Your PayPal account has been suspended within 24 hours
Authentication-Results: mx.acme-corp.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 10:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear customer, urgent action required!</p>
<p>Your account will be suspended within 24 hours. Log in immediately to verify your identity.</p>
<p><a href="http://192.168.1.100/login">https://paypal.com/security-check</a></p>
</body></html>
"""

BENIGN_EML = b"""From: "Alice Smith" <alice@acme-corp.com>
To: bob@acme-corp.com
Subject: Project update sync at 3pm
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 10:15:00 -0800
Content-Type: text/plain; charset=utf-8

Hi Bob,
Let's review the active verification architecture deck this afternoon.
See you in conference room 3.
Best,
Alice
"""


def test_analyzers_on_phishing():
    msg = parser.parse_raw(PHISHING_EML)

    s_hdr = header_analyzer.run(msg)
    assert s_hdr.score >= 0.70
    assert any("paypal" in r.lower() for r in s_hdr.reasons)

    s_url = url_analyzer.run(msg)
    assert s_url.score >= 0.80
    assert any("Deceptive link text" in r or "IP address" in r for r in s_url.reasons)

    s_dom = domain_analyzer.run(msg)
    assert s_dom.score >= 0.70

    s_cnt = content_analyzer.run(msg)
    assert s_cnt.score >= 0.50

    s_llm = llm_judge.run(msg)
    assert s_llm.score >= 0.60


def test_analyzers_on_benign():
    msg = parser.parse_raw(BENIGN_EML)

    s_hdr = header_analyzer.run(msg)
    assert s_hdr.score <= 0.10

    s_url = url_analyzer.run(msg)
    assert s_url.score == 0.0

    s_dom = domain_analyzer.run(msg)
    assert s_dom.score <= 0.20

    s_cnt = content_analyzer.run(msg)
    assert s_cnt.score <= 0.20
