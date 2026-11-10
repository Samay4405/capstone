import pytest
from active_verification.ingestion.parser import parser
from active_verification.models.schemas import AuthStatus

SAMPLE_EML = b"""From: "Security Team" <security@paypa1-update.com>
Reply-To: phisher@attacker.org
To: victim@example.com
Subject: Urgent: Verify your PayPal account
Authentication-Results: mx.google.com; spf=fail (google.com: domain does not designate IP) smtp.mailfrom=attacker.org; dkim=neutral; dmarc=fail action=none header.from=paypa1-update.com
Received: from mail.attacker.org (mail.attacker.org [198.51.100.42]) by mx.google.com with ESMTP id abc123xyz; Fri, 6 Nov 2026 10:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear customer, click here: <a href="http://192.168.1.1/login">https://paypal.com/verify</a></p>
<p>Alternative link: <a href="http://xn--pypal-4ve.com">Special portal</a></p>
</body></html>
"""


def test_parser_headers_and_urls():
    msg = parser.parse_raw(SAMPLE_EML)
    assert msg.headers.from_name == "Security Team"
    assert msg.headers.from_address == "security@paypa1-update.com"
    assert msg.headers.from_domain == "paypa1-update.com"
    assert msg.headers.reply_to == "phisher@attacker.org"
    assert msg.headers.auth_results.spf == AuthStatus.FAIL
    assert msg.headers.auth_results.dmarc == AuthStatus.FAIL
    assert len(msg.urls) == 2

    mismatch_url = next(u for u in msg.urls if "192.168.1.1" in u.original_url)
    assert mismatch_url.href_mismatch is True
    assert mismatch_url.is_ip_address is True

    puny_url = next(u for u in msg.urls if "xn--" in u.original_url)
    assert puny_url.punycode_domain is not None

