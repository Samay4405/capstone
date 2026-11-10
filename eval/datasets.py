"""Curated evaluation dataset generator: classic corpora, LLM-generated phishing, and legitimate business mail."""

import random
from typing import List, Dict, Any, Tuple
from active_verification.models.schemas import EmailMessage, IngestionSource
from active_verification.ingestion.parser import parser

# Templates for LLM-written phishing (flawless grammar, professional tone, valid SPF/DKIM on attacker domains, zero tell-tale typos)
LLM_PHISHING_TEMPLATES = [
    """From: "Enterprise Identity Services" <auth-notice@company-sso-sync.org>
Reply-To: identity-support@company-sso-sync.org
To: employee@target-enterprise.com
Subject: Action Required: Mandatory Migration to Enterprise SSO Security Token
Authentication-Results: mx.target-enterprise.com; spf=pass (google.com: domain designates IP); dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 09:15:00 -0500
Content-Type: text/html; charset=utf-8

<html><body>
<p>Good morning,</p>
<p>As part of our periodic ISO 27001 compliance audit, corporate security is transitioning all active directory accounts to hardware-backed identity certificates. To ensure uninterrupted access to internal tools, VPN tunnels, and email routing, please complete the seamless authentication synchronization prior to 17:00 EST today.</p>
<p>You may initiate the single-sign-on verification via our gateway: <a href="https://portal-sso-verify.org/auth/sso">https://sso.target-enterprise.com/cert-sync</a></p>
<p>Failure to synchronize will result in automated credential lock-out per infosec policy.</p>
<p>Sincerely,<br>Identity & Access Governance Team</p>
</body></html>""",

    """From: "David Miller, Chief Financial Officer" <david.miller.cfo@exec-advisory.org>
Reply-To: direct.exec.desk@gmail.com
To: accounts.payable@target-enterprise.com
Subject: Strictly Confidential: Interim Escrow Deposit for Horizon Acquisition
Authentication-Results: mx.target-enterprise.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 11:45:00 -0500
Content-Type: text/plain; charset=utf-8

Hi team,

I am in an executive board meeting discussing the Horizon closing and cannot step out for phone calls.
Our outside legal counsel has requested that we wire an initial earnest escrow installment of $64,200 today to satisfy closing covenants.
Please expedite this payment against our primary commercial account.
Wiring instructions are as follows:
Bank: Metropolitan First Commercial
Routing: 021000089
Account: 8849201938
Beneficiary: Horizon Escrow Holdings LLC

Please reply directly with the federal reference wire confirmation number as soon as submitted.
Keep this matter strictly between us until the formal press release.

Best regards,
David Miller
Chief Financial Officer""",

    """From: "DocuSign Trust Center" <notifications@docusign-partner-portal.com>
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
</body></html>""",

    """From: "Microsoft 365 Cloud Compliance" <security@microsoft-tenant-audit.com>
Reply-To: compliance@microsoft-tenant-audit.com
To: user@target-enterprise.com
Subject: Security Notification: Enterprise Multi-Factor Authentication Synchronization Required
Authentication-Results: mx.target-enterprise.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 14:10:00 -0500
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Microsoft 365 User,</p>
<p>In accordance with updated tenant security baselines, your workstation identity certificate requires renewal to continue synchronizing Exchange Online and OneDrive for Business.</p>
<p>Please review and confirm your modern authentication tokens through the verified cloud endpoint:</p>
<p><a href="https://tenant-access-review.com/auth">https://mysignins.microsoft.com/security-info</a></p>
<p>Microsoft Security & Identity Operations</p>
</body></html>""",

    """From: "Strategic Vendor Operations" <billing@cdn-cloud-infrastructure.com>
Reply-To: accounts-clearing@gmail.com
To: finance@target-enterprise.com
Subject: Overdue Notice: Outstanding Infrastructure Invoice #INV-2026-881
Authentication-Results: mx.target-enterprise.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 15:00:00 -0500
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Accounts Payable,</p>
<p>Our records indicate that invoice #INV-2026-881 in the amount of $18,420.00 for core CDN network delivery remains unpaid and is currently 14 days past due.</p>
<p>To avoid service degradation or routing suspension of your production cluster, please remit payment via ACH or update your clearing instructions using our secure enterprise billing portal:</p>
<p><a href="https://cdn-billing-gateway.com/pay/inv-881">https://fastcloud.net/enterprise/billing/pay</a></p>
<p>Thank you for your prompt cooperation.</p>
</body></html>""",
]

# Classic phishing templates (Nazario / SpamAssassin corpus style: typos, raw IPs, generic urgency, lottery/bank scams)
CLASSIC_PHISHING_TEMPLATES = [
    """From: "PayPal Security" <security@paypa1-update.com>
Reply-To: phisher@harvest-creds.top
To: victim@example.com
Subject: URGENT: Your PayPal account has been suspended within 24 hours!!
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 10:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Customer,</p>
<p>Your PayPal acount has been locked due to irregular activities!! Click bellow to verify your account or it will be suspended forever!!</p>
<p><a href="http://192.168.1.100/login">https://paypal.com/security-check</a></p>
<p>Thanks, Paypal Team</p>
</body></html>""",

    """From: "Bank of America Online" <alert@bofa-sec-alert.xyz>
Reply-To: bofa.fraud.desk@gmail.com
To: customer@example.com
Subject: IMPORTANT NOTIFICATION: Verify your Online Banking Profile
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 08:30:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Valued Client,</p>
<p>We detected unauthorized access to your checking account. To restore full access, verify your debit card number and PIN code.</p>
<p><a href="http://www.bofa-sec-alert.xyz/verify">https://bankofamerica.com/login</a></p>
</body></html>""",

    """From: "International Lottery Commission" <lottery@win-cash-now.top>
Reply-To: claims.agent@yahoo.com
To: lucky.winner@example.com
Subject: YOU HAVE WON $2,500,000.00 USD IN 2026 MEGA DRAW
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=none
Date: Fri, 6 Nov 2026 04:00:00 -0800
Content-Type: text/plain; charset=utf-8

CONGRATULATIONS!
Your email was selected as the lucky winner of 2.5 Million USD.
To claim your funds, reply with your full name, telephone, address, and processing fee of $250.
Contact Agent Michael at claims.agent@yahoo.com.""",

    """From: "Apple Support" <no-reply@appleid-manage-icloud.club>
Reply-To: apple.case.992@mail.ru
To: icloud.user@example.com
Subject: Your iCloud Storage is Full - Photos Will Be Deleted
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 12:10:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your iCloud storage has exceeded its quota (50 GB / 50 GB). Your photo backups will be deleted in 24 hours.</p>
<p>Upgrade to 200 GB immediately for $0.99: <a href="http://appleid-manage-icloud.club/upgrade">https://apple.com/icloud/upgrade</a></p>
</body></html>""",

    """From: "DHL Delivery Express" <tracking@dhl-parcel-pickup.icu>
Reply-To: dhl-dispatch@dhl-parcel-pickup.icu
To: recipient@example.com
Subject: Delivery Failed: Package #DHL-994029 Held at Warehouse
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Date: Fri, 6 Nov 2026 16:45:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your parcel #DHL-994029 could not be delivered due to incomplete street address.</p>
<p>Download the shipping label and confirm your redelivery fee: <a href="http://185.120.30.4/label.zip">https://dhl.com/track/label</a></p>
</body></html>""",
]

# Legitimate business emails (genuine domains, valid SPF/DKIM/DMARC pass, normal tone)
LEGITIMATE_BUSINESS_TEMPLATES = [
    """From: "Alice Smith" <alice@acme-corp.com>
To: bob@acme-corp.com
Subject: Architecture sync today at 3:00 PM
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 10:15:00 -0800
Content-Type: text/plain; charset=utf-8

Hi Bob,

Let's review the active verification architecture deck this afternoon.
See you in conference room 3 or join on Google Meet.

Best,
Alice""",

    """From: "GitHub" <notifications@github.com>
To: dev-team@acme-corp.com
Subject: [acme/core-engine] Pull request #142 opened: Add calibrator for ensemble
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 11:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>@reviewer, @contributor opened pull request #142: "Add calibrator for ensemble".</p>
<p>View the diff and run CI checks: <a href="https://github.com/acme/core-engine/pull/142">https://github.com/acme/core-engine/pull/142</a></p>
</body></html>""",

    """From: "Google Calendar" <calendar-notification@google.com>
To: engineer@acme-corp.com
Subject: Invitation: Weekly Engineering Standup @ Mon Nov 9, 2026 9:30am - 10am
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 12:00:00 -0800
Content-Type: text/plain; charset=utf-8

You have been invited to Weekly Engineering Standup.
When: Mon Nov 9, 2026 9:30am - 10am (PST)
Organizer: Sarah Connor <sarah@acme-corp.com>""",

    """From: "AWS Billing" <no-reply-aws@amazon.com>
To: cloud-ops@acme-corp.com
Subject: Amazon Web Services Invoice Available [Account: 4892-1049-2910]
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 07:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>Greetings from Amazon Web Services,</p>
<p>Your latest billing statement for account 4892-1049-2910 is now available in the AWS Management Console.</p>
<p>You can view and download your tax invoice at: <a href="https://console.aws.amazon.com/billing/home">https://console.aws.amazon.com/billing/home</a></p>
<p>Thank you for using AWS.</p>
</body></html>""",

    """From: "Slack Notifications" <notification@slack.com>
To: employee@acme-corp.com
Subject: New messages in #security-eng
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 14:00:00 -0800
Content-Type: text/plain; charset=utf-8

Jordan posted in #security-eng:
"The new Active Verification pipeline passed all unit tests with 100% test coverage."
Reply on Slack: https://acme.slack.com/archives/C01234567""",
]


def load_curated_eval_dataset(total_samples: int = 120, seed: int = 42) -> List[Tuple[EmailMessage, int, str]]:
    """Build a balanced, reproducible evaluation dataset.
    
    Returns:
        List of tuples: (EmailMessage, ground_truth_label, category)
        where ground_truth_label is 1 for phishing, 0 for benign.
    """
    random.seed(seed)
    dataset: List[Tuple[EmailMessage, int, str]] = []

    # Target ratio: 25% classic phishing, 25% LLM-written phishing, 50% benign
    n_classic = total_samples // 4
    n_llm = total_samples // 4
    n_benign = total_samples - (n_classic + n_llm)

    # 1. Classic Phishing (Label = 1)
    for i in range(n_classic):
        tmpl = CLASSIC_PHISHING_TEMPLATES[i % len(CLASSIC_PHISHING_TEMPLATES)]
        msg = parser.parse_raw(tmpl.encode("utf-8"), source=IngestionSource.EVAL)
        msg.id = f"eval_classic_{i:04d}"
        dataset.append((msg, 1, "classic_phishing"))

    # 2. LLM-written Phishing (Label = 1)
    for i in range(n_llm):
        tmpl = LLM_PHISHING_TEMPLATES[i % len(LLM_PHISHING_TEMPLATES)]
        msg = parser.parse_raw(tmpl.encode("utf-8"), source=IngestionSource.EVAL)
        msg.id = f"eval_llm_{i:04d}"
        dataset.append((msg, 1, "llm_written_phishing"))

    # 3. Legitimate Business Mail (Label = 0)
    for i in range(n_benign):
        tmpl = LEGITIMATE_BUSINESS_TEMPLATES[i % len(LEGITIMATE_BUSINESS_TEMPLATES)]
        msg = parser.parse_raw(tmpl.encode("utf-8"), source=IngestionSource.EVAL)
        msg.id = f"eval_benign_{i:04d}"
        dataset.append((msg, 0, "legitimate_business"))

    random.shuffle(dataset)
    return dataset
