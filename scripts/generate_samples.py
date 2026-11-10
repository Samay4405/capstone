"""Generates realistic sample .eml files across multiple threat categories."""

import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

BASE_DIR = "sample_emails"

CATEGORIES = [
    "phishing_credential_harvest",
    "phishing_llm_spearphishing",
    "phishing_malware_attachment",
    "spam_bulk_commercial",
    "legitimate_business",
]

for cat in CATEGORIES:
    os.makedirs(os.path.join(BASE_DIR, cat), exist_ok=True)


def write_file(subfolder: str, filename: str, content: str):
    path = os.path.join(BASE_DIR, subfolder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Created: {path}")


def write_bytes(subfolder: str, filename: str, raw_bytes: bytes):
    path = os.path.join(BASE_DIR, subfolder, filename)
    with open(path, "wb") as f:
        f.write(raw_bytes)
    print(f"Created: {path}")


# ==============================================================================
# 1. Credential Harvesting Phishing (Punycode, Raw IP, Href Mismatch)
# ==============================================================================

p1 = """From: "PayPal Account Security" <security@paypa1-update.com>
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
</body></html>"""
write_file("phishing_credential_harvest", "01_paypal_account_suspended.eml", p1)

p2 = """From: "Microsoft 365 Support" <no-reply@microsoft-tenant-audit.xyz>
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
</body></html>"""
write_file("phishing_credential_harvest", "02_microsoft365_password_expiry.eml", p2)

p3 = """From: "Apple Support Desk" <support@appleid-verify.xyz>
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
</body></html>"""
write_file("phishing_credential_harvest", "03_apple_id_security_lock.eml", p3)


# ==============================================================================
# 2. LLM-Written Spearphishing (No typos, high context, BEC, SSO migration)
# ==============================================================================

l1 = """From: "Sarah Connor (CEO)" <sarah.connor.executive@gmail.com>
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
Chief Executive Officer"""
write_file("phishing_llm_spearphishing", "01_executive_ceo_urgent_wire.eml", l1)

l2 = """From: "Enterprise Identity Services" <auth-notice@company-sso-sync.org>
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
</body></html>"""
write_file("phishing_llm_spearphishing", "02_it_sso_certificate_migration.eml", l2)

l3 = """From: "DocuSign Trust Center" <notifications@docusign-partner-portal.com>
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
</body></html>"""
write_file("phishing_llm_spearphishing", "03_docusign_executive_bonus_agreement.eml", l3)


# ==============================================================================
# 3. Malware & Dangerous Attachment Phishing
# ==============================================================================

# 01 with double extension & PE executable header
msg_att1 = MIMEMultipart()
msg_att1['From'] = '"Accounts Receivable" <billing@supplier-clearing-house.top>'
msg_att1['To'] = 'ap@acme-corp.com'
msg_att1['Subject'] = 'Urgent: Overdue Remittance Invoice #INV-889102'
msg_att1['Date'] = 'Fri, 6 Nov 2026 09:00:00 -0800'
msg_att1.attach(MIMEText('Please review the attached invoice immediately and process payment.', 'plain'))

part1 = MIMEBase('application', 'octet-stream')
part1.set_payload(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' + b'A' * 200)
encoders.encode_base64(part1)
part1.add_header('Content-Disposition', 'attachment; filename="Invoice_INV_889102.pdf.exe"')
msg_att1.attach(part1)
write_bytes("phishing_malware_attachment", "01_overdue_invoice_double_extension.eml", msg_att1.as_bytes())

# 02 with macro-enabled document (.docm)
msg_att2 = MIMEMultipart()
msg_att2['From'] = '"DHL Logistics Hub" <dispatch@dhl-express-tracking.icu>'
msg_att2['To'] = 'operations@acme-corp.com'
msg_att2['Subject'] = 'Delivery Exception Notice: Consignment #DHL-4920'
msg_att2['Date'] = 'Fri, 6 Nov 2026 10:45:00 -0800'
msg_att2.attach(MIMEText('Your consignment could not be cleared through customs. Open the attached customs declaration and enable macros to view tracking data.', 'plain'))

part2 = MIMEBase('application', 'vnd.ms-word.document.macroEnabled.12')
part2.set_payload(b'PK\x03\x04\x14\x00\x06\x00' + b'VBA-MACRO-PAYLOAD' * 20)
encoders.encode_base64(part2)
part2.add_header('Content-Disposition', 'attachment; filename="Customs_Declaration_Manifest.docm"')
msg_att2.attach(part2)
write_bytes("phishing_malware_attachment", "02_shipping_manifest_macro_doc.eml", msg_att2.as_bytes())

# 03 with compressed archive container (.zip)
msg_att3 = MIMEMultipart()
msg_att3['From'] = '"HR Benefits Bureau" <payroll@hr-compliance-portal.club>'
msg_att3['To'] = 'all-staff@acme-corp.com'
msg_att3['Subject'] = 'Confidential: 2026 Revised Medical Benefit Schedules'
msg_att3['Date'] = 'Fri, 6 Nov 2026 15:20:00 -0800'
msg_att3.attach(MIMEText('Attached is the 2026 open enrollment benefits archive. Extract and review the documentation before Friday.', 'plain'))

part3 = MIMEBase('application', 'zip')
part3.set_payload(b'PK\x03\x04\x14\x00\x08\x00' + b'ZIP-CONTAINER' * 30)
encoders.encode_base64(part3)
part3.add_header('Content-Disposition', 'attachment; filename="Open_Enrollment_Benefits_2026.zip"')
msg_att3.attach(part3)
write_bytes("phishing_malware_attachment", "03_scanned_benefits_archive.eml", msg_att3.as_bytes())


# ==============================================================================
# 4. Bulk Commercial Spam
# ==============================================================================

s1 = """From: "International Mega Lottery" <claims@win-cash-draw-2026.top>
Reply-To: claims.agent.miller@yahoo.com
To: lucky.winner@acme-corp.com
Subject: CONGRATULATIONS: You won $2,500,000.00 USD in 2026 draw
Date: Fri, 6 Nov 2026 04:00:00 -0800
Content-Type: text/plain; charset=utf-8

CONGRATULATIONS!
Your email was selected as the lucky winner of 2.5 Million USD in the International Mega Draw.
To release your funds, reply with your full name, telephone, address, and processing fee of $250.
Contact Agent Michael at claims.agent.miller@yahoo.com."""
write_file("spam_bulk_commercial", "01_international_lottery_winner.eml", s1)

s2 = """From: "Global SEO Marketing Agency" <leads@top-rank-traffic.xyz>
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
</body></html>"""
write_file("spam_bulk_commercial", "02_unsolicited_seo_lead_generation.eml", s2)

s3 = """From: "Crypto Alpha Trading Group" <vip@crypto-guaranteed-returns.club>
To: investor@acme-corp.com
Subject: Automated AI Crypto Trading Bot - 350% Returns Guaranteed
Date: Fri, 6 Nov 2026 12:40:00 -0800
Content-Type: text/plain; charset=utf-8

Join our private VIP institutional crypto signal channel.
Our proprietary deep learning arbitrage bot executes flash loans with zero drawdown risk.
Deposit a minimum of 0.05 BTC to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to activate daily compounding yield.
Limited slots available for today only."""
write_file("spam_bulk_commercial", "03_cryptocurrency_investment_spam.eml", s3)


# ==============================================================================
# 5. Legitimate Business Mail (Auth passed, normal tone)
# ==============================================================================

b1 = """From: "Alice Smith" <alice@acme-corp.com>
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
Alice"""
write_file("legitimate_business", "01_engineering_architecture_sync.eml", b1)

b2 = """From: "GitHub Notifications" <notifications@github.com>
To: dev-team@acme-corp.com
Subject: [acme/core-engine] Pull request #142 opened: Add calibrator for ensemble
Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass
Date: Fri, 6 Nov 2026 11:00:00 -0800
Content-Type: text/html; charset=utf-8

<html><body>
<p>@reviewer, @contributor opened pull request #142: "Add calibrator for ensemble".</p>
<p>View the diff and run CI checks: <a href="https://github.com/acme/core-engine/pull/142">https://github.com/acme/core-engine/pull/142</a></p>
<p>You are receiving this because you are subscribed to this repository.</p>
</body></html>"""
write_file("legitimate_business", "02_github_pull_request_notification.eml", b2)

b3 = """From: "Amazon Web Services" <no-reply-aws@amazon.com>
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
</body></html>"""
write_file("legitimate_business", "03_aws_cloud_monthly_invoice.eml", b3)

print("\nSuccessfully generated 15 test email files in sample_emails/")

