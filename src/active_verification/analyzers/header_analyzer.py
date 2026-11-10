"""Header analyzer: examines SPF/DKIM/DMARC, spoofing, and routing anomalies."""

import re
from typing import List, Dict, Any
from active_verification.models.schemas import EmailMessage, SignalScore, AuthStatus
from active_verification.analyzers.base import BaseAnalyzer

COMMON_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office365.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wells fargo": ["wellsfargo.com"],
    "docusign": ["docusign.net", "docusign.com"],
    "dropbox": ["dropbox.com"],
    "irs": ["irs.gov"],
    "internal it": [],
    "it support": [],
    "hr payroll": [],
    "ceo": [],
    "cfo": [],
    "executive": [],
    "chief executive": [],
}


class HeaderAnalyzer(BaseAnalyzer):
    """Analyzes email headers for authentication, brand spoofing, and routing anomalies."""

    def __init__(self, weight: float = 1.2):
        super().__init__(name="header_analyzer", weight=weight)

    def analyze(self, email: EmailMessage) -> SignalScore:
        reasons: List[str] = []
        score = 0.0
        meta: Dict[str, Any] = {}

        headers = email.headers
        from_name = headers.from_name.lower()
        from_addr = headers.from_address.lower()
        from_domain = headers.from_domain.lower()
        reply_to = (headers.reply_to or "").lower()
        return_path = (headers.return_path or "").lower()

        # 1. Brand display name spoofing
        brand_spoofed = False
        for brand, legit_domains in COMMON_BRANDS.items():
            if brand in from_name:
                if legit_domains:
                    is_legit = any(from_domain == d or from_domain.endswith("." + d) for d in legit_domains)
                    if not is_legit:
                        brand_spoofed = True
                        score += 0.50
                        reasons.append(
                            f"Display name claims brand '{brand.title()}' but sending domain is '{from_domain}'"
                        )
                else:
                    # Generic internal impersonation (IT Support, HR, etc.) from external domain
                    score += 0.35
                    reasons.append(
                        f"Display name impersonates internal authority role '{from_name}' from external address '{from_addr}'"
                    )
                break
        meta["brand_spoofed"] = brand_spoofed

        # 2. Authentication-Results (SPF, DKIM, DMARC)
        auth = headers.auth_results
        meta["spf_status"] = auth.spf.value
        meta["dkim_status"] = auth.dkim.value
        meta["dmarc_status"] = auth.dmarc.value

        if auth.dmarc == AuthStatus.FAIL:
            score += 0.40
            reasons.append(f"DMARC validation failed ({auth.dmarc_details or 'policy reject/quarantine'})")
        elif auth.dmarc == AuthStatus.PASS:
            score -= 0.15

        if auth.spf == AuthStatus.FAIL:
            score += 0.30
            reasons.append("SPF validation failed (unauthorized sending IP)")
        elif auth.spf == AuthStatus.SOFTFAIL:
            score += 0.15
            reasons.append("SPF validation returned softfail")
        elif auth.spf == AuthStatus.PASS:
            score -= 0.10

        if auth.dkim == AuthStatus.FAIL:
            score += 0.25
            reasons.append("DKIM cryptographic signature verification failed")
        elif auth.dkim == AuthStatus.PASS:
            score -= 0.10

        # 3. From vs Reply-To mismatch
        meta["reply_to_mismatch"] = False
        if reply_to and "@" in reply_to:
            reply_domain = reply_to.split("@")[-1].strip()
            if from_domain and reply_domain != from_domain:
                # Exclude common corporate mailing domains if subdomain
                if not (reply_domain.endswith("." + from_domain) or from_domain.endswith("." + reply_domain)):
                    meta["reply_to_mismatch"] = True
                    score += 0.35
                    reasons.append(
                        f"Sender address '{from_addr}' does not match Reply-To address '{reply_to}'"
                    )

        # 4. From vs Return-Path mismatch
        meta["return_path_mismatch"] = False
        if return_path and "@" in return_path and from_domain:
            rp_domain = return_path.split("@")[-1].strip()
            if rp_domain != from_domain and not (rp_domain.endswith("." + from_domain) or from_domain.endswith("." + rp_domain)):
                meta["return_path_mismatch"] = True
                score += 0.15
                reasons.append(f"Return-Path domain '{rp_domain}' differs from From domain '{from_domain}'")

        # 5. Received-chain anomalies
        hops = headers.received_hops
        meta["hop_count"] = len(hops)
        if len(hops) > 8:
            score += 0.10
            reasons.append(f"Unusually long relay chain ({len(hops)} hops) suggests relay proxying")

        # Normalize score within [0.0, 1.0]
        final_score = max(0.0, min(1.0, score))

        # Confidence is high if we have authentication headers or multiple verification checks
        confidence = 0.95 if auth.raw_header or auth.spf != AuthStatus.NONE else 0.70

        return SignalScore(
            analyzer_name=self.name,
            score=round(final_score, 4),
            weight=self.weight,
            confidence=confidence,
            reasons=reasons,
            metadata=meta,
        )


header_analyzer = HeaderAnalyzer()

