"""URL and HTML analyzer: detects link spoofing, redirects, punycode, and obfuscation."""

import re
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs
from active_verification.models.schemas import EmailMessage, SignalScore, ExtractedURL
from active_verification.analyzers.base import BaseAnalyzer

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "icu", "click", "cam", "kim", "rest", "surf",
    "gq", "cf", "ml", "ga", "tk", "pw", "link", "bid", "loan", "club"
}

SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "verify", "update", "banking", "secure", "account",
    "confirm", "password", "credential", "wallet", "recover", "authenticate"
}


class URLAnalyzer(BaseAnalyzer):
    """Analyzes URLs and HTML anchor structure for deceitful patterns."""

    def __init__(self, weight: float = 1.3):
        super().__init__(name="url_analyzer", weight=weight)

    def analyze(self, email: EmailMessage) -> SignalScore:
        reasons: List[str] = []
        urls = email.urls

        if not urls:
            return SignalScore(
                analyzer_name=self.name,
                score=0.0,
                weight=self.weight,
                confidence=0.5,
                reasons=["No URLs present in message"],
                metadata={"url_count": 0},
            )

        max_url_risk = 0.0
        cumulative_score = 0.0
        meta: Dict[str, Any] = {
            "url_count": len(urls),
            "mismatch_count": 0,
            "ip_count": 0,
            "punycode_count": 0,
            "shortener_count": 0,
            "open_redirect_count": 0,
        }

        unique_domains: Set[str] = set()

        for u in urls:
            url_risk = u.risk_score
            parsed = urlparse(u.original_url)
            domain = u.domain.lower()
            if domain:
                unique_domains.add(domain)

            # Check individual URL reasons already flagged during extraction
            for r in u.reasons:
                if r not in reasons:
                    reasons.append(r)

            if u.href_mismatch:
                meta["mismatch_count"] += 1
                url_risk = max(url_risk, 0.90)

            if u.is_ip_address:
                meta["ip_count"] += 1
                url_risk = max(url_risk, 0.80)

            if u.punycode_domain:
                meta["punycode_count"] += 1
                url_risk = max(url_risk, 0.85)

            if u.is_shortener:
                meta["shortener_count"] += 1
                url_risk = max(url_risk, 0.50)

            # Check suspicious TLD
            tld = domain.split(".")[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                url_risk = max(url_risk, 0.65)
                reasons.append(f"High-risk top-level domain '.{tld}' on '{domain}'")

            # Check open redirect parameters
            query_dict = parse_qs(parsed.query)
            for param in ["url", "redirect", "next", "link", "dest", "target", "r"]:
                if param in query_dict:
                    val = query_dict[param][0]
                    if val.startswith("http://") or val.startswith("https://"):
                        meta["open_redirect_count"] += 1
                        url_risk = max(url_risk, 0.75)
                        reasons.append(f"Potential open-redirect chain via parameter '{param}={val[:40]}...'")

            # Check suspicious keywords in path or subdomain
            path_lower = parsed.path.lower()
            for kw in SUSPICIOUS_PATH_KEYWORDS:
                if kw in path_lower or kw in domain:
                    # If on non-standard or multiple subdomains
                    subdomain_parts = domain.split(".")
                    if len(subdomain_parts) >= 3 and kw in subdomain_parts[0]:
                        url_risk = max(url_risk, 0.70)
                        reasons.append(f"Subdomain impersonating sensitive term '{kw}' in '{domain}'")

            max_url_risk = max(max_url_risk, url_risk)
            cumulative_score += url_risk

        # Aggregate final score: heavily driven by the most dangerous single URL
        final_score = max_url_risk
        if len(urls) > 3 and max_url_risk > 0.4:
            final_score = min(1.0, final_score + 0.1)

        meta["unique_domain_count"] = len(unique_domains)
        final_score = max(0.0, min(1.0, final_score))

        return SignalScore(
            analyzer_name=self.name,
            score=round(final_score, 4),
            weight=self.weight,
            confidence=0.95,
            reasons=reasons,
            metadata=meta,
        )


url_analyzer = URLAnalyzer()

