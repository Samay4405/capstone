"""Domain intelligence analyzer: WHOIS age heuristics, typo-squatting, and entropy."""

import math
import re
from typing import List, Dict, Any, Set
from active_verification.models.schemas import EmailMessage, SignalScore
from active_verification.analyzers.base import BaseAnalyzer

PROTECTED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "docusign", "dropbox",
    "facebook", "instagram", "linkedin", "twitter", "adobe", "walmart",
    "target", "fedex", "ups", "dhl", "usps", "irs"
]

ESTABLISHED_BENIGN_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "chase.com", "netflix.com", "linkedin.com", "github.com",
    "dropbox.com", "docusign.com", "wellsfargo.com", "bankofamerica.com",
    "cloudflare.com", "adobe.com", "salesforce.com", "zoom.us", "slack.com"
}


def compute_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein edit distance."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class DomainAnalyzer(BaseAnalyzer):
    """Analyzes domain characteristics: typo-squatting, entropy, and brand lookalikes."""

    def __init__(self, weight: float = 1.1):
        super().__init__(name="domain_analyzer", weight=weight)
        # In-memory mock/passive WHOIS database for realistic evaluations
        self._mock_whois_cache: Dict[str, Dict[str, Any]] = {
            "paypa1-update.com": {"age_days": 4, "has_mx": True, "reputation": "malicious"},
            "secure-appleid-login.xyz": {"age_days": 2, "has_mx": False, "reputation": "malicious"},
            "microsoft-auth-portal.com": {"age_days": 8, "has_mx": True, "reputation": "malicious"},
            "google.com": {"age_days": 10000, "has_mx": True, "reputation": "benign"},
            "microsoft.com": {"age_days": 11000, "has_mx": True, "reputation": "benign"},
            "apple.com": {"age_days": 12000, "has_mx": True, "reputation": "benign"},
            "paypal.com": {"age_days": 9000, "has_mx": True, "reputation": "benign"},
        }

    def analyze(self, email: EmailMessage) -> SignalScore:
        reasons: List[str] = []
        score = 0.0
        meta: Dict[str, Any] = {"inspected_domains": []}

        # Collect domains to inspect: From domain + all unique URL domains
        domains_to_check: Set[str] = set()
        if email.headers.from_domain:
            domains_to_check.add(email.headers.from_domain.lower())

        for u in email.urls:
            if u.domain:
                domains_to_check.add(u.domain.lower())

        max_domain_risk = 0.0

        for dom in domains_to_check:
            dom_risk = 0.0
            domain_info: Dict[str, Any] = {"domain": dom}

            # 1. Whitelisted well-known benign domains
            if dom in ESTABLISHED_BENIGN_DOMAINS or any(dom.endswith("." + b) for b in ESTABLISHED_BENIGN_DOMAINS):
                domain_info["established"] = True
                meta["inspected_domains"].append(domain_info)
                continue

            # 2. Typo-squatting & brand lookalike checks
            # Extract root label (e.g., 'paypa1' from 'paypa1-update.com')
            label = dom.split(".")[0] if "." in dom else dom
            # Check for visual character substitution: 1 -> l, 0 -> o, vv -> w, rn -> m
            normalized_label = label.replace("1", "l").replace("0", "o").replace("vv", "w").replace("rn", "m")

            for brand in PROTECTED_BRANDS:
                # Direct substring inclusion with hyphen/modifier (e.g., paypal-verify, secure-microsoft)
                if brand in dom and not dom.endswith(f"{brand}.com"):
                    dom_risk = max(dom_risk, 0.85)
                    reasons.append(
                        f"Domain '{dom}' embeds protected brand '{brand}' with deceptive prefixes/suffixes"
                    )
                    domain_info["brand_embed"] = brand
                    break

                # Levenshtein distance typo-squatting check
                dist = levenshtein_distance(label, brand)
                norm_dist = levenshtein_distance(normalized_label, brand)

                if (dist == 1 or norm_dist == 0) and len(brand) >= 4:
                    dom_risk = max(dom_risk, 0.90)
                    reasons.append(
                        f"Domain label '{label}' is an adversarial typo-squat of brand '{brand}' (edit distance={dist})"
                    )
                    domain_info["typosquat_target"] = brand
                    break
                elif dist == 2 and len(brand) >= 6:
                    dom_risk = max(dom_risk, 0.70)
                    reasons.append(
                        f"Domain label '{label}' closely resembles brand '{brand}' (edit distance={dist})"
                    )
                    domain_info["lookalike_target"] = brand
                    break

            # 3. High Shannon entropy (Domain Generation Algorithm / random hex)
            entropy = compute_shannon_entropy(label)
            domain_info["entropy"] = round(entropy, 2)
            if entropy > 3.8 and len(label) > 10:
                dom_risk = max(dom_risk, 0.65)
                reasons.append(f"High character entropy ({entropy:.2f}) on '{dom}' suggests algorithmic generation")

            # 4. Passive WHOIS age lookup (using cache/heuristics)
            cached = self._mock_whois_cache.get(dom)
            if cached:
                age = cached.get("age_days", 365)
                domain_info["age_days"] = age
                if age < 14:
                    dom_risk = max(dom_risk, 0.85)
                    reasons.append(f"Newly registered domain '{dom}' (created {age} days ago)")
                elif age < 30:
                    dom_risk = max(dom_risk, 0.60)
                    reasons.append(f"Young domain '{dom}' (age {age} days)")

            max_domain_risk = max(max_domain_risk, dom_risk)
            meta["inspected_domains"].append(domain_info)

        final_score = max(0.0, min(1.0, max_domain_risk))
        meta["max_domain_risk"] = round(final_score, 4)

        return SignalScore(
            analyzer_name=self.name,
            score=round(final_score, 4),
            weight=self.weight,
            confidence=0.85 if domains_to_check else 0.50,
            reasons=reasons,
            metadata=meta,
        )


domain_analyzer = DomainAnalyzer()

