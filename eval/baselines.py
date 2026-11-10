"""Baseline implementations: SpamAssassin rule simulator, keyword heuristic, and active pipeline."""

import re
import numpy as np
from typing import Dict, Any
from active_verification.models.schemas import EmailMessage, AuthStatus
from active_verification.ensemble.engine import ensemble_engine


class SpamAssassinBaseline:
    """Emulates an open SpamAssassin-style static rule accumulation engine."""

    def __init__(self, threshold: float = 5.0):
        self.threshold = threshold

    def predict_score(self, email: EmailMessage) -> float:
        points = 0.0

        subject = email.headers.subject
        body = email.body_plain or ""
        combined = f"{subject}\n{body}"

        # 1. Subject checks
        if subject.isupper() and len(subject) > 8:
            points += 1.8  # SUBJ_ALL_CAPS
        if "!" in subject or "!!" in subject:
            points += 1.2  # SUBJ_EXCESS_EXCLAMATION

        # 2. Authentication rules
        auth = email.headers.auth_results
        if auth.spf == AuthStatus.FAIL:
            points += 2.0  # SPF_FAIL
        elif auth.spf == AuthStatus.PASS:
            points -= 1.5  # SPF_PASS

        if auth.dkim == AuthStatus.FAIL:
            points += 1.5  # DKIM_FAIL
        elif auth.dkim == AuthStatus.PASS:
            points -= 1.5  # DKIM_PASS

        if auth.dmarc == AuthStatus.FAIL:
            points += 2.5  # DMARC_FAIL
        elif auth.dmarc == AuthStatus.PASS:
            points -= 2.0  # DMARC_PASS

        # 3. Traditional spam lexical patterns
        if re.search(r'\b(?:lottery|winner|million\s+usd|claim\s+funds)\b', combined, re.I):
            points += 3.5  # LOTTERY_SPAM
        if re.search(r'\b(?:bellow|acount|unautorized)\b', combined, re.I):
            points += 2.2  # FREQ_TYPOS

        # 4. URL checks
        for u in email.urls:
            if u.is_ip_address:
                points += 2.5  # URI_RAW_IP
            if u.href_mismatch:
                points += 3.0  # URI_LINK_TEXT_MISMATCH

        # Convert accumulated points to sigmoid [0.0, 1.0]
        prob = 1.0 / (1.0 + np.exp(-0.8 * (points - 2.5)))
        return float(np.clip(prob, 0.001, 0.999))


class KeywordHeuristicBaseline:
    """Simple keyword matching baseline."""

    KEYWORDS = ["urgent", "verify", "suspended", "password", "bank", "wire", "immediately", "account", "lock"]

    def predict_score(self, email: EmailMessage) -> float:
        text = f"{email.headers.subject} {email.body_plain}".lower()
        hits = sum(1 for kw in self.KEYWORDS if kw in text)
        prob = 1.0 / (1.0 + np.exp(-(hits - 2.0)))
        return float(np.clip(prob, 0.01, 0.99))


spam_assassin_baseline = SpamAssassinBaseline()
keyword_baseline = KeywordHeuristicBaseline()

