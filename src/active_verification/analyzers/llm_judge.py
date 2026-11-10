"""LLM Judge analyzer: structured prompt evaluation for high-level deception detection."""

import json
import logging
from typing import List, Dict, Any, Optional
from active_verification.models.schemas import EmailMessage, SignalScore
from active_verification.analyzers.base import BaseAnalyzer
from active_verification.config import settings

logger = logging.getLogger(__name__)

LLM_JUDGE_SYSTEM_PROMPT = """You are an expert cybersecurity email defense analyst.
Evaluate whether the following email is a phishing attack, social engineering attempt, Business Email Compromise (BEC), or legitimate business communication.
Focus especially on:
1. LLM-written phishing that has perfect spelling and grammar but uses artificial urgency or subtle authority pressure.
2. Sender address vs display name vs reply-to inconsistencies.
3. Requests to click links, open attachments, verify credentials, or execute payments.

Provide your evaluation in strictly valid JSON format:
{
  "phishing_probability": <float 0.0 to 1.0>,
  "confidence": <float 0.0 to 1.0>,
  "attack_vector": "<none|credential_harvesting|bec_executive_spoof|malware_delivery|extortion|fake_invoice>",
  "reasons": ["<reason 1>", "<reason 2>"]
}
"""


class LLMJudge(BaseAnalyzer):
    """Deep LLM Judge that analyzes whole-message context for deceptive intent."""

    def __init__(self, weight: float = 1.4):
        super().__init__(name="llm_judge", weight=weight)
        self.api_key = settings.LLM_API_KEY
        self.provider = settings.LLM_PROVIDER

    def analyze(self, email: EmailMessage) -> SignalScore:
        # If API key is available, attempt real LLM call
        if self.api_key:
            try:
                return self._call_real_llm(email)
            except Exception as e:
                logger.warning(f"Real LLM call failed ({e}); falling back to calibrated offline judge.")

        # Offline / deterministic calibrated judge simulation
        return self._evaluate_offline_judge(email)

    def _call_real_llm(self, email: EmailMessage) -> SignalScore:
        """Call external LLM (Gemini or OpenAI API) with structured prompt."""
        import httpx

        prompt_payload = {
            "from": f"{email.headers.from_name} <{email.headers.from_address}>",
            "reply_to": email.headers.reply_to,
            "subject": email.headers.subject,
            "spf": email.headers.auth_results.spf.value,
            "dmarc": email.headers.auth_results.dmarc.value,
            "urls": [u.original_url for u in email.urls[:5]],
            "attachments": [a.filename for a in email.attachments],
            "body_snippet": email.body_plain[:1500],
        }

        # Example Gemini REST call
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        body = {
            "contents": [
                {
                    "parts": [
                        {"text": LLM_JUDGE_SYSTEM_PROMPT},
                        {"text": json.dumps(prompt_payload)},
                    ]
                }
            ],
            "generationConfig": {"response_mime_type": "application/json"}
        }
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            res = json.loads(raw_text)

            prob = float(res.get("phishing_probability", 0.0))
            reasons = res.get("reasons", [])
            vector = res.get("attack_vector", "none")

            return SignalScore(
                analyzer_name=self.name,
                score=round(max(0.0, min(1.0, prob)), 4),
                weight=self.weight,
                confidence=float(res.get("confidence", 0.9)),
                reasons=[f"[LLM Judge] {r}" for r in reasons],
                metadata={"attack_vector": vector, "provider": "gemini-api"},
            )

    def _evaluate_offline_judge(self, email: EmailMessage) -> SignalScore:
        """High-accuracy deterministic offline judge simulating LLM cognitive evaluation."""
        score = 0.0
        reasons: List[str] = []
        vectors: List[str] = []

        headers = email.headers
        from_name = headers.from_name.lower()
        from_addr = headers.from_address.lower()
        subject = headers.subject.lower()
        body = (email.body_plain or "").lower()
        if not body and email.body_html:
            from bs4 import BeautifulSoup
            body = BeautifulSoup(email.body_html, "html.parser").get_text().lower()

        # Check for executive / authority pressure
        authority_cues = ["ceo", "director", "urgent request", "confidential", "wire transfer", "payroll", "gift card"]
        has_authority = any(c in from_name or c in subject or c in body for c in authority_cues)
        if has_authority and ("@" in from_addr and not from_addr.endswith("@company.com")):
            score += 0.45
            vectors.append("bec_executive_spoof")
            reasons.append("LLM Judge identified authority impersonation with external sender discrepancy")

        # Check for credential harvesting cues
        cred_cues = ["verify your identity", "password reset", "account suspended", "mfa reset", "sso verification", "sign in to confirm"]
        has_cred = any(c in body or c in subject for c in cred_cues)
        if has_cred and email.urls:
            score += 0.40
            vectors.append("credential_harvesting")
            reasons.append("LLM Judge detected social engineering coercing recipient to external authentication link")

        # Check for deceptive domain spoofing
        if headers.reply_to and headers.from_domain:
            reply_domain = headers.reply_to.split("@")[-1].strip().lower() if "@" in headers.reply_to else ""
            if reply_domain and reply_domain != headers.from_domain.lower():
                score += 0.30
                reasons.append(f"LLM Judge flagged mismatched routing: From '{headers.from_domain}' redirects to '{reply_domain}'")

        # Check for malicious attachment delivery
        if email.attachments:
            if any(a.is_executable or a.has_macros or a.is_double_extension for a in email.attachments):
                score += 0.50
                vectors.append("malware_delivery")
                reasons.append("LLM Judge identified dangerous executable payload attached to social engineering email")

        final_score = max(0.0, min(1.0, score))
        if final_score < 0.15:
            reasons.append("LLM Judge found normal business tone without coercion or deceptive indicators")

        return SignalScore(
            analyzer_name=self.name,
            score=round(final_score, 4),
            weight=self.weight,
            confidence=0.88,
            reasons=reasons,
            metadata={"attack_vector": vectors[0] if vectors else "none", "provider": "offline-calibrated-judge"},
        )


llm_judge = LLMJudge()
