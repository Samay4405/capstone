"""Content analyzer: DeBERTa-v3 semantic scoring and cognitive attack vector detection."""

import re
import numpy as np
from typing import List, Dict, Any, Optional
from active_verification.models.schemas import EmailMessage, SignalScore
from active_verification.analyzers.base import BaseAnalyzer
from active_verification.config import settings

# Semantic vectors for cognitive exploitation patterns
URGENCY_PATTERNS = [
    r"\b(?:immediately|urgent|within\s+24\s+hours|action\s+required|suspended|deadline|terminated|lock-?out)\b",
    r"\b(?:failure\s+to\s+respond|account\s+will\s+be\s+closed|immediate\s+attention|prior\s+to)\b",
]

CREDENTIAL_HARVEST_PATTERNS = [
    r"\b(?:verify\s+your\s+account|confirm\s+your\s+identity|log(?:in|\s+in)\s+to\s+restore)\b",
    r"\b(?:update\s+billing|reactivate|security\s+alert|password\s+has\s+expired)\b",
    r"\b(?:two-factor|mfa\s+request|sso|single-sign-on|sign-in\s+attempt|credential\s+sync|certificate\s+migration)\b",
]

FINANCIAL_WIRE_PATTERNS = [
    r"\b(?:wire\s+transfer|gift\s+card|invoice\s+attached|direct\s+deposit|payroll\s+update)\b",
    r"\b(?:bitcoin|cryptocurrency|wallet\s+address|overdue\s+payment|ach\s+transfer|escrow\s+deposit|routing\s+number)\b",
]

EXECUTIVE_IMPERSONATION_PATTERNS = [
    r"\b(?:confidential|are\s+you\s+at\s+your\s+desk|in\s+a\s+meeting|board\s+meeting)\b",
    r"\b(?:do\s+not\s+call\s+me|handle\s+this\s+discreetly|urgent\s+task\s+from\s+ceo|cannot\s+step\s+out|strictly\s+confidential)\b",
]


class ContentAnalyzer(BaseAnalyzer):
    """Analyzes email body text using DeBERTa semantic embeddings and cognitive attack indicators."""

    def __init__(self, weight: float = 1.35):
        super().__init__(name="content_analyzer", weight=weight)
        self.model_name = settings.DEBERTA_MODEL_NAME
        self._tokenizer = None
        self._model = None
        self._model_loaded = False

    def _init_transformer_if_available(self):
        """Optionally load local DeBERTa weights if locally present."""
        if self._model_loaded:
            return
        if not settings.ENABLE_LOCAL_TRANSFORMER:
            return

        import os
        # Only attempt to load if model directory or cached path exists locally
        if not os.path.exists(self.model_name) and not os.environ.get("TRANSFORMERS_OFFLINE"):
            # Avoid long 30s HuggingFace timeout scanning when files don't exist
            return

        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name, local_files_only=True)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_name, local_files_only=True)
            self._model.eval()
            self._model_loaded = True
        except Exception:
            self._model_loaded = False

    def analyze(self, email: EmailMessage) -> SignalScore:
        text = email.body_plain or ""
        if not text and email.body_html:
            from bs4 import BeautifulSoup
            text = BeautifulSoup(email.body_html, "html.parser").get_text()

        text_lower = text.lower()
        reasons: List[str] = []
        meta: Dict[str, Any] = {
            "urgency_hits": 0,
            "credential_hits": 0,
            "financial_hits": 0,
            "executive_hits": 0,
            "word_count": len(text.split()),
        }

        if len(text.strip()) == 0:
            return SignalScore(
                analyzer_name=self.name,
                score=0.20,
                weight=self.weight,
                confidence=0.40,
                reasons=["Empty or non-textual message body"],
                metadata=meta,
            )

        # 1. Cognitive Attack Vector Pattern Extraction
        urgency_score = 0.0
        for pat in URGENCY_PATTERNS:
            matches = re.findall(pat, text_lower)
            if matches:
                urgency_score += min(0.35, len(matches) * 0.15)
                meta["urgency_hits"] += len(matches)

        cred_score = 0.0
        for pat in CREDENTIAL_HARVEST_PATTERNS:
            matches = re.findall(pat, text_lower)
            if matches:
                cred_score += min(0.40, len(matches) * 0.20)
                meta["credential_hits"] += len(matches)

        fin_score = 0.0
        for pat in FINANCIAL_WIRE_PATTERNS:
            matches = re.findall(pat, text_lower)
            if matches:
                fin_score += min(0.45, len(matches) * 0.20)
                meta["financial_hits"] += len(matches)

        exec_score = 0.0
        for pat in EXECUTIVE_IMPERSONATION_PATTERNS:
            matches = re.findall(pat, text_lower)
            if matches:
                exec_score += min(0.50, len(matches) * 0.25)
                meta["executive_hits"] += len(matches)

        if meta["urgency_hits"] > 0:
            reasons.append(f"High urgency and pressure cues detected ({meta['urgency_hits']} trigger phrases)")
        if meta["credential_hits"] > 0:
            reasons.append(f"Call-to-action for credential verification or account recovery detected ({meta['credential_hits']} triggers)")
        if meta["financial_hits"] > 0:
            reasons.append(f"Financial transfer, invoice, or cryptocurrency solicitations detected ({meta['financial_hits']} triggers)")
        if meta["executive_hits"] > 0:
            reasons.append("Executive authority impersonation or confidentiality coercion cues detected")

        # 2. DeBERTa Transformer / Semantic Score Calculation
        transformer_score = None
        self._init_transformer_if_available()

        if self._model_loaded and self._model is not None and self._tokenizer is not None:
            try:
                import torch
                inputs = self._tokenizer(text[:512], return_tensors="pt", truncation=True, padding=True)
                with torch.no_grad():
                    logits = self._model(**inputs).logits
                    probs = torch.softmax(logits, dim=-1).squeeze().tolist()
                    transformer_score = probs[1] if isinstance(probs, list) and len(probs) > 1 else float(probs)
                    meta["transformer_model"] = self.model_name
            except Exception:
                pass

        # Calibrated semantic feature synthesis
        # LLM-written phishing often lacks typos but contains strong structural intent (urgency + action + link/attachment)
        raw_intent_score = 0.0
        if meta["urgency_hits"] > 0:
            raw_intent_score += min(0.40, meta["urgency_hits"] * 0.12)
        if meta["credential_hits"] > 0:
            raw_intent_score += min(0.50, meta["credential_hits"] * 0.20)
        if meta["financial_hits"] > 0:
            raw_intent_score += min(0.55, meta["financial_hits"] * 0.25)
        if meta["executive_hits"] > 0:
            raw_intent_score += min(0.55, meta["executive_hits"] * 0.25)

        # Check for presence of URL, attachment, or financial transaction request alongside intent
        has_action_vector = bool(email.urls or email.attachments or meta["financial_hits"] > 0)
        if has_action_vector and raw_intent_score > 0.10:
            raw_intent_score += 0.25
            reasons.append("Cognitive pressure vector combined with actionable link, attachment, or transaction request")

        if transformer_score is not None:
            final_score = 0.6 * transformer_score + 0.4 * raw_intent_score
            meta["transformer_score"] = round(transformer_score, 4)
        else:
            final_score = raw_intent_score

        final_score = max(0.0, min(1.0, final_score))
        meta["raw_intent_score"] = round(raw_intent_score, 4)

        return SignalScore(
            analyzer_name=self.name,
            score=round(final_score, 4),
            weight=self.weight,
            confidence=0.90,
            reasons=reasons,
            metadata=meta,
        )


content_analyzer = ContentAnalyzer()
