"""Privacy-by-default redactor: hashes PII and redacts sensitive email contents."""

import re
import hashlib
from typing import Tuple, List, Dict, Any
from active_verification.config import settings


class PrivacyRedactor:
    """Provides PII redaction and salted cryptographic pseudonymization."""

    def __init__(self, salt: str = ""):
        self.salt = salt or settings.PRIVACY_SALT

        # Compiled regex patterns for PII detection
        self._email_re = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self._phone_re = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
        self._ssn_re = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
        self._cc_re = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
        self._ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def hash_identifier(self, identifier: str) -> str:
        """Create a deterministic salted SHA-256 hash for an identifier."""
        if not identifier:
            return ""
        norm = identifier.strip().lower()
        h = hashlib.sha256(f"{norm}:{self.salt}".encode("utf-8")).hexdigest()
        return f"HASH_{h[:16]}"

    def redact_text(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Redact sensitive patterns in text, returning redacted string and count of replacements."""
        if not text:
            return "", {}

        counts: Dict[str, int] = {
            "emails": 0,
            "phones": 0,
            "ssns": 0,
            "credit_cards": 0,
        }

        # Redact SSNs
        def replace_ssn(match: re.Match) -> str:
            counts["ssns"] += 1
            return "[REDACTED_SSN]"

        text = self._ssn_re.sub(replace_ssn, text)

        # Redact Credit Cards
        def replace_cc(match: re.Match) -> str:
            counts["credit_cards"] += 1
            return "[REDACTED_CREDIT_CARD]"

        text = self._cc_re.sub(replace_cc, text)

        # Redact Phones
        def replace_phone(match: re.Match) -> str:
            counts["phones"] += 1
            return "[REDACTED_PHONE]"

        text = self._phone_re.sub(replace_phone, text)

        # Pseudonymize Emails with salted hash
        def replace_email(match: re.Match) -> str:
            counts["emails"] += 1
            raw_email = match.group(0)
            return f"[{self.hash_identifier(raw_email)}]"

        text = self._email_re.sub(replace_email, text)

        return text, counts

    def generate_safe_preview(self, text: str, max_chars: int = 200) -> str:
        """Generate a privacy-safe truncated snippet of the text."""
        redacted, _ = self.redact_text(text)
        cleaned = " ".join(redacted.split())
        if len(cleaned) <= max_chars:
            return cleaned
        return cleaned[:max_chars] + "..."


redactor = PrivacyRedactor()

