"""Attachment analyzer: evaluates file extensions, macro presence, and executable risks."""

from typing import List, Dict, Any
from active_verification.models.schemas import EmailMessage, SignalScore
from active_verification.analyzers.base import BaseAnalyzer


class AttachmentAnalyzer(BaseAnalyzer):
    """Analyzes message attachments for malware, macros, and deceptive extensions."""

    def __init__(self, weight: float = 1.4):
        super().__init__(name="attachment_analyzer", weight=weight)

    def analyze(self, email: EmailMessage) -> SignalScore:
        attachments = email.attachments
        if not attachments:
            return SignalScore(
                analyzer_name=self.name,
                score=0.0,
                weight=self.weight,
                confidence=0.5,
                reasons=["No attachments present"],
                metadata={"attachment_count": 0},
            )

        max_risk = 0.0
        reasons: List[str] = []
        meta: Dict[str, Any] = {
            "attachment_count": len(attachments),
            "files": []
        }

        for att in attachments:
            att_info = {
                "filename": att.filename,
                "size_bytes": att.size_bytes,
                "extension": att.extension,
                "is_executable": att.is_executable,
                "has_macros": att.has_macros,
                "is_archive": att.is_archive,
                "is_double_extension": att.is_double_extension,
                "risk_score": att.risk_score,
            }
            meta["files"].append(att_info)

            for r in att.risk_reasons:
                if r not in reasons:
                    reasons.append(r)

            if att.risk_score > max_risk:
                max_risk = att.risk_score

        # Normalize score
        final_score = max(0.0, min(1.0, max_risk))

        return SignalScore(
            analyzer_name=self.name,
            score=round(final_score, 4),
            weight=self.weight,
            confidence=0.95,
            reasons=reasons,
            metadata=meta,
        )


attachment_analyzer = AttachmentAnalyzer()

