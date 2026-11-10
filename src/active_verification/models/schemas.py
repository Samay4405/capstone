"""Core data schemas and Pydantic models for Active Verification."""

from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class IngestionSource(str, Enum):
    GMAIL = "gmail"
    IMAP = "imap"
    FILE_UPLOAD = "file_upload"
    FORWARDING = "forwarding"
    EVAL = "eval"


class DecisionPolicy(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"


class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class EmailAuthResults(BaseModel):
    spf: AuthStatus = AuthStatus.NONE
    spf_details: Optional[str] = None
    dkim: AuthStatus = AuthStatus.NONE
    dkim_details: Optional[str] = None
    dmarc: AuthStatus = AuthStatus.NONE
    dmarc_details: Optional[str] = None
    raw_header: Optional[str] = None


class ReceivedHop(BaseModel):
    by: Optional[str] = None
    from_server: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[float] = None


class EmailHeader(BaseModel):
    from_raw: str = ""
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    to: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    subject: str = ""
    date: Optional[str] = None
    message_id: Optional[str] = None
    auth_results: EmailAuthResults = Field(default_factory=EmailAuthResults)
    received_hops: List[ReceivedHop] = Field(default_factory=list)


class ExtractedURL(BaseModel):
    original_url: str
    display_text: str = ""
    domain: str = ""
    punycode_domain: Optional[str] = None
    is_ip_address: bool = False
    is_shortener: bool = False
    is_lookalike: bool = False
    lookalike_target: Optional[str] = None
    href_mismatch: bool = False
    has_hidden_text: bool = False
    risk_score: float = 0.0
    reasons: List[str] = Field(default_factory=list)


class EmailAttachment(BaseModel):
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    extension: str = ""
    is_executable: bool = False
    has_macros: bool = False
    is_archive: bool = False
    is_double_extension: bool = False
    risk_score: float = 0.0
    risk_reasons: List[str] = Field(default_factory=list)


class EmailMessage(BaseModel):
    id: str
    source: IngestionSource = IngestionSource.FILE_UPLOAD
    raw_sha256: str
    headers: EmailHeader = Field(default_factory=EmailHeader)
    body_plain: str = ""
    body_html: str = ""
    urls: List[ExtractedURL] = Field(default_factory=list)
    attachments: List[EmailAttachment] = Field(default_factory=list)
    raw_size_bytes: int = 0
    received_at: Optional[str] = None


class SignalScore(BaseModel):
    analyzer_name: str
    score: float = Field(..., ge=0.0, le=1.0, description="Normalized risk score 0.0=benign, 1.0=phishing")
    weight: float = 1.0
    confidence: float = 1.0
    reasons: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: float = 0.0


class VerificationTurn(BaseModel):
    turn_index: int
    role: str  # "synthetic_persona" or "simulated_adversary"
    message: str
    timestamp: str
    red_flags_detected: List[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    engaged: bool = False
    persona_name: Optional[str] = None
    turns: List[VerificationTurn] = Field(default_factory=list)
    adversary_tactics_observed: List[str] = Field(default_factory=list)
    deception_score: float = 0.0
    sandbox_verified_safe: bool = True
    summary: str = ""


class AnalysisResult(BaseModel):
    message_id: str
    decision: DecisionPolicy
    risk_score: float = Field(..., ge=0.0, le=1.0)
    calibrated_score: float = Field(..., ge=0.0, le=1.0)
    target_fpr: float = 0.01
    latency_ms: float = 0.0
    fast_path_used: bool = False
    signals: Dict[str, SignalScore] = Field(default_factory=dict)
    why_explanation: List[str] = Field(default_factory=list)
    verdict_headline: str = ""
    verdict_category: str = ""
    what_does_it_say: str = ""
    why_is_it_fishy: str = ""
    recommended_action: str = ""
    feature_attributions: Dict[str, float] = Field(default_factory=dict)
    active_verification: Optional[VerificationResult] = None
    redacted_preview: Optional[str] = None
    timestamp: Optional[str] = None

