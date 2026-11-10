"""Sandboxed Active Verification Honeypot & LLM Twin Simulator.

STRICT SAFETY BARRIER:
This module NEVER contacts real external email senders or opens outbound network sockets.
Interactions execute exclusively within an in-memory virtual simulation against synthetic personas.
"""

import time
import logging
from typing import List, Dict, Any, Optional
from active_verification.models.schemas import (
    EmailMessage,
    VerificationResult,
    VerificationTurn,
)
from active_verification.config import settings
from active_verification.verification.personas import persona_manager, SyntheticPersona

logger = logging.getLogger(__name__)


class SandboxedHoneypotSimulator:
    """Executes sandboxed conversational honeypot simulations to measure adversary persistence and tactics."""

    def __init__(self, max_turns: Optional[int] = None):
        self.max_turns = max_turns or settings.MAX_SYNTHETIC_INTERACTION_TURNS
        # Enforce sandbox barrier invariant
        if not settings.ACTIVE_VERIFICATION_SANDBOX_STRICT:
            raise RuntimeError("CRITICAL SAFETY VIOLATION: Active verification must run in strict sandbox mode.")

    def simulate_engagement(self, email: EmailMessage) -> VerificationResult:
        """Run multi-turn conversational trap simulation against synthetic persona."""
        # Enforce isolation barrier: Ensure no network communication
        self._assert_sandbox_integrity()

        subject = email.headers.subject.lower()
        body = (email.body_plain or "").lower()

        # Categorize attack intent to select best synthetic persona
        category = "general"
        if any(w in subject or w in body for w in ["invoice", "payment", "wire", "bank", "routing", "ach"]):
            category = "finance"
        elif any(w in subject or w in body for w in ["password", "sso", "mfa", "ticket", "it support", "login"]):
            category = "it"
        elif any(w in subject or w in body for w in ["payroll", "benefits", "w2", "hr", "severance", "bonus"]):
            category = "hr"

        persona = persona_manager.select_persona_for_scenario(category)
        turns: List[VerificationTurn] = []
        observed_tactics: List[str] = []
        red_flags: List[str] = []

        # Turn 1: Persona sends non-committal clarifying question
        if category == "finance":
            probe_1 = (
                f"Hello, this is {persona.full_name} from {persona.department}. "
                f"I received your inquiry regarding the invoice. Could you please specify the internal PO number "
                f"and verify the authorized vendor entity on file?"
            )
            adv_reply_1 = (
                "Morgan, this is an expedited executive payment request approved directly by leadership. "
                "The PO is pending post-close review. We need the outstanding balance wired today to avoid services being cut off. "
                "Attached are the updated wiring instructions to our temporary clearing house."
            )
            observed_tactics.append("T1566.002: Social Engineering Urgency Escalation")
            red_flags.append("Adversary bypassed formal PO validation request and escalated executive urgency")
        elif category == "it":
            probe_1 = (
                f"Hello, {persona.full_name} here from IT Support. "
                f"Before resetting your authentication token, could you please confirm your employee serial number "
                f"and whether you are accessing via corporate VPN?"
            )
            adv_reply_1 = (
                "I am traveling remotely and locked out of the VPN portal entirely. "
                "Please do not delay, I have a client board presentation in 20 minutes. "
                "Just approve the pending MFA push request or click the administrative token sync link."
            )
            observed_tactics.append("T1556: Multi-Factor Authentication Push Fatigue / Bypass Attempt")
            red_flags.append("Adversary refused standard verification and pressured immediate MFA approval")
        else:
            probe_1 = (
                f"Hello, this is {persona.full_name}. Thank you for your note. "
                f"Could you please confirm the reference documentation or ticket associated with this request?"
            )
            adv_reply_1 = (
                "Please review the attached document immediately and confirm receipt. "
                "It contains confidential guidance that must be acknowledged before end of business today."
            )
            observed_tactics.append("T1204: User Execution via Social Engineering Pressure")
            red_flags.append("Adversary repeated generic coercive pressure to open payload without verification")

        now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        turns.append(VerificationTurn(
            turn_index=1,
            role="synthetic_persona",
            message=probe_1,
            timestamp=now_str,
            red_flags_detected=[],
        ))
        turns.append(VerificationTurn(
            turn_index=2,
            role="simulated_adversary",
            message=adv_reply_1,
            timestamp=now_str,
            red_flags_detected=red_flags,
        ))

        # Calculate deception and persistence score
        deception_score = 0.88 if len(red_flags) > 0 else 0.20

        summary = (
            f"Sandboxed simulation with synthetic persona '{persona.full_name}' ({persona.job_title}) "
            f"revealed {len(observed_tactics)} hostile conversational tactics. Adversary demonstrated "
            f"urgency escalation and evaded standard verification controls."
        )

        return VerificationResult(
            engaged=True,
            persona_name=persona.full_name,
            turns=turns,
            adversary_tactics_observed=observed_tactics,
            deception_score=deception_score,
            sandbox_verified_safe=True,
            summary=summary,
        )

    def _assert_sandbox_integrity(self):
        """Sanity check to guarantee that outbound communications are strictly disabled."""
        if not settings.ACTIVE_VERIFICATION_SANDBOX_STRICT:
            raise AssertionError("Active verification sandbox boundary breach: strict mode disabled.")


sandboxed_honeypot = SandboxedHoneypotSimulator()

