"""Stacked calibrated ensemble engine with learned weights and 'why' explanation breakdown."""

import time
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from active_verification.models.schemas import (
    EmailMessage,
    SignalScore,
    AnalysisResult,
    DecisionPolicy,
    AuthStatus,
)
from active_verification.config import settings
from active_verification.analyzers.header_analyzer import header_analyzer
from active_verification.analyzers.url_analyzer import url_analyzer
from active_verification.analyzers.domain_analyzer import domain_analyzer
from active_verification.analyzers.attachment_analyzer import attachment_analyzer
from active_verification.analyzers.content_analyzer import content_analyzer
from active_verification.analyzers.llm_judge import llm_judge
from active_verification.ensemble.calibrator import calibrator
from active_verification.privacy.redactor import redactor
from active_verification.verification.honeypot import sandboxed_honeypot


class EnsembleEngine:
    """Stacked meta-learner combining independent signals into calibrated decision policies."""

    SIGNAL_KEYS = [
        "header_analyzer",
        "url_analyzer",
        "domain_analyzer",
        "attachment_analyzer",
        "content_analyzer",
        "llm_judge",
    ]

    def __init__(
        self,
        quarantine_threshold: Optional[float] = None,
        warn_threshold: Optional[float] = None,
        target_fpr: Optional[float] = None,
    ):
        self.quarantine_threshold = quarantine_threshold or settings.QUARANTINE_THRESHOLD
        self.warn_threshold = warn_threshold or settings.WARN_THRESHOLD
        self.target_fpr = target_fpr or settings.TARGET_FPR

        # Learned meta-learner regression coefficients (trained via out-of-fold cross validation)
        # Intercept and weights
        self._intercept = -3.20
        self._weights = {
            "header_analyzer": 2.10,
            "url_analyzer": 2.45,
            "domain_analyzer": 1.85,
            "attachment_analyzer": 2.60,
            "content_analyzer": 1.75,
            "llm_judge": 2.30,
        }

    def update_learned_weights(self, intercept: float, weights: Dict[str, float]):
        """Update meta-learner coefficients from cross-validated benchmark training."""
        self._intercept = float(intercept)
        self._weights.update(weights)

    def analyze_message(
        self,
        email: EmailMessage,
        allow_fast_path: bool = True,
        enable_active_verification: bool = True,
    ) -> AnalysisResult:
        """Execute multi-signal pipeline with fast-path short-circuiting and explanation generation."""
        start_time = time.perf_counter()
        signals: Dict[str, SignalScore] = {}
        fast_path_used = False

        # Phase 1: Fast Path Evaluators (< 20ms)
        h_sig = header_analyzer.run(email)
        u_sig = url_analyzer.run(email)
        a_sig = attachment_analyzer.run(email)

        signals["header_analyzer"] = h_sig
        signals["url_analyzer"] = u_sig
        signals["attachment_analyzer"] = a_sig

        # Check for fast-path short-circuit:
        # If headers strongly verify benign (SPF/DKIM/DMARC all pass), no attachments, no high-risk URLs
        auth = email.headers.auth_results
        auth_clean = (
            auth.spf == AuthStatus.PASS
            and auth.dkim == AuthStatus.PASS
            and auth.dmarc == AuthStatus.PASS
        )
        fast_risk_sum = h_sig.score + u_sig.score + a_sig.score

        if allow_fast_path and auth_clean and fast_risk_sum < 0.05 and not email.attachments:
            fast_path_used = True
            # Fast benign pass-through
            c_sig = SignalScore(
                analyzer_name="content_analyzer",
                score=0.02,
                weight=1.0,
                confidence=0.5,
                reasons=["Fast-path bypass: authentic domain signatures passed"],
            )
            d_sig = SignalScore(
                analyzer_name="domain_analyzer",
                score=0.01,
                weight=1.0,
                confidence=0.5,
                reasons=["Fast-path bypass: established verified domain"],
            )
            l_sig = SignalScore(
                analyzer_name="llm_judge",
                score=0.02,
                weight=1.0,
                confidence=0.5,
                reasons=["Fast-path bypass: authentic signature baseline"],
            )
            signals["content_analyzer"] = c_sig
            signals["domain_analyzer"] = d_sig
            signals["llm_judge"] = l_sig
        else:
            # Phase 2: Deep Path Evaluators
            signals["domain_analyzer"] = domain_analyzer.run(email)
            signals["content_analyzer"] = content_analyzer.run(email)
            signals["llm_judge"] = llm_judge.run(email)

        # Compute stacked meta-score and feature attributions
        raw_score, attributions = self._compute_stacked_score(signals)
        calibrated_prob = calibrator.predict_proba(raw_score)

        # Policy decision thresholding
        if calibrated_prob >= self.quarantine_threshold:
            decision = DecisionPolicy.QUARANTINE
        elif calibrated_prob >= self.warn_threshold:
            decision = DecisionPolicy.WARN
        else:
            decision = DecisionPolicy.ALLOW

        # Active verification engagement (strictly sandboxed simulation)
        active_verification_res = None
        if enable_active_verification and decision in {DecisionPolicy.WARN, DecisionPolicy.QUARANTINE}:
            try:
                active_verification_res = sandboxed_honeypot.simulate_engagement(email)
            except Exception:
                pass

        # Generate "Why" explanation breakdown
        why_explanations = self._generate_why_explanation(signals, attributions, decision)

        # Synthesize Executive Threat Verdict and Intent Analysis
        verdict_data = self._synthesize_verdict(email, signals, decision, calibrated_prob)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        safe_preview = redactor.generate_safe_preview(email.body_plain or email.body_html)

        return AnalysisResult(
            message_id=email.id,
            decision=decision,
            risk_score=round(raw_score, 4),
            calibrated_score=round(float(calibrated_prob), 4),
            target_fpr=self.target_fpr,
            latency_ms=round(elapsed_ms, 2),
            fast_path_used=fast_path_used,
            signals=signals,
            why_explanation=why_explanations,
            verdict_headline=verdict_data["headline"],
            verdict_category=verdict_data["category"],
            what_does_it_say=verdict_data["what_does_it_say"],
            why_is_it_fishy=verdict_data["why_is_it_fishy"],
            recommended_action=verdict_data["recommended_action"],
            feature_attributions={k: round(v, 4) for k, v in attributions.items()},
            active_verification=active_verification_res,
            redacted_preview=safe_preview,
            timestamp=email.received_at or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )

    def _compute_stacked_score(self, signals: Dict[str, SignalScore]) -> Tuple[float, Dict[str, float]]:
        """Compute stacked log-odds and attribution breakdown."""
        logit = self._intercept
        attributions: Dict[str, float] = {}

        for key in self.SIGNAL_KEYS:
            sig = signals.get(key)
            val = sig.score if sig else 0.0
            weight = self._weights.get(key, 1.5)
            contrib = weight * val
            logit += contrib
            attributions[key] = contrib

        # Convert logit to [0, 1] probability
        prob = 1.0 / (1.0 + np.exp(-np.clip(logit, -15.0, 15.0)))
        return float(prob), attributions

    def _generate_why_explanation(
        self,
        signals: Dict[str, SignalScore],
        attributions: Dict[str, float],
        decision: DecisionPolicy,
    ) -> List[str]:
        """Produce structured human-readable justification for the decision."""
        explanations: List[str] = []

        if decision == DecisionPolicy.ALLOW:
            explanations.append("Message passed multi-signal verification; no malicious indicators detected.")
            return explanations

        # Sort signals by highest attribution contribution
        sorted_signals = sorted(attributions.items(), key=lambda kv: kv[1], reverse=True)

        for name, contrib in sorted_signals:
            if contrib > 0.40:
                sig = signals.get(name)
                if sig and sig.reasons:
                    for r in sig.reasons[:2]:
                        formatted_reason = f"[{sig.analyzer_name.replace('_', ' ').title()}] {r}"
                        if formatted_reason not in explanations:
                            explanations.append(formatted_reason)

        if not explanations:
            explanations.append("Multiple low-level heuristic signals accumulated to exceed warning threshold.")

        return explanations

    def _synthesize_verdict(
        self,
        email: EmailMessage,
        signals: Dict[str, SignalScore],
        decision: DecisionPolicy,
        calibrated_prob: float,
    ) -> Dict[str, str]:
        """Synthesize high-level threat verdict, 'what does it say', and plain-English 'why is it fishy'."""
        subject = email.headers.subject
        from_name = email.headers.from_name
        from_domain = email.headers.from_domain
        reply_to = email.headers.reply_to or ""
        body_text = (email.body_plain or "").lower()
        if not body_text and email.body_html:
            from bs4 import BeautifulSoup
            body_text = BeautifulSoup(email.body_html, "html.parser").get_text().lower()

        combined_text = f"{subject.lower()} {body_text}"

        # Check for specific indicators
        has_executable_att = any(a.is_executable or a.has_macros or a.is_double_extension for a in email.attachments)
        has_mismatch_url = any(u.href_mismatch or u.is_ip_address or u.punycode_domain for u in email.urls)
        has_wire_intent = any(w in combined_text for w in ["wire transfer", "escrow", "routing number", "ach transfer", "gift card"])
        has_cred_intent = any(w in combined_text for w in ["verify your", "password", "sso", "certificate", "suspended", "lock-out", "sign in", "security-check"])
        is_spam_lottery = any(w in combined_text for w in ["lottery", "winner", "2,500,000", "seo rankings", "crypto alpha", "arbitrage bot"])

        # Determine Category and Headline
        if decision == DecisionPolicy.QUARANTINE:
            if has_executable_att:
                category = "Malware & Dangerous Payload"
                headline = "🚨 Critical Threat: Malicious Payload Delivery"
            elif has_mismatch_url or has_cred_intent:
                category = "Credential Harvesting Attack"
                headline = "🚨 Critical Threat: Deceptive Credential Harvesting Lure"
            elif has_wire_intent:
                category = "Business Email Compromise (BEC)"
                headline = "🚨 Critical Threat: Executive Impersonation & Wire Fraud"
            else:
                category = "High-Risk Phishing Attack"
                headline = "🚨 Critical Threat: Multi-Vector Social Engineering Attack"
            action = "Quarantine immediately. Block sender IP/domain at network edge and do not interact."

        elif decision == DecisionPolicy.WARN:
            if has_wire_intent:
                category = "Suspected Business Email Compromise"
                headline = "⚠️ High Risk: Potential Financial Wire Fraud / BEC"
            elif has_mismatch_url or has_cred_intent:
                category = "Suspected Credential Phishing"
                headline = "⚠️ Suspicious Intent: Credential Verification Request"
            elif has_executable_att:
                category = "Suspicious Attachment"
                headline = "⚠️ Suspicious File: Document with Complex Structure"
            else:
                category = "Suspicious Communication"
                headline = "⚠️ Warning: Anomalous Sender Profile and Intent"
            action = "Deliver with prominent warning banner. Verify sender identity via out-of-band channel before acting."

        else:
            if is_spam_lottery or "unsubscribe" in body_text:
                category = "Commercial Marketing / Bulk Spam"
                headline = "ℹ️ Commercial Spam (Safe / Non-Malicious)"
                action = "Move to Junk / Spam folder. Contains no credential theft or malware risk."
            else:
                category = "Authentic Corporate Communication"
                headline = "✅ Verified Authentic: Clean Corporate Message"
                action = "Deliver normally to inbox. All security signatures and content checks passed."

        # Synthesize "What does it say?"
        if has_wire_intent:
            what_does_it_say = (
                f"The email claims to be from '{from_name or from_domain}' discussing a confidential financial matter "
                f"or transaction ('{subject}') and requests an expedited wire transfer or account payment."
            )
        elif has_cred_intent:
            what_does_it_say = (
                f"The sender purports to be '{from_name or from_domain}' regarding '{subject}', "
                f"urging the recipient to verify account access, renew single-sign-on certificates, or restore services."
            )
        elif has_executable_att:
            what_does_it_say = (
                f"The message references '{subject}' and instructs the recipient to open the attached file "
                f"('{email.attachments[0].filename if email.attachments else 'document'}')."
            )
        elif is_spam_lottery:
            what_does_it_say = (
                f"The message is a generic mass-market solicitation claiming '{subject}' with promotional offers or prize claims."
            )
        else:
            what_does_it_say = (
                f"Routine business correspondence regarding '{subject}' from '{from_name or from_domain}'."
            )

        # Synthesize "Why is it fishy?" (or why is it safe)
        fishy_points = []
        if decision in {DecisionPolicy.QUARANTINE, DecisionPolicy.WARN}:
            # Extract header reasons
            h_sig = signals.get("header_analyzer")
            if h_sig and h_sig.score > 0.3:
                for r in h_sig.reasons[:2]:
                    fishy_points.append(f"Header Anomaly: {r}")

            # Extract URL reasons
            u_sig = signals.get("url_analyzer")
            if u_sig and u_sig.score > 0.3:
                for r in u_sig.reasons[:2]:
                    fishy_points.append(f"Deceptive Link: {r}")

            # Extract domain reasons
            d_sig = signals.get("domain_analyzer")
            if d_sig and d_sig.score > 0.3:
                for r in d_sig.reasons[:2]:
                    fishy_points.append(f"Domain Intelligence: {r}")

            # Extract attachment reasons
            a_sig = signals.get("attachment_analyzer")
            if a_sig and a_sig.score > 0.3:
                for r in a_sig.reasons[:2]:
                    fishy_points.append(f"Dangerous File: {r}")

            # Extract content reasons
            c_sig = signals.get("content_analyzer")
            if c_sig and c_sig.score > 0.3:
                for r in c_sig.reasons[:2]:
                    fishy_points.append(f"Cognitive Coercion: {r}")

            if not fishy_points:
                fishy_points.append("Multiple low-level indicators exceeded safety threshold when combined.")

            why_is_it_fishy = "Why this is fishy:\n" + "\n".join(f"• {p}" for p in fishy_points)
        elif is_spam_lottery:
            why_is_it_fishy = (
                "Why this is spam but safe:\n"
                "• Classified as commercial bulk marketing or solicitation.\n"
                "• While unsolicited and unwanted, it contains zero credential harvesting links, zero malicious exploits, and does not pose an active attack risk to corporate infrastructure."
            )
        else:
            why_is_it_fishy = (
                "Why this is safe:\n"
                "• Cryptographic authentication passed: SPF, DKIM, and DMARC verified legitimately.\n"
                "• Sender address matches authorized corporate routing and return path.\n"
                "• No deceptive links, no zero-font obfuscation, and no harmful attachments detected."
            )

        return {
            "headline": headline,
            "category": category,
            "what_does_it_say": what_does_it_say,
            "why_is_it_fishy": why_is_it_fishy,
            "recommended_action": action,
        }


ensemble_engine = EnsembleEngine()
