"""Abstract base class for all signal analyzers."""

import time
from abc import ABC, abstractmethod
from typing import Optional
from active_verification.models.schemas import EmailMessage, SignalScore


class BaseAnalyzer(ABC):
    """Abstract Base Analyzer contract."""

    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight

    @abstractmethod
    def analyze(self, email: EmailMessage) -> SignalScore:
        """Analyze an email message and return a SignalScore."""
        pass

    def run(self, email: EmailMessage) -> SignalScore:
        """Execute analysis with latency tracking."""
        start = time.perf_counter()
        try:
            signal = self.analyze(email)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            signal.execution_time_ms = round(elapsed_ms, 2)
            signal.weight = self.weight
            return signal
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return SignalScore(
                analyzer_name=self.name,
                score=0.0,
                weight=self.weight,
                confidence=0.0,
                reasons=[f"Analyzer error: {str(e)}"],
                metadata={"error": str(e)},
                execution_time_ms=round(elapsed_ms, 2),
            )

