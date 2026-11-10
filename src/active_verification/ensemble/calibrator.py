"""Calibrator for converting raw ensemble outputs into well-calibrated probabilities."""

import numpy as np
from typing import Tuple, Optional
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression


class ProbabilityCalibrator:
    """Implements Platt scaling and Isotonic regression for risk score calibration."""

    def __init__(self, method: str = "platt"):
        self.method = method
        self._platt_model: Optional[LogisticRegression] = None
        self._isotonic_model: Optional[IsotonicRegression] = None
        self._is_fitted = False

        # Default pre-calibrated logistic parameters for cold start
        # logit(p) = w0 + w1 * raw_score
        self._default_w0 = -2.8
        self._default_w1 = 5.2

    def fit(self, scores: np.ndarray, labels: np.ndarray) -> "ProbabilityCalibrator":
        """Fit calibration curve on out-of-fold validation scores and true labels."""
        scores = np.asarray(scores).reshape(-1, 1)
        labels = np.asarray(labels).ravel()

        if self.method == "isotonic":
            self._isotonic_model = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
            self._isotonic_model.fit(scores.ravel(), labels)
        else:
            self._platt_model = LogisticRegression(solver="lbfgs", C=1.0)
            self._platt_model.fit(scores, labels)

        self._is_fitted = True
        return self

    def predict_proba(self, scores: np.ndarray) -> np.ndarray:
        """Calibrate raw score(s) to posterior probability P(phishing=1 | score)."""
        arr = np.asarray(scores, dtype=np.float64)
        is_scalar = arr.ndim == 0

        if is_scalar:
            arr = arr.reshape(1, 1)
        elif arr.ndim == 1:
            arr = arr.reshape(-1, 1)

        if self._is_fitted:
            if self.method == "isotonic" and self._isotonic_model is not None:
                calibrated = self._isotonic_model.predict(arr.ravel())
            elif self._platt_model is not None:
                calibrated = self._platt_model.predict_proba(arr)[:, 1]
            else:
                calibrated = self._sigmoid(self._default_w0 + self._default_w1 * arr.ravel())
        else:
            calibrated = self._sigmoid(self._default_w0 + self._default_w1 * arr.ravel())

        calibrated = np.clip(calibrated, 0.001, 0.999)
        return float(calibrated[0]) if is_scalar else calibrated

    def _sigmoid(self, z: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(z, -15.0, 15.0)))

    def calculate_brier_score(self, y_true: np.ndarray, y_prob: np.ndarray) -> float:
        """Compute Brier calibration error: mean((y_prob - y_true)^2)."""
        return float(np.mean((np.asarray(y_prob) - np.asarray(y_true)) ** 2))


calibrator = ProbabilityCalibrator()

