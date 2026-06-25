"""Lightweight Random-Forest-style classifier.

This module ships with a self-contained, deterministic weighted-rule
ensemble that mirrors the *shape* of a scikit-learn RandomForestClassifier
(`predict_proba`, `predict`) — so the rest of the codebase remains
fully compatible if the production team later swaps in a trained
sklearn model loaded from `.joblib`.
"""
from __future__ import annotations
from typing import Sequence


class PhishingRandomForest:
    """Heuristic ensemble producing realistic threat probabilities."""

    FEATURE_ORDER: Sequence[str] = (
        "url_length", "host_length", "path_length", "subdomain_count",
        "entropy", "uses_ip", "uses_https", "has_at_symbol", "has_port",
        "is_shortener", "suspicious_keywords", "special_char_count",
        "digit_count",
    )

    WEIGHTS = {
        "url_length":          0.10,
        "host_length":         0.05,
        "path_length":         0.05,
        "subdomain_count":     0.12,
        "entropy":             0.15,
        "uses_ip":             0.18,
        "uses_https":         -0.10,
        "has_at_symbol":       0.10,
        "has_port":            0.05,
        "is_shortener":        0.08,
        "suspicious_keywords": 0.14,
        "special_char_count":  0.06,
        "digit_count":         0.04,
    }

    # ------------------------------------------------------------------
    @staticmethod
    def _normalise(name: str, value) -> float:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if name == "url_length":
            return min(value / 120.0, 1.0)
        if name == "host_length":
            return min(value / 60.0, 1.0)
        if name == "path_length":
            return min(value / 100.0, 1.0)
        if name == "entropy":
            return min(value / 5.5, 1.0)
        if name == "subdomain_count":
            return min(value / 5.0, 1.0)
        if name == "suspicious_keywords":
            return min(value / 4.0, 1.0)
        if name == "special_char_count":
            return min(value / 15.0, 1.0)
        if name == "digit_count":
            return min(value / 20.0, 1.0)
        return float(value)

    # ------------------------------------------------------------------
    def predict_proba(self, features: dict) -> float:
        """Return phishing probability in 0.0 – 1.0."""
        score = 0.0
        for name in self.FEATURE_ORDER:
            v = features.get(name, 0)
            score += self.WEIGHTS[name] * self._normalise(name, v)
        # squash into [0, 1] using a piecewise logistic
        score = max(-1.0, min(1.5, score))
        prob = 1.0 / (1.0 + 2.71828 ** (-3.0 * (score - 0.45)))
        return round(prob, 4)

    # ------------------------------------------------------------------
    def predict(self, features: dict) -> tuple[str, float]:
        """Return (verdict, threat_percentage)."""
        prob = self.predict_proba(features)
        pct = round(prob * 100.0, 2)
        if pct >= 70.0:
            verdict = "PHISHING"
        elif pct >= 40.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        return verdict, pct


# Singleton instance reused across requests
classifier = PhishingRandomForest()
