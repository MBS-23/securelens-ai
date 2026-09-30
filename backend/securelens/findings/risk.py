"""The SecureLens Risk Index (SRI) — a transparent, configurable risk calculation.

This is SecureLens's own methodology, not an industry-standard score such as
CVSS. Severity, confidence and risk are kept separate:

    finding_risk = S(severity) × C(confidence) × E(exploitability)
                   × X(exposure) × B(business criticality, only if supplied)
                   × V(verification) × T(status)

    SRI = 100 × (1 − e^(−Σ finding_risk / K))

The exponential form keeps the index between 0 and 100, rising quickly with
the first serious findings and saturating as open risk accumulates. K (the
saturation constant) and every weight can be changed per organization; the API
returns the full breakdown so every number can be traced.
"""

from __future__ import annotations

import copy
import math
from dataclasses import dataclass, field
from typing import Any

DEFAULT_WEIGHTS: dict[str, Any] = {
    "severity": {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.5, "INFO": 0.0},
    "confidence": {"CONFIRMED": 1.0, "HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3},
    "exploitability": {"PROVEN_DATAFLOW": 1.0, "LIKELY": 0.85, "POSSIBLE": 0.65, "THEORETICAL": 0.45},
    "exposure": {"INTERNET_FACING": 1.25, "INTERNAL": 0.9, "UNKNOWN": 1.0},
    "business_criticality": {"CRITICAL": 1.3, "HIGH": 1.15, "MEDIUM": 1.0, "LOW": 0.85},
    "verification": {"CONFIRMED": 1.0, "DETECTED": 1.0, "AI_SUGGESTED": 0.5, "FALSE_POSITIVE": 0.0,
                     "NOT_TESTED": 0.0},
    "status": {"OPEN": 1.0, "IN_PROGRESS": 1.0, "REOPENED": 1.0, "RESOLVED": 0.0, "FALSE_POSITIVE": 0.0,
               "ACCEPTED_RISK": 0.0},
    "saturation": 25.0,
}

METHODOLOGY = (
    "SecureLens Risk Index (SRI) = 100 × (1 − e^(−Σ risk / K)). Each open finding contributes "
    "severity × confidence × exploitability × exposure × business criticality (only when supplied) × "
    "verification × status. Resolved, false-positive and accepted-risk findings contribute 0. "
    "This is a SecureLens-specific prioritisation aid, not CVSS and not a measure of overall security."
)


def merge_weights(overrides: dict[str, Any] | None) -> dict[str, Any]:
    weights = copy.deepcopy(DEFAULT_WEIGHTS)
    for key, value in (overrides or {}).items():
        if key not in weights:
            continue
        if isinstance(weights[key], dict) and isinstance(value, dict):
            for sub, number in value.items():
                if sub in weights[key] and isinstance(number, int | float) and 0 <= number <= 100:
                    weights[key][sub] = float(number)
        elif key == "saturation" and isinstance(value, int | float) and 1 <= value <= 10_000:
            weights[key] = float(value)
    return weights


@dataclass
class RiskInput:
    id: str
    severity: str
    confidence: str
    exploitability: str
    verification: str = "DETECTED"
    status: str = "OPEN"


@dataclass
class RiskBreakdown:
    index: float
    total: float
    accepted_risk_total: float
    weights: dict[str, Any]
    exposure: str
    business_criticality: str | None
    contributions: list[dict[str, Any]] = field(default_factory=list)
    methodology: str = METHODOLOGY

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "total": round(self.total, 3),
            "accepted_risk_total": round(self.accepted_risk_total, 3),
            "exposure": self.exposure,
            "business_criticality": self.business_criticality,
            "weights": self.weights,
            "contributions": self.contributions,
            "methodology": self.methodology,
        }


def finding_risk(item: RiskInput, weights: dict[str, Any], exposure: str, criticality: str | None,
                 ignore_status: bool = False) -> tuple[float, dict[str, float]]:
    factors = {
        "severity": weights["severity"].get(item.severity, 0.0),
        "confidence": weights["confidence"].get(item.confidence, 0.0),
        "exploitability": weights["exploitability"].get(item.exploitability, 0.65),
        "exposure": weights["exposure"].get(exposure, 1.0),
        "business_criticality": weights["business_criticality"].get(criticality, 1.0) if criticality else 1.0,
        "verification": weights["verification"].get(item.verification, 1.0),
        "status": 1.0 if ignore_status else weights["status"].get(item.status, 1.0),
    }
    value = 1.0
    for f in factors.values():
        value *= f
    return value, factors


def compute(items: list[RiskInput], *, exposure: str = "UNKNOWN", business_criticality: str | None = None,
            overrides: dict[str, Any] | None = None) -> RiskBreakdown:
    weights = merge_weights(overrides)
    total = 0.0
    accepted = 0.0
    contributions = []
    for item in items:
        value, factors = finding_risk(item, weights, exposure, business_criticality)
        if item.status == "ACCEPTED_RISK":
            accepted += finding_risk(item, weights, exposure, business_criticality, ignore_status=True)[0]
        total += value
        if value > 0:
            contributions.append({"id": item.id, "risk": round(value, 3), "factors": factors})
    contributions.sort(key=lambda c: c["risk"], reverse=True)
    index = round(100.0 * (1.0 - math.exp(-total / weights["saturation"])), 1) if total > 0 else 0.0
    return RiskBreakdown(index=index, total=total, accepted_risk_total=accepted, weights=weights, exposure=exposure,
                         business_criticality=business_criticality, contributions=contributions[:200])
