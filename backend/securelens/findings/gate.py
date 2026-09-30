"""Security gate evaluation for CI/CD and the dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field

from securelens.enums import CONFIDENCE_ORDER, Confidence, Severity

ACTIVE = {"OPEN", "IN_PROGRESS", "REOPENED"}


@dataclass
class GatePolicy:
    fail_on: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    min_confidence: str = "MEDIUM"
    include_ai_suggested: bool = False
    fail_on_regression: bool = True
    max_findings: int | None = None

    @classmethod
    def from_dict(cls, data: dict | None) -> GatePolicy:
        data = data or {}
        return cls(
            fail_on=[str(s).upper() for s in data.get("fail_on", ["CRITICAL", "HIGH"])],
            min_confidence=str(data.get("min_confidence", "MEDIUM")).upper(),
            include_ai_suggested=bool(data.get("include_ai_suggested", False)),
            fail_on_regression=bool(data.get("fail_on_regression", True)),
            max_findings=data.get("max_findings"),
        )

    def as_dict(self) -> dict:
        return {"fail_on": self.fail_on, "min_confidence": self.min_confidence,
                "include_ai_suggested": self.include_ai_suggested, "fail_on_regression": self.fail_on_regression,
                "max_findings": self.max_findings}


@dataclass
class GateItem:
    id: str
    title: str
    severity: str
    confidence: str
    verification: str = "DETECTED"
    status: str = "OPEN"
    location: str | None = None


@dataclass
class GateResult:
    status: str  # PASS | FAIL
    reasons: list[str]
    blocking: list[GateItem]
    counts: dict[str, int]
    policy: GatePolicy

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "reasons": self.reasons,
            "blocking": [{"id": b.id, "title": b.title, "severity": b.severity, "confidence": b.confidence,
                          "location": b.location} for b in self.blocking[:50]],
            "counts": self.counts,
            "policy": self.policy.as_dict(),
        }


def evaluate(items: list[GateItem], policy: GatePolicy, *, regressions: int = 0, new_blocking: int | None = None) -> GateResult:
    min_conf = CONFIDENCE_ORDER[Confidence(policy.min_confidence)]
    counts = {s.value: 0 for s in Severity}
    blocking: list[GateItem] = []
    active = [i for i in items if i.status in ACTIVE and i.verification != "FALSE_POSITIVE"]
    for item in active:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        if item.verification == "AI_SUGGESTED" and not policy.include_ai_suggested:
            continue
        if item.severity in policy.fail_on and CONFIDENCE_ORDER[Confidence(item.confidence)] >= min_conf:
            blocking.append(item)
    reasons: list[str] = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = sum(1 for b in blocking if b.severity == severity)
        if n:
            reasons.append(f"{n} {severity} finding{'s' if n != 1 else ''} at confidence ≥ {policy.min_confidence}")
    if policy.fail_on_regression and regressions:
        reasons.append(f"{regressions} regression{'s' if regressions != 1 else ''}: previously resolved finding(s) reappeared")
    if new_blocking:
        reasons.append(f"{new_blocking} new blocking finding{'s' if new_blocking != 1 else ''} introduced since the baseline")
    if policy.max_findings is not None and len(active) > policy.max_findings:
        reasons.append(f"{len(active)} open findings exceed the limit of {policy.max_findings}")
    return GateResult(status="FAIL" if reasons else "PASS", reasons=reasons, blocking=blocking, counts=counts,
                      policy=policy)
