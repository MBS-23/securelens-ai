"""SARIF 2.1.0 output for GitHub code scanning, GitLab and IDEs.

Severity is exported both as the SARIF ``level`` and as the
``security-severity`` rule property that GitHub uses to rank alerts. Data-flow
evidence becomes a ``codeFlow`` so viewers can step from the source to the
sink. Snippets were redacted by the engine before they reach this module.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from securelens.enums import SEVERITY_ORDER, Severity
from securelens.findings import catalog
from securelens.findings.model import Finding, ScanResult
from securelens.reporting.context import ASSURANCE_STATEMENT
from securelens.version import TOOL_NAME, TOOL_URI, __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# GitHub maps >= 9.0 to critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}
_PRECISION = {"CONFIRMED": "very-high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _uri(path: str) -> str:
    return quote(path.replace("\\", "/").lstrip("/"), safe="/")


def _camel(key: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[_\-\s]+", key) if part)


def _region(start: int | None, end: int | None, col: int | None, snippet: str | None) -> dict[str, Any] | None:
    if not start:
        return None
    region: dict[str, Any] = {"startLine": start}
    if end and end >= start:
        region["endLine"] = end
    if col:
        region["startColumn"] = col
    if snippet:
        region["snippet"] = {"text": snippet}
    return region


def _physical(path: str, start: int | None, end: int | None = None, col: int | None = None,
              snippet: str | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {"artifactLocation": {"uri": _uri(path), "uriBaseId": "%SRCROOT%"}}
    region = _region(start, end, col, snippet)
    if region:
        location["region"] = region
    return location


def _rule(f: Finding) -> dict[str, Any]:
    vc = catalog.get(f.vuln_class) if catalog.known(f.vuln_class) else None
    name = vc.name if vc else f.category
    help_text = f.recommendation or (vc.recommendation if vc else "")
    return {
        "id": f.rule_id,
        "name": _camel(f.vuln_class),
        "shortDescription": {"text": name},
        "fullDescription": {"text": (vc.description if vc else f.description)[:1000] or name},
        "help": {"text": help_text or name, "markdown": f"**{name}**\n\n{help_text}"},
        **({"helpUri": f.references[0]} if f.references and f.references[0].startswith("https://") else {}),
        "defaultConfiguration": {"level": _LEVEL[f.severity.value]},
        "properties": {
            "tags": ["security", *f.cwe, *(o.split(" ")[0] for o in f.owasp)],
            "security-severity": _SECURITY_SEVERITY[f.severity.value],
            "precision": _PRECISION[f.confidence.value],
            "problem.severity": {"error": "error", "warning": "warning", "note": "recommendation"}[
                _LEVEL[f.severity.value]],
        },
    }


def _code_flow(f: Finding) -> dict[str, Any] | None:
    flow = next((e for e in f.evidence if e.kind == "dataflow"), None)
    if flow is None:
        return None
    data = flow.data or {}
    locations: list[dict[str, Any]] = []
    for src in data.get("sources") or []:
        if src.get("path") and src.get("line"):
            locations.append({"location": {"physicalLocation": _physical(src["path"], src["line"],
                                                                         snippet=src.get("code") or None),
                                           "message": {"text": f"Source: {src.get('label', 'untrusted input')}"}}})
            break
    for step in data.get("steps") or []:
        if step.get("path") and step.get("line"):
            locations.append({"location": {"physicalLocation": _physical(step["path"], step["line"],
                                                                         snippet=step.get("code") or None),
                                           "message": {"text": step.get("note") or "data flows here"}}})
    if len(locations) < 2:
        return None
    return {"threadFlows": [{"locations": locations}]}


def _result(f: Finding, rule_index: int) -> dict[str, Any]:
    loc = f.location
    message = f.title
    summary = next((e.summary for e in f.evidence if e.summary), "")
    if summary and summary != f.title:
        message = f"{f.title}. {summary}"
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[f.severity.value],
        "message": {"text": message[:2000]},
        "partialFingerprints": {"securelens/v1": f.fingerprint},
        "properties": {
            "securelensId": f.public_id,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "exploitability": f.exploitability.value,
            "verification": f.verification.value,
            "vulnerabilityClass": f.vuln_class,
            "cwe": list(f.cwe),
            "owasp": list(f.owasp),
            "scanners": list(f.scanners),
        },
    }
    if loc is not None and loc.path:
        result["locations"] = [{"physicalLocation": _physical(loc.path, loc.start_line, loc.end_line,
                                                              loc.start_col, loc.snippet)}]
    flow = _code_flow(f)
    if flow:
        result["codeFlows"] = [flow]
    return result


def render(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    rule_order: list[str] = []
    worst: dict[str, Severity] = {}
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = _rule(f)
            rule_order.append(f.rule_id)
            worst[f.rule_id] = f.severity
        elif SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst[f.rule_id]]:
            # A rule's severity for ranking is the worst severity it reported in this run.
            worst[f.rule_id] = f.severity
            rules[f.rule_id]["properties"]["security-severity"] = _SECURITY_SEVERITY[f.severity.value]
            rules[f.rule_id]["defaultConfiguration"]["level"] = _LEVEL[f.severity.value]
    index = {rule_id: i for i, rule_id in enumerate(rule_order)}
    notifications = [{"level": "warning", "message": {"text": e[:1000]}} for e in result.errors[:100]]
    notifications += [{"level": "note", "message": {"text": f"{s.scanner} {s.status}: {s.detail}"[:1000]}}
                      for s in result.scanners if s.status != "ran" and s.detail]
    run: dict[str, Any] = {
        "tool": {"driver": {"name": TOOL_NAME, "version": (result.tool or {}).get("version", __version__),
                            "semanticVersion": __version__, "informationUri": TOOL_URI,
                            "rules": [rules[r] for r in rule_order]}},
        "automationDetails": {"id": f"securelens/{result.target}/"},
        "invocations": [{"executionSuccessful": True, "startTimeUtc": result.started_at,
                         **({"endTimeUtc": result.finished_at} if result.finished_at else {}),
                         "toolExecutionNotifications": notifications}],
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Root of the scanned source tree"}}},
        "results": [_result(f, index[f.rule_id]) for f in result.findings],
        "properties": {
            "gate": result.gate,
            "riskIndex": (result.risk or {}).get("index"),
            "riskMethodology": "SecureLens Risk Index; a SecureLens-specific prioritisation aid, not CVSS.",
            "statement": ASSURANCE_STATEMENT,
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
