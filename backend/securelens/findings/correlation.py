"""Finding correlation: one issue reported by several scanners becomes one finding.

Rules (all explainable, recorded in ``finding.correlation``):

* Code findings merge only when they share the file, the vulnerability class
  and a location within two lines. Different classes never merge, and two
  findings of the same class elsewhere in the file stay separate.
* Secret findings merge on file + line.
* Dependency findings merge on ecosystem + package + version + advisory
  (including advisory aliases such as a CVE shared by two IDs).

The merged finding keeps every evidence item and every source scanner.
Confidence rises one level when independent scanners corroborate each other.
"""

from __future__ import annotations

from securelens.enums import CONFIDENCE_ORDER, SEVERITY_ORDER, Confidence, Exploitability, SourceKind
from securelens.findings.model import Evidence, Finding

_EXPLOIT_ORDER = {Exploitability.PROVEN_DATAFLOW: 3, Exploitability.LIKELY: 2, Exploitability.POSSIBLE: 1,
                  Exploitability.THEORETICAL: 0}
_BUMP = {Confidence.LOW: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.HIGH, Confidence.HIGH: Confidence.HIGH,
         Confidence.CONFIRMED: Confidence.CONFIRMED}
LINE_WINDOW = 2


def _rank(f: Finding) -> tuple:
    has_flow = any(e.kind == "dataflow" and e.data.get("sources") for e in f.evidence)
    ai_class = f.engine.value == "AISEC"
    return (has_flow, ai_class, f.scanners[0].startswith("securelens"), CONFIDENCE_ORDER[f.confidence],
            SEVERITY_ORDER[f.severity])


def _family(f: Finding) -> str:
    """LLM-output and tool-input findings are the same issue as the sink they reach."""
    return str(f.correlation.get("base_class") or f.vuln_class)


def _dep_keys(f: Finding) -> set[str]:
    data = next((e.data for e in f.evidence if e.kind == "dependency"), {})
    base = f"{data.get('ecosystem')}|{str(data.get('name', '')).lower()}|{data.get('version')}"
    ids = {data.get("advisory_id", f.rule_id), *data.get("aliases", [])}
    return {f"{base}|{i}" for i in ids if i}


def correlate(findings: list[Finding]) -> list[Finding]:
    groups: list[list[Finding]] = []
    code_index: dict[tuple[str, str], list[int]] = {}
    secret_index: dict[tuple[str, int | None], int] = {}
    dep_index: dict[str, int] = {}

    for finding in findings:
        loc = finding.location
        kind = finding.source_kind
        target: int | None = None
        if kind == SourceKind.DEPENDENCY:
            keys = _dep_keys(finding)
            target = next((dep_index[k] for k in keys if k in dep_index), None)
            if target is None:
                target = len(groups)
                groups.append([finding])
            else:
                groups[target].append(finding)
            for k in keys:
                dep_index.setdefault(k, target)
            continue
        if kind == SourceKind.SECRET or finding.vuln_class == "hardcoded_secret":
            key = (loc.path if loc else "", loc.start_line if loc else None)
            target = secret_index.get(key)
            if target is None:
                secret_index[key] = len(groups)
                groups.append([finding])
            else:
                groups[target].append(finding)
            continue
        if loc is None or kind == SourceKind.LLM_TEST:
            groups.append([finding])
            continue
        key = (loc.path, _family(finding))
        for idx in code_index.get(key, []):
            anchor = groups[idx][0].location
            if not (anchor and anchor.start_line is not None and loc.start_line is not None):
                continue
            same_scanner = bool(set(groups[idx][0].scanners) & set(finding.scanners))
            # Different tools may anchor one issue on neighbouring lines; one tool's
            # reports on different lines are different issues.
            window = 0 if same_scanner else LINE_WINDOW
            if abs(anchor.start_line - loc.start_line) <= window:
                target = idx
                break
        if target is None:
            code_index.setdefault(key, []).append(len(groups))
            groups.append([finding])
        else:
            groups[target].append(finding)

    return [_merge(group) for group in groups]


def _merge(group: list[Finding]) -> Finding:
    if len(group) == 1:
        only = group[0]
        only.correlation = {**only.correlation, "merged": 1, "scanners": list(only.scanners)}
        return only
    ordered = sorted(group, key=_rank, reverse=True)
    primary = ordered[0].model_copy(deep=True)
    scanners = list(dict.fromkeys(s for f in ordered for s in f.scanners))
    evidence: list[Evidence] = []
    seen = set()
    for f in ordered:
        for e in f.evidence:
            key = (e.kind, e.source, e.summary, e.location.start_line if e.location else None)
            if key not in seen:
                seen.add(key)
                evidence.append(e)
    independent = {s.split(":")[0] for s in scanners}
    confidence = max((f.confidence for f in ordered), key=lambda c: CONFIDENCE_ORDER[c])
    credible = [f for f in ordered if CONFIDENCE_ORDER[f.confidence] >= CONFIDENCE_ORDER[Confidence.MEDIUM]]
    severity = max((f.severity for f in credible or ordered), key=lambda s_: SEVERITY_ORDER[s_])
    exploitability = max((f.exploitability for f in ordered), key=lambda e: _EXPLOIT_ORDER[e])
    reason = (f"Merged {len(group)} reports of {primary.vuln_class} at "
              f"{primary.location.path if primary.location else 'the same component'}"
              f"{':' + str(primary.location.start_line) if primary.location and primary.location.start_line else ''} "
              f"from {', '.join(scanners)}.")
    # Agreement only adds certainty when it is about more than the same syntactic
    # pattern: at least one report must carry evidence beyond "the pattern exists".
    if (len(independent) >= 2 and confidence not in (Confidence.HIGH, Confidence.CONFIRMED)
            and _EXPLOIT_ORDER[exploitability] >= _EXPLOIT_ORDER[Exploitability.LIKELY]):
        confidence = _BUMP[confidence]
        reason += " Confidence raised one level because independent scanners agree."
    if severity != primary.severity:
        reason += f" Severity {severity.value} taken from the most severe credible report."
    primary.confidence = confidence
    primary.severity = severity
    primary.exploitability = exploitability
    primary.scanners = scanners
    primary.cwe = list(dict.fromkeys(c for f in ordered for c in f.cwe))
    primary.references = list(dict.fromkeys(r for f in ordered for r in f.references))
    primary.tags = list(dict.fromkeys(t for f in ordered for t in f.tags))
    primary.evidence = evidence
    primary.evidence.append(Evidence(kind="correlation", source="securelens-correlation", summary=reason, data={
        "reports": [{"scanner": ",".join(f.scanners), "rule_id": f.rule_id, "severity": f.severity.value,
                     "confidence": f.confidence.value,
                     "line": f.location.start_line if f.location else None} for f in ordered]}))
    primary.correlation = {"merged": len(group), "scanners": scanners, "reason": reason,
                           "rules": [f.rule_id for f in ordered]}
    return primary
