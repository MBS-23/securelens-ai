"""Correlation, fingerprints, risk index, security gate and workspace safety."""

from __future__ import annotations

import os
from pathlib import Path

from securelens.enums import Confidence, Engine, Exploitability, Severity, SourceKind
from securelens.findings import fingerprint, risk
from securelens.findings.correlation import correlate
from securelens.findings.gate import GateItem, GatePolicy, evaluate
from securelens.findings.model import Evidence, Finding, Location
from securelens.scanners.base import ScanOptions
from securelens.scanners.engine import run_scan
from securelens.scanners.workspace import build_inventory


def make(line: int, scanner: str, vuln_class: str = "sql_injection", confidence: Confidence = Confidence.MEDIUM,
         severity: Severity = Severity.HIGH, snippet: str = "cursor.execute(q)",
         exploit: Exploitability = Exploitability.POSSIBLE) -> Finding:
    loc = Location(path="app/db.py", start_line=line, snippet=snippet, function="get")
    return Finding(rule_id=f"{scanner}:r", engine=Engine.APPSEC, source_kind=SourceKind.SAST, vuln_class=vuln_class,
                   title="t", category="c", severity=severity, confidence=confidence, exploitability=exploit,
                   location=loc, evidence=[Evidence(kind="pattern", source=scanner, summary=scanner, location=loc)],
                   scanners=[scanner])


def test_cross_scanner_findings_merge_with_all_evidence() -> None:
    merged = correlate([make(10, "securelens-sast", confidence=Confidence.HIGH, severity=Severity.CRITICAL,
                             exploit=Exploitability.PROVEN_DATAFLOW),
                        make(11, "bandit", confidence=Confidence.MEDIUM, severity=Severity.MEDIUM)])
    assert len(merged) == 1
    f = merged[0]
    assert f.scanners == ["securelens-sast", "bandit"]
    assert f.severity == Severity.CRITICAL
    assert {e.source for e in f.evidence} >= {"securelens-sast", "bandit", "securelens-correlation"}
    assert f.correlation["merged"] == 2 and "Merged 2 reports" in f.correlation["reason"]


def test_same_scanner_different_lines_stay_separate() -> None:
    assert len(correlate([make(10, "securelens-sast"), make(12, "securelens-sast")])) == 2


def test_different_classes_never_merge() -> None:
    assert len(correlate([make(10, "securelens-sast"), make(10, "bandit", vuln_class="xss")])) == 2


def test_corroboration_raises_confidence_only_with_real_evidence() -> None:
    likely = correlate([make(5, "a", exploit=Exploitability.LIKELY), make(5, "b", exploit=Exploitability.LIKELY)])[0]
    assert likely.confidence == Confidence.HIGH
    pattern_only = correlate([make(5, "a"), make(5, "b")])[0]
    assert pattern_only.confidence == Confidence.MEDIUM


def test_fingerprint_survives_line_shifts_but_not_code_changes() -> None:
    a = fingerprint.compute(make(10, "s", snippet="cursor.execute(query)"))
    b = fingerprint.compute(make(42, "s", snippet="cursor.execute(query)   "))
    c = fingerprint.compute(make(10, "s", snippet="cursor.execute(query, (uid,))"))
    assert a == b
    assert a != c


def test_risk_index_is_bounded_monotonic_and_explained() -> None:
    one = risk.compute([risk.RiskInput("1", "CRITICAL", "HIGH", "PROVEN_DATAFLOW")])
    three = risk.compute([risk.RiskInput(str(i), "CRITICAL", "HIGH", "PROVEN_DATAFLOW") for i in range(3)])
    none = risk.compute([risk.RiskInput("1", "CRITICAL", "HIGH", "PROVEN_DATAFLOW", status="RESOLVED")])
    assert 0 < one.index < three.index < 100
    assert none.index == 0
    assert one.contributions[0]["factors"]["severity"] == 10.0
    assert "not CVSS" in one.methodology


def test_risk_weights_are_configurable_and_accepted_risk_tracked() -> None:
    base = risk.compute([risk.RiskInput("1", "HIGH", "HIGH", "LIKELY")])
    heavier = risk.compute([risk.RiskInput("1", "HIGH", "HIGH", "LIKELY")], overrides={"severity": {"HIGH": 9.0}})
    exposed = risk.compute([risk.RiskInput("1", "HIGH", "HIGH", "LIKELY")], exposure="INTERNET_FACING")
    accepted = risk.compute([risk.RiskInput("1", "HIGH", "HIGH", "LIKELY", status="ACCEPTED_RISK")])
    assert heavier.index > base.index and exposed.index > base.index
    assert accepted.index == 0 and accepted.accepted_risk_total > 0
    # Out-of-range overrides are ignored rather than trusted.
    assert risk.merge_weights({"severity": {"HIGH": -5}, "saturation": 0})["severity"]["HIGH"] == 7.0


def test_gate_policy() -> None:
    items = [GateItem("SL-001", "SQLi", "CRITICAL", "HIGH"), GateItem("SL-002", "weak", "MEDIUM", "HIGH"),
             GateItem("SL-003", "maybe", "HIGH", "LOW"), GateItem("SL-004", "ai", "HIGH", "HIGH", verification="AI_SUGGESTED"),
             GateItem("SL-005", "fixed", "CRITICAL", "HIGH", status="RESOLVED")]
    result = evaluate(items, GatePolicy())
    assert result.status == "FAIL"
    assert [b.id for b in result.blocking] == ["SL-001"]
    assert evaluate([GateItem("x", "info", "INFO", "HIGH")], GatePolicy()).status == "PASS"
    assert evaluate([], GatePolicy(), regressions=1).status == "FAIL"
    assert evaluate(items[1:2], GatePolicy(fail_on=["CRITICAL", "HIGH", "MEDIUM"])).status == "FAIL"


def test_workspace_does_not_follow_symlinks_and_honours_excludes(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import os\nos.system(input())\n")
    project = tmp_path / "project"
    (project / "node_modules" / "lib").mkdir(parents=True)
    (project / "node_modules" / "lib" / "index.js").write_text("eval(process.argv[2])")
    (project / "app.py").write_text("print('hi')\n")
    os.symlink(outside, project / "linked_dir")
    os.symlink(outside / "secret.py", project / "linked.py")
    files, records, _ = build_inventory(project, ScanOptions(exclude=["generated/"]))
    paths = {f.path for f in files}
    assert paths == {"app.py"}
    details = {r.path: r.detail for r in records}
    assert "symbolic link" in details["linked_dir"] and "symbolic link" in details["linked.py"]


def test_file_limit_is_enforced(tmp_path: Path) -> None:
    for i in range(12):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    result = run_scan(tmp_path, ScanOptions(max_files=10, external={}, vulnerability_source="none"))
    assert len([f for f in result.files if f.status == "ANALYZED"]) == 10
    assert any("file limit" in e for e in result.errors)
