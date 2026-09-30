"""Scanner regression corpus: every vulnerable example is detected, every safe one is not."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from securelens.enums import CONFIDENCE_ORDER, Confidence
from securelens.scanners.base import ScanOptions
from securelens.scanners.engine import run_scan

CASES = yaml.safe_load((Path(__file__).parent / "corpus" / "cases.yml").read_text())


def scan_case(tmp_path: Path, case: dict):
    (tmp_path / case["file"]).write_text(case["code"])
    for extra in case.get("support", []):
        (tmp_path / extra["file"]).write_text(extra["code"])
    return run_scan(tmp_path, ScanOptions(scanners={"sast", "secrets"}, external={}, vulnerability_source="none"))


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_corpus_case(tmp_path: Path, case: dict) -> None:
    result = scan_case(tmp_path, case)
    files = {case["file"], *(extra["file"] for extra in case.get("support", []))}
    found = {}
    for f in result.findings:
        if f.location and f.location.path in files:
            best = found.get(f.vuln_class)
            if best is None or CONFIDENCE_ORDER[f.confidence] > CONFIDENCE_ORDER[best]:
                found[f.vuln_class] = f.confidence
    summary = {k: v.value for k, v in found.items()}
    for vuln_class in case.get("expect", []):
        assert vuln_class in found, f"{case['id']}: expected {vuln_class}, found {summary}"
        if "min_confidence" in case:
            minimum = Confidence(case["min_confidence"])
            assert CONFIDENCE_ORDER[found[vuln_class]] >= CONFIDENCE_ORDER[minimum], (
                f"{case['id']}: {vuln_class} confidence {found[vuln_class].value} < {minimum.value}")
    for vuln_class in case.get("absent", []):
        assert vuln_class not in found, f"{case['id']}: {vuln_class} must not be reported, found {summary}"


def test_every_language_is_covered() -> None:
    extensions = {Path(c["file"]).suffix for c in CASES}
    assert {".py", ".js", ".ts", ".tsx", ".php", ".java", ".cs", ".go", ".c", ".cpp"} <= extensions
