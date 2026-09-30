"""Report rendering: required sections, SARIF structure, and escaping of untrusted content."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securelens.findings.model import ScanResult
from securelens.reporting import render
from securelens.reporting.context import ASSURANCE_STATEMENT, apply_gate_and_risk
from securelens.scanners.base import ScanOptions
from securelens.scanners.engine import run_scan

HOSTILE_NAME = "<img src=x onerror=alert(1)> | x.py"

VULNERABLE_APP = '''\
from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route("/user")
def user():
    user_id = request.args["id"]
    cursor = sqlite3.connect("db").cursor()
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)  # </pre><script>alert(1)</script>
    return "ok"
'''


@pytest.fixture()
def result(tmp_path: Path) -> ScanResult:
    (tmp_path / HOSTILE_NAME).write_text(VULNERABLE_APP)
    (tmp_path / "requirements.txt").write_text("flask>=2.0\n")
    res = run_scan(tmp_path, ScanOptions(external={}, vulnerability_source="none"), target="demo")
    return apply_gate_and_risk(res)


def test_result_has_the_expected_finding(result: ScanResult) -> None:
    assert any(f.vuln_class == "sql_injection" for f in result.findings)


def test_html_is_self_contained_and_escaped(result: ScanResult) -> None:
    html = render(result, "html")
    assert "<script" not in html.lower()
    assert "onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;/pre&gt;&lt;script&gt;" in html
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "default-src 'none'" in html
    assert "src=\"http" not in html and "href=\"//" not in html  # no external resources


def test_html_states_scope_methodology_limitations_and_time(result: ScanResult) -> None:
    html = render(result, "html")
    for heading in ("<h2>Scope</h2>", "<h2>Methodology</h2>", "<h2>Limitations</h2>"):
        assert heading in html
    assert "Generated " in html and result.finished_at[:10] in html
    assert ASSURANCE_STATEMENT in html
    assert "Why SecureLens detected this" in html
    assert "not CVSS" in html


def test_limitations_reflect_what_did_not_run(result: ScanResult) -> None:
    data = json.loads(render(result, "json"))
    limits = " ".join(data["report"]["limitations"])
    assert "Known-vulnerability lookup skipped" in limits
    assert "NOT VERIFIED" in limits
    assert ASSURANCE_STATEMENT in limits


def test_json_round_trips_into_the_model(result: ScanResult) -> None:
    data = json.loads(render(result, "json"))
    again = ScanResult.model_validate(data)
    assert [f.fingerprint for f in again.findings] == [f.fingerprint for f in result.findings]
    assert data["report"]["scope"]["target"] == "demo"
    assert data["report"]["methodology"]


def test_sarif_structure(result: ScanResult) -> None:
    sarif = json.loads(render(result, "sarif"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        assert res["partialFingerprints"]["securelens/v1"]
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert " " not in uri and "<" not in uri
    sqli = next(r for r in run["results"] if r["properties"]["vulnerabilityClass"] == "sql_injection")
    assert sqli["level"] == "error"
    assert sqli["codeFlows"][0]["threadFlows"][0]["locations"]
    rule = rules[sqli["ruleIndex"]]
    assert float(rule["properties"]["security-severity"]) >= 9.0
    assert "CWE-89" in rule["properties"]["tags"]


def test_markdown_escapes_table_cells(result: ScanResult) -> None:
    md = render(result, "markdown")
    rows = [line for line in md.splitlines() if line.startswith("| SL-")]
    assert rows
    for row in rows:
        # Six columns → seven unescaped pipes, whatever the file name contains.
        unescaped = row.replace("\\|", "")
        assert unescaped.count("|") == 6
    # Markup from file names may appear only inside code spans, where it is shown as text.
    import re

    assert "<img" not in re.sub(r"`[^`]*`", "", md)


def test_empty_result_does_not_claim_the_code_is_secure(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('hello')\n")
    res = apply_gate_and_risk(run_scan(tmp_path, ScanOptions(external={}, vulnerability_source="none")))
    md = render(res, "markdown")
    html = render(res, "html")
    assert "not proof" in md
    assert "does not prove the code is free of vulnerabilities" in html
    assert res.gate["status"] == "PASS"
