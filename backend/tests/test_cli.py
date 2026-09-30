"""The `securelens` command: exit codes, outputs, retest and configuration handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securelens.cli import output
from securelens.cli.main import main

VULNERABLE = '''\
from flask import Flask, request
import sqlite3, subprocess
app = Flask(__name__)
@app.route("/user")
def user():
    user_id = request.args["id"]
    sqlite3.connect("db").execute("SELECT * FROM users WHERE id=" + user_id)
    return "ok"
@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)
'''

FIXED = '''\
from flask import Flask, request
import sqlite3, subprocess
app = Flask(__name__)
@app.route("/user")
def user():
    user_id = request.args["id"]
    sqlite3.connect("db").execute("SELECT * FROM users WHERE id=?", (user_id,))
    return "ok"
@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)
'''

SAFE = "def add(a, b):\n    return a + b\n"


@pytest.fixture()
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SECURELENS_API_KEY", raising=False)
    (tmp_path / "app").mkdir()
    return tmp_path


def scan(*extra: str) -> int:
    return main(["scan", "app", "--vuln-source", "none", "--no-external", "--no-color", *extra])


def test_version(capsys) -> None:
    assert main(["version"]) == 0
    assert "SecureLens AI" in capsys.readouterr().out


def test_scan_fails_the_gate_and_saves_reports(workdir: Path, capsys) -> None:
    (workdir / "app" / "app.py").write_text(VULNERABLE)
    assert scan("--json-out", "out/report.json", "--sarif-out", "out/report.sarif") == 1
    out = capsys.readouterr().out
    assert "SQL query built from untrusted input" in out
    assert "Security gate: FAIL" in out
    report = json.loads((workdir / "out" / "report.json").read_text())
    assert report["gate"]["status"] == "FAIL"
    assert json.loads((workdir / "out" / "report.sarif").read_text())["version"] == "2.1.0"
    assert (workdir / ".securelens" / "last-scan.json").is_file()


def test_gate_options_change_the_exit_code(workdir: Path) -> None:
    (workdir / "app" / "app.py").write_text(VULNERABLE)
    assert scan("--fail-on", "none") == 0
    assert scan("--no-fail") == 0
    assert scan("--min-confidence", "confirmed") == 0


def test_clean_code_passes(workdir: Path, capsys) -> None:
    (workdir / "app" / "util.py").write_text(SAFE)
    assert scan() == 0
    assert "Security gate: PASS" in capsys.readouterr().out


def test_machine_readable_stdout(workdir: Path, capsys) -> None:
    (workdir / "app" / "app.py").write_text(VULNERABLE)
    scan("--format", "json", "--no-save")
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] and data["report"]["limitations"]
    assert not (workdir / ".securelens").exists()


def test_findings_show_explains_a_finding(workdir: Path, capsys) -> None:
    (workdir / "app" / "app.py").write_text(VULNERABLE)
    scan()
    capsys.readouterr()
    assert main(["findings", "--show", "SL-001", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "Why SecureLens detected this" in out
    assert "Untrusted input enters the program" in out
    assert main(["findings", "--show", "SL-999"]) == 2


def test_report_command_renders_saved_scan(workdir: Path) -> None:
    (workdir / "app" / "app.py").write_text(VULNERABLE)
    scan()
    assert main(["report", "--format", "html", "-o", "report.html"]) == 0
    html = (workdir / "report.html").read_text()
    assert "<h2>Limitations</h2>" in html


def test_retest_resolved_new_and_regression(workdir: Path, capsys) -> None:
    app = workdir / "app" / "app.py"
    app.write_text(VULNERABLE)
    scan("--json-out", "v1.json")
    capsys.readouterr()

    app.write_text(FIXED)  # SQL injection fixed, command injection left in place
    assert main(["retest", "app", "--baseline", "v1.json", "--vuln-source", "none", "--no-external",
                 "--no-color", "--json-out", "v2.json"]) == 0
    out = capsys.readouterr().out
    assert "RESOLVED" in out and "STILL_OPEN" in out
    v2 = json.loads((workdir / "v2.json").read_text())
    assert v2["history"]["retest"]["resolved"] == 1
    assert v2["history"]["resolved_fingerprints"]

    app.write_text(VULNERABLE)  # the fix is reverted: a regression
    assert main(["retest", "app", "--baseline", "v2.json", "--vuln-source", "none", "--no-external",
                 "--no-color"]) == 1
    assert "REGRESSION" in capsys.readouterr().out


def test_baseline_only_fails_on_new_issues(workdir: Path) -> None:
    app = workdir / "app" / "app.py"
    app.write_text(FIXED)
    scan("--json-out", "base.json")
    assert scan("--baseline", "base.json") == 0  # same issues as the baseline
    app.write_text(VULNERABLE)
    assert scan("--baseline", "base.json") == 1  # a new SQL injection


def test_init_and_ci_templates(workdir: Path) -> None:
    assert main(["init", "--ci", "github"]) == 0
    assert (workdir / ".securelens.yml").is_file()
    workflow = (workdir / ".github" / "workflows" / "securelens.yml").read_text()
    assert "upload-sarif" in workflow and "securelens scan" in workflow
    assert main(["init"]) == 2  # refuses to overwrite
    assert main(["init", "--force", "--ci", "gitlab"]) == 0
    assert (workdir / "securelens.gitlab-ci.yml").is_file()


def test_config_typos_are_errors(workdir: Path, capsys) -> None:
    (workdir / "app" / "util.py").write_text(SAFE)
    (workdir / ".securelens.yml").write_text("gate:\n  fail_on: [CRITICAL, HIHG]\n")
    assert scan() == 2
    assert "fail_on" in capsys.readouterr().err
    (workdir / ".securelens.yml").write_text("scan:\n  exclude_paths: []\n")
    assert scan() == 2


def test_config_is_applied(workdir: Path) -> None:
    (workdir / "app" / "app.py").write_text(VULNERABLE)
    (workdir / ".securelens.yml").write_text("scan:\n  external: off\ngate:\n  fail_on: []\n")
    assert scan() == 0


def test_usage_errors(workdir: Path) -> None:
    assert main(["scan", "does-not-exist"]) == 2
    assert main(["scan", "app", "--vuln-source", "offline"]) == 2
    assert main(["findings", "--input", "missing.json"]) == 2
    assert main(["no-such-command"]) == 2


def test_push_validates_server_and_key(workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (workdir / "app" / "util.py").write_text(SAFE)
    scan()
    assert main(["push", "--server", "https://securelens.example", "--project", "p"]) == 2  # no API key
    monkeypatch.setenv("SECURELENS_API_KEY", "slk_test")
    assert main(["push", "--server", "http://securelens.example", "--project", "p"]) == 2  # plain http
    assert main(["push", "--server", "https://user:pw@securelens.example", "--project", "p"]) == 2


def test_terminal_output_strips_control_characters() -> None:
    assert output.clean("evil\x1b[2J\x1b]0;title\x07name‮.py") == "evil[2J]0;titlename.py"
