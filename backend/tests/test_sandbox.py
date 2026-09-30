"""The analysis sandbox: same results as in-process analysis, no secrets, limits enforced."""

from __future__ import annotations

from pathlib import Path

import pytest

from securelens.scanners.base import ScanOptions
from securelens.scanners.engine import analyze
from securelens.worker.sandbox import SandboxError, SandboxLimits, _child_env, run_isolated

APP = '''\
from flask import request
import subprocess
def run():
    return subprocess.check_output("ls " + request.args["dir"], shell=True)
'''


def options() -> ScanOptions:
    return ScanOptions(external={}, vulnerability_source="none", secret_hash_key=b"sandbox-test-key")


def test_isolated_analysis_matches_in_process(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP)
    isolated = run_isolated(tmp_path, options(), "demo", SandboxLimits(timeout_seconds=120, memory_mb=2048))
    direct = analyze(tmp_path, options(), target="demo")
    assert {f.rule_id for f in isolated.findings} == {f.rule_id for f in direct.findings}
    assert any(f.vuln_class == "command_injection" for f in isolated.findings)


def test_child_environment_carries_no_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURELENS_SECRET_KEY", "a-server-secret-that-must-not-leak")
    monkeypatch.setenv("SECURELENS_DATABASE_URL", "postgresql://user:password@db/securelens")
    monkeypatch.setenv("SECURELENS_AI_API_KEY", "provider-key")
    env = _child_env("/tmp/work")
    assert not any(k.startswith("SECURELENS_") for k in env)
    assert not any("secret" in v or "password" in v or "provider-key" in v for v in env.values())


def test_resource_limit_violation_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP)
    # No output may be written, so the child is stopped when it writes its result.
    with pytest.raises(SandboxError):
        run_isolated(tmp_path, options(), "demo", SandboxLimits(timeout_seconds=120, max_output_mb=0))
