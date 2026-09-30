"""Dependency inventory, advisory correlation (offline and OSV) and version logic.

Advisory records used here carry obviously synthetic IDs (SLTEST-...) — no real
CVE data is invented.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from securelens.findings.model import DependencyRecord, ScanResult
from securelens.scanners.base import ScanOptions
from securelens.scanners.dependencies import scanner as deps
from securelens.scanners.dependencies.advisories import OfflineSource, OSVSource
from securelens.scanners.dependencies.manifests import (
    merge,
    parse_composer_lock,
    parse_package_json,
    parse_package_lock,
    parse_pyproject,
    parse_requirements,
    parse_yarn_lock,
)
from securelens.scanners.dependencies.versions import compare, cvss3_base_score, is_affected
from securelens.scanners.engine import run_scan

ADVISORY = {
    "id": "SLTEST-2026-0001",
    "aliases": ["SLTEST-CVE-0001"],
    "summary": "Synthetic advisory used by the SecureLens test-suite",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.4.2"}]}]}],
    "references": [{"type": "ADVISORY", "url": "https://example.invalid/SLTEST-2026-0001"}],
}


def test_requirements_parsing() -> None:
    m = parse_requirements("requirements.txt", """
flask==2.0.1  # web
requests>=2.0
Django[bcrypt]==4.2.1 ; python_version >= "3.8"
-r other.txt
git+https://github.com/org/pkg.git
""")
    by = {r.name: r for r in m.records}
    assert by["flask"].version == "2.0.1"
    assert by["requests"].version is None and by["requests"].version_spec == ">=2.0"
    assert by["django"].version == "4.2.1"
    assert len(m.records) == 3


def test_pyproject_pep621_and_poetry() -> None:
    m = parse_pyproject("pyproject.toml", """
[project]
dependencies = ["httpx==0.27.0", "pydantic>=2"]
[project.optional-dependencies]
dev = ["pytest==8.0.0"]
[tool.poetry.dependencies]
python = "^3.11"
rich = "13.7.1"
""")
    by = {r.name: r for r in m.records}
    assert by["httpx"].version == "0.27.0"
    assert by["pytest"].dev
    assert by["rich"].version == "13.7.1"
    assert "python" not in by


def test_npm_lockfile_marks_direct_and_dev() -> None:
    manifest = parse_package_json("package.json", json.dumps({
        "dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "29.7.0"}}))
    lock = parse_package_lock("package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "29.7.0"}},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
            "node_modules/qs": {"version": "6.11.0"},
        }}))
    records = {r.name: r for r in merge([manifest, lock])}
    assert records["express"].version == "4.18.2" and records["express"].direct
    assert records["jest"].dev
    assert records["qs"].direct is False


def test_yarn_and_composer_lock() -> None:
    yarn = parse_yarn_lock("yarn.lock", '"lodash@^4.17.0":\n  version "4.17.21"\n  resolved "x"\n')
    assert [(r.name, r.version) for r in yarn.records] == [("lodash", "4.17.21")]
    composer = parse_composer_lock("composer.lock", json.dumps({"packages": [{"name": "Monolog/Monolog", "version": "v2.9.1"}]}))
    assert composer.records[0].name == "monolog/monolog" and composer.records[0].version == "2.9.1"


def test_versions_and_ranges() -> None:
    assert compare("PyPI", "1.10.0", "1.9.9") == 1
    assert compare("PyPI", "2.0.0rc1", "2.0.0") == -1
    assert compare("npm", "1.2.3-beta.2", "1.2.3") == -1
    affected = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]}]}
    assert is_affected("npm", "1.4.0", affected)
    assert not is_affected("npm", "1.4.1", affected)
    assert not is_affected("npm", "0.9.0", affected)


def test_cvss_v3_scores() -> None:
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 6.4
    assert cvss3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("CVSS:4.0/AV:N") is None


def test_offline_database_produces_verified_findings(tmp_path: Path) -> None:
    db = tmp_path / "advisories"
    db.mkdir()
    (db / "SLTEST-2026-0001.json").write_text(json.dumps(ADVISORY))
    project = tmp_path / "app"
    project.mkdir()
    (project / "requirements.txt").write_text("demo-lib==1.2.0\nsafe-lib==2.0.0\nunpinned-lib>=1.0\n")
    options = ScanOptions(scanners={"dependencies"}, external={}, vulnerability_source="offline", offline_db=db)
    result = run_scan(project, options)
    status = {d.name: d.vuln_status for d in result.dependencies}
    assert status == {"demo-lib": "VULNERABLE", "safe-lib": "NO_KNOWN_VULNERABILITIES", "unpinned-lib": "NOT_VERIFIED"}
    [finding] = result.findings
    assert finding.rule_id == "SLTEST-2026-0001"
    assert finding.severity.value == "CRITICAL"
    ev = finding.evidence[0].data
    assert ev["fixed_versions"] == ["1.4.2"] and ev["verification"] == "VERIFIED"
    assert finding.location.path == "requirements.txt" and finding.location.start_line == 1


def test_no_source_marks_not_verified(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("demo-lib==1.2.0\n")
    result = run_scan(tmp_path, ScanOptions(scanners={"dependencies"}, external={}, vulnerability_source="none"))
    assert result.dependencies[0].vuln_status == "NOT_VERIFIED"
    assert not result.findings


def _osv_transport(fail: bool = False) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if fail:
            return httpx.Response(503)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "SLTEST-2026-0001"}]} if q["package"]["name"] == "demo-lib" else {}
                for q in queries]})
        if request.url.path == "/v1/vulns/SLTEST-2026-0001":
            return httpx.Response(200, json=ADVISORY)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_osv_source_with_mock_api() -> None:
    client = httpx.Client(transport=_osv_transport(), base_url="https://osv.test")
    source = OSVSource("https://osv.test", client=client)
    result = ScanResult(target="t", started_at="", finished_at="", dependencies=[
        DependencyRecord(ecosystem="PyPI", name="demo-lib", version="1.2.0", manifest_path="requirements.txt"),
        DependencyRecord(ecosystem="PyPI", name="other", version="1.0.0", manifest_path="requirements.txt"),
    ])
    deps.enrich(result, ScanOptions(), source=source)
    assert [d.vuln_status for d in result.dependencies] == ["VULNERABLE", "NO_KNOWN_VULNERABILITIES"]
    assert result.findings[0].evidence[0].source == "OSV.dev"


def test_osv_failure_is_not_verified_not_clean() -> None:
    client = httpx.Client(transport=_osv_transport(fail=True), base_url="https://osv.test")
    result = ScanResult(target="t", started_at="", finished_at="", dependencies=[
        DependencyRecord(ecosystem="PyPI", name="demo-lib", version="1.2.0", manifest_path="requirements.txt")])
    deps.enrich(result, ScanOptions(), source=OSVSource("https://osv.test", client=client))
    assert result.dependencies[0].vuln_status == "NOT_VERIFIED"
    assert result.errors and "NOT VERIFIED" in result.errors[0]
    assert not result.findings
