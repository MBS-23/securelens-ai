"""End to end through the API: upload → worker → findings → triage → fixed upload → retest."""

from __future__ import annotations

import io
import json
import zipfile

from tests.conftest import add_member, new_client, run_jobs

VULNERABLE_APP = '''\
from flask import Flask, request
import sqlite3, subprocess
app = Flask(__name__)
AWS_KEY = "{aws_key}"

@app.route("/user")
def user():
    user_id = request.args["id"]
    sqlite3.connect("db").execute("SELECT * FROM users WHERE id=" + user_id)
    return "ok"

@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)
'''

FIXED_APP = '''\
import os
from flask import Flask, request
import sqlite3, subprocess
app = Flask(__name__)
AWS_KEY = os.environ["AWS_KEY"]

@app.route("/user")
def user():
    user_id = request.args["id"]
    sqlite3.connect("db").execute("SELECT * FROM users WHERE id=?", (user_id,))
    return "ok"

@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)
'''


def aws_key() -> str:
    # Built at runtime so no credential-shaped literal lives in the repository.
    return "AKIA" + "QX7Z" + "4MPL3K2J" + "9WHT"


def zip_bytes(files: dict[str, str], prefix: str = "shop-api/") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in files.items():
            zf.writestr(prefix + name, text)
    return buf.getvalue()


def upload(account, project_id: str, data: bytes, filename: str = "shop-api.zip", **form):
    return account.post(f"/api/v1/projects/{project_id}/uploads",
                        files={"file": (filename, data, "application/zip")}, data=form)


def vulnerable_zip() -> bytes:
    return zip_bytes({"app.py": VULNERABLE_APP.format(aws_key=aws_key()), "requirements.txt": "flask==2.0.1\n"})


def completed_scan(owner, project_id: str, data: bytes | None = None, **form) -> dict:
    r = upload(owner, project_id, data or vulnerable_zip(), **form)
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "QUEUED"
    assert run_jobs() >= 1
    scan = owner.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}").json()
    assert scan["status"] == "COMPLETED", scan
    return scan


def findings_of(owner, project_id: str, **params) -> list[dict]:
    r = owner.get(f"/api/v1/projects/{project_id}/findings", params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_upload_scan_produces_findings(owner, project_id):
    scan = completed_scan(owner, project_id)
    assert scan["repository_name"] == "shop-api"
    assert scan["gate_status"] == "FAIL"
    assert scan["risk_index"] > 0
    assert scan["stats"]["files_analyzed"] == 2
    classes = {f["vuln_class"] for f in findings_of(owner, project_id)}
    assert {"sql_injection", "command_injection", "hardcoded_secret"} <= classes
    ids = [f["public_id"] for f in findings_of(owner, project_id)]
    assert all(i.startswith("SL-") for i in ids) and len(ids) == len(set(ids))
    deps = owner.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}/dependencies").json()
    assert deps[0]["name"] == "flask" and deps[0]["vuln_status"] == "NOT_VERIFIED"


def test_secrets_are_masked_everywhere(owner, project_id):
    scan = completed_scan(owner, project_id)
    secret = next(f for f in findings_of(owner, project_id) if f["vuln_class"] == "hardcoded_secret")
    detail = owner.get(f"/api/v1/projects/{project_id}/findings/{secret['id']}")
    assert aws_key() not in detail.text
    view = owner.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}/file", params={"path": "app.py"})
    assert view.status_code == 200
    body = view.json()
    assert body["redacted"] is True and aws_key() not in body["content"]
    assert any(m["line"] for m in body["findings"])
    for fmt in ("html", "json", "sarif", "markdown"):
        report = owner.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}/report", params={"format": fmt})
        assert report.status_code == 200, (fmt, report.text)
        assert aws_key() not in report.text


def test_file_view_refuses_paths_outside_the_scan(owner, project_id):
    scan = completed_scan(owner, project_id)
    for path in ("../../etc/passwd", "/etc/passwd", "missing.py"):
        r = owner.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}/file", params={"path": path})
        assert r.status_code in (400, 404), path


def test_finding_detail_explains_the_detection(owner, project_id):
    completed_scan(owner, project_id)
    sqli = next(f for f in findings_of(owner, project_id) if f["vuln_class"] == "sql_injection")
    detail = owner.get(f"/api/v1/projects/{project_id}/findings/{sqli['id']}").json()
    titles = [s["title"] for s in detail["explanation"]["steps"]]
    assert titles[0] == "Untrusted input enters the program"
    assert "It reaches a dangerous operation" in titles
    assert detail["occurrences"][0]["evidence"][0]["kind"] == "dataflow"
    assert detail["verification"] == "DETECTED"


def test_fixed_upload_retest_resolves_only_what_was_fixed(owner, project_id):
    first = completed_scan(owner, project_id)
    fixed = zip_bytes({"app.py": FIXED_APP, "requirements.txt": "flask==2.0.1\n"})
    r = owner.post(f"/api/v1/projects/{project_id}/retests/upload",
                   files={"file": ("shop-api.zip", fixed, "application/zip")},
                   data={"baseline_scan_id": first["id"]})
    assert r.status_code == 202, r.text
    run_jobs()
    second = owner.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}").json()
    assert second["status"] == "COMPLETED" and second["trigger"] == "RETEST"
    summary = second["stats"]["retest"]
    assert summary["resolved"] >= 2 and summary["still_open"] >= 1 and summary["regressions"] == 0

    by_class = {f["vuln_class"]: f for f in findings_of(owner, project_id)}
    assert by_class["sql_injection"]["status"] == "RESOLVED"
    assert by_class["hardcoded_secret"]["status"] == "RESOLVED"
    assert by_class["command_injection"]["status"] == "OPEN"

    retests = owner.get(f"/api/v1/projects/{project_id}/retests").json()
    detail = owner.get(f"/api/v1/projects/{project_id}/retests/{retests[0]['id']}").json()
    results = {r["vuln_class"]: r["result"] for r in detail["results"]}
    assert results["sql_injection"] == "RESOLVED" and results["command_injection"] == "STILL_OPEN"

    # Reintroducing the vulnerability is a regression that fails the gate.
    r = upload(owner, project_id, vulnerable_zip(), baseline_scan_id=second["id"])
    run_jobs()
    third = owner.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}").json()
    assert third["stats"]["retest"]["regressions"] >= 1
    assert third["gate_status"] == "FAIL"
    reopened = {f["vuln_class"]: f["status"] for f in findings_of(owner, project_id)}
    assert reopened["sql_injection"] == "REOPENED"


def test_rescan_keeps_finding_identity(owner, project_id):
    scan = completed_scan(owner, project_id)
    before = {f["public_id"] for f in findings_of(owner, project_id)}
    r = owner.post(f"/api/v1/projects/{project_id}/scans/{scan['id']}/rescan", json={})
    assert r.status_code == 202, r.text
    run_jobs()
    assert owner.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}").json()["status"] == "COMPLETED"
    assert {f["public_id"] for f in findings_of(owner, project_id)} == before


def test_triage_permissions(app, owner, org_id, project_id):
    completed_scan(owner, project_id)
    finding = findings_of(owner, project_id)[0]
    url = f"/api/v1/projects/{project_id}/findings/{finding['id']}"
    developer = add_member(app, owner, org_id, "DEVELOPER")
    analyst = add_member(app, owner, org_id, "SECURITY_ANALYST")
    owner.post(f"/api/v1/projects/{project_id}/members", json={"user_id": developer.user_id})

    assert developer.patch(f"{url}/status", json={"status": "IN_PROGRESS"}).status_code == 200
    assert developer.patch(f"{url}/status", json={"status": "FALSE_POSITIVE", "reason": "test"}).status_code == 403
    assert developer.patch(f"{url}/status", json={"status": "RESOLVED", "reason": "fixed"}).status_code == 403
    assert developer.patch(f"{url}/verification", json={"verification": "CONFIRMED", "reason": "x"}).status_code == 403
    assert analyst.patch(f"{url}/status", json={"status": "FALSE_POSITIVE"}).status_code == 422  # reason required
    r = analyst.patch(f"{url}/status", json={"status": "FALSE_POSITIVE", "reason": "input is a constant"})
    assert r.status_code == 200 and r.json()["verification"] == "FALSE_POSITIVE"
    assert analyst.patch(f"{url}/verification", json={"verification": "AI_SUGGESTED"}).status_code == 422
    r = analyst.patch(f"{url}/verification", json={"verification": "CONFIRMED", "reason": "reproduced"})
    assert r.status_code == 200 and r.json()["status"] == "OPEN"
    logs = owner.get(f"/api/v1/organizations/{org_id}/audit-logs", params={"action": "finding."}).json()["items"]
    assert {entry["action"] for entry in logs} == {"finding.status", "finding.verification"}


def test_access_control_on_scans(app, owner, org_id, project_id):
    scan = completed_scan(owner, project_id)
    viewer = add_member(app, owner, org_id, "VIEWER")
    owner.post(f"/api/v1/projects/{project_id}/members", json={"user_id": viewer.user_id})
    assert viewer.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}").status_code == 200
    assert upload(viewer, project_id, vulnerable_zip()).status_code == 403
    outsider = add_member(app, owner, org_id, "DEVELOPER")  # not added to the project
    assert outsider.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}").status_code == 404
    assert outsider.get(f"/api/v1/projects/{project_id}/findings").status_code == 404


def test_rejected_uploads(owner, project_id):
    assert upload(owner, project_id, b"MZ\x90\x00", filename="tool.exe").status_code == 422
    assert upload(owner, project_id, b"", filename="empty.zip").status_code == 422
    assert upload(owner, project_id, b"x", filename="notes.docx").status_code == 422


def test_malicious_archive_fails_the_scan_safely(owner, project_id):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../../tmp/securelens-pwned.py", "x = 1")
    r = upload(owner, project_id, buf.getvalue(), filename="evil.zip")
    assert r.status_code == 202
    run_jobs()
    scan = owner.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}").json()
    assert scan["status"] == "FAILED"
    assert "Unsafe path" in scan["error"]


def test_cancelled_scan_is_not_run(owner, project_id):
    r = upload(owner, project_id, vulnerable_zip())
    scan_id = r.json()["id"]
    assert owner.post(f"/api/v1/projects/{project_id}/scans/{scan_id}/cancel").json()["status"] == "CANCELLED"
    run_jobs()
    assert owner.get(f"/api/v1/projects/{project_id}/scans/{scan_id}").json()["status"] == "CANCELLED"
    assert findings_of(owner, project_id) == []


def test_report_requires_a_completed_scan(owner, project_id):
    r = upload(owner, project_id, vulnerable_zip())
    report = owner.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}/report")
    assert report.status_code == 409


def test_html_report_download(owner, project_id):
    scan = completed_scan(owner, project_id)
    r = owner.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}/report", params={"format": "html"})
    assert r.headers["content-type"].startswith("text/html")
    assert "attachment" in r.headers["content-disposition"]
    assert "<h2>Limitations</h2>" in r.text and "<h2>Methodology</h2>" in r.text
    sarif = owner.get(f"/api/v1/projects/{project_id}/scans/{scan['id']}/report", params={"format": "sarif"}).json()
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]


def test_cli_import_with_project_api_key(app, owner, org_id, project_id, tmp_path):
    from securelens.reporting import render
    from securelens.reporting.context import apply_gate_and_risk
    from securelens.scanners.base import ScanOptions
    from securelens.scanners.engine import run_scan

    (tmp_path / "app.py").write_text(VULNERABLE_APP.format(aws_key=aws_key()))
    result = apply_gate_and_risk(run_scan(tmp_path, ScanOptions(external={}, vulnerability_source="none")))
    report = json.loads(render(result, "json"))
    r = owner.post(f"/api/v1/organizations/{org_id}/api-keys",
                   json={"name": "ci", "role": "DEVELOPER", "project_id": project_id})
    key = r.json()["key"]
    ci = new_client(app)
    r = ci.post(f"/api/v1/projects/{project_id}/scans/import", headers={"Authorization": f"Bearer {key}"},
                json={"repository_name": "shop-api-ci", "commit": "a" * 40, "branch": "main", "report": report})
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "COMPLETED" and r.json()["trigger"] == "CLI_IMPORT"
    imported = findings_of(owner, project_id)
    assert {"sql_injection", "command_injection"} <= {f["vuln_class"] for f in imported}
    r = ci.post(f"/api/v1/projects/{project_id}/scans/import", headers={"Authorization": f"Bearer {key}"},
                json={"report": {"not": "a report"}})
    assert r.status_code == 422


def test_unbounded_chunked_upload_is_refused(owner, project_id):
    def body():
        yield b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\n\r\n"
        yield b"PK"

    r = owner.post(f"/api/v1/projects/{project_id}/uploads", content=body(),
                   headers={"Content-Type": "multipart/form-data; boundary=x"})
    assert r.status_code == 411
