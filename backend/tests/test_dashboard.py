"""Dashboard metrics and organization settings."""

from __future__ import annotations

from tests.conftest import add_member
from tests.test_scan_api import completed_scan


def test_summary_without_projects(owner, org_id):
    data = owner.get("/api/v1/dashboard/summary", params={"organization_id": org_id}).json()
    assert data["projects"] == [] and data["open_by_severity"]["CRITICAL"] == 0
    assert data["recent_scans"] == []


def test_summary_after_a_scan(owner, org_id, project_id):
    completed_scan(owner, project_id)
    data = owner.get("/api/v1/dashboard/summary").json()
    assert data["open_by_severity"]["CRITICAL"] >= 1
    assert len(data["trend"]) == 30 and data["trend"][-1]["new"] >= 3
    assert data["recent_scans"][0]["status"] == "COMPLETED"
    assert data["top_findings"][0]["risk_score"] >= data["top_findings"][-1]["risk_score"]
    assert data["projects"][0]["risk_index"] > 0
    assert {"sql_injection", "command_injection"} <= {c["vuln_class"] for c in data["top_classes"]}
    project = owner.get(f"/api/v1/projects/{project_id}/metrics").json()
    assert project["hotspots"][0]["path"] == "app.py"
    assert "python" in project["languages"]


def test_summary_is_scoped_to_visible_projects(app, owner, org_id, project_id):
    completed_scan(owner, project_id)
    developer = add_member(app, owner, org_id, "DEVELOPER")  # not a member of the project
    data = developer.get("/api/v1/dashboard/summary").json()
    assert data["projects"] == [] and data["top_findings"] == []
    assert developer.get(f"/api/v1/projects/{project_id}/metrics").status_code == 404


def test_settings_permissions_and_validation(app, owner, org_id):
    analyst = add_member(app, owner, org_id, "SECURITY_ANALYST")
    url = f"/api/v1/organizations/{org_id}/settings"
    current = analyst.get(url).json()
    assert current["risk_weights"]["saturation"] == 25.0 and "not CVSS" in current["risk_methodology"]
    assert analyst.patch(url, json={"risk_weights": {"saturation": 40}}).status_code == 403
    assert owner.patch(url, json={"risk_weights": {"severity": {"CRITICAL": 500}}}).status_code == 422
    assert owner.patch(url, json={"risk_weights": {"made_up": {}}}).status_code == 422
    r = owner.patch(url, json={"risk_weights": {"saturation": 40, "exposure": {"INTERNET_FACING": 1.5}}})
    assert r.status_code == 200
    assert r.json()["risk_weights"]["saturation"] == 40.0
    assert r.json()["risk_weights"]["exposure"]["INTERNET_FACING"] == 1.5
    assert owner.patch(url, json={"reset_risk_weights": True}).json()["risk_overrides"] == {}


def test_default_gate_policy_applies_to_scans(owner, org_id, project_id):
    r = owner.patch(f"/api/v1/organizations/{org_id}/settings",
                    json={"gate_policy": {"fail_on": [], "fail_on_regression": False}})
    assert r.status_code == 200
    scan = completed_scan(owner, project_id)
    assert scan["gate_status"] == "PASS"
