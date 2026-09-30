"""Authentication, sessions, CSRF, RBAC and tenant isolation."""

from __future__ import annotations

from tests.conftest import STRONG_PASSWORD, add_member, login, new_client


def test_bootstrap_only_once(app, owner):
    c = new_client(app)
    r = c.post("/api/v1/auth/bootstrap", json={
        "email": "second@example.com", "display_name": "X", "password": STRONG_PASSWORD,
        "organization_name": "Other",
    })
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "already_initialised"


def test_status_reports_initialisation(client, owner):
    assert client.get("/api/v1/auth/status").json() == {"initialised": True}


def test_weak_password_rejected(app):
    c = new_client(app)
    r = c.post("/api/v1/auth/bootstrap", json={
        "email": "a@example.com", "display_name": "A", "password": "password1234", "organization_name": "Org",
    })
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "weak_password"


def test_validation_errors_do_not_echo_input(app):
    c = new_client(app)
    r = c.post("/api/v1/auth/login", json={"email": "x@example.com", "password": "", "extra": "s3cr3t-value"})
    assert r.status_code == 422
    assert "s3cr3t-value" not in r.text


def test_login_sets_hardened_cookies(app, owner):
    c = new_client(app)
    r = c.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": STRONG_PASSWORD})
    assert r.status_code == 200
    cookies = r.headers.get_list("set-cookie")
    session_cookie = next(h for h in cookies if h.startswith("sl_session="))
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie or "samesite=strict" in session_cookie.lower()
    assert "Path=/api" in session_cookie


def test_wrong_password_and_lockout(app, owner, db):
    c = new_client(app)
    for _ in range(5):
        r = c.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": "wrong-password-123"})
        assert r.status_code == 401
    # Account is now locked, even with the right password.
    r = c.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": STRONG_PASSWORD})
    assert r.status_code == 401
    from sqlalchemy import select

    from securelens.models import AuditLog

    outcomes = [a.outcome for a in db.scalars(select(AuditLog).where(AuditLog.action == "auth.login"))]
    assert "FAILURE" in outcomes and "DENIED" in outcomes


def test_unknown_email_same_error(app):
    c = new_client(app)
    r = c.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "whatever-password-1"})
    assert r.status_code == 401
    assert "Invalid email or password" in r.json()["error"]["message"]


def test_csrf_required_for_cookie_writes(owner, org_id):
    # Missing token
    r = owner.client.post("/api/v1/projects", json={"organization_id": org_id, "name": "No CSRF"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"
    # Wrong token
    r = owner.client.post("/api/v1/projects", json={"organization_id": org_id, "name": "Bad CSRF"},
                          headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    # Correct token
    r = owner.post("/api/v1/projects", json={"organization_id": org_id, "name": "Good CSRF"})
    assert r.status_code == 201


def test_logout_revokes_session(owner):
    assert owner.get("/api/v1/auth/me").status_code == 200
    assert owner.post("/api/v1/auth/logout").status_code == 200
    assert owner.get("/api/v1/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(app, owner):
    other = login(app, "owner@example.com")
    r = owner.post("/api/v1/auth/change-password",
                   json={"current_password": STRONG_PASSWORD, "new_password": "An0ther-Strong-Passphrase"})
    assert r.status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 401
    assert owner.get("/api/v1/auth/me").status_code == 200


def test_role_matrix_on_project_creation(app, owner, org_id):
    viewer = add_member(app, owner, org_id, "VIEWER")
    developer = add_member(app, owner, org_id, "DEVELOPER")
    analyst = add_member(app, owner, org_id, "SECURITY_ANALYST")
    for account, expected in [(viewer, 403), (developer, 403), (analyst, 201)]:
        r = account.post("/api/v1/projects", json={"organization_id": org_id, "name": f"P {account.email}"})
        assert r.status_code == expected, (account.email, r.text)


def test_developer_sees_only_assigned_projects(app, owner, org_id, project_id):
    developer = add_member(app, owner, org_id, "DEVELOPER")
    assert developer.get(f"/api/v1/projects/{project_id}").status_code == 404
    assert developer.get("/api/v1/projects").json() == []
    r = owner.post(f"/api/v1/projects/{project_id}/members", json={"user_id": developer.user_id})
    assert r.status_code == 201
    assert developer.get(f"/api/v1/projects/{project_id}").status_code == 200
    assert len(developer.get("/api/v1/projects").json()) == 1
    # Developers cannot delete projects even when they can see them.
    assert developer.delete(f"/api/v1/projects/{project_id}").status_code == 403


def test_cross_organization_isolation(app, owner, org_id, project_id):
    # A second, completely separate tenant.
    outsider_owner = add_member(app, owner, org_id, "OWNER", email="outsider@example.com")
    r = outsider_owner.post("/api/v1/organizations", json={"name": "Other Corp"})
    assert r.status_code == 201
    other_org = r.json()["id"]
    stranger = add_member(app, outsider_owner, other_org, "ADMIN", email="stranger@example.com")
    # The stranger belongs only to Other Corp.
    assert stranger.get(f"/api/v1/projects/{project_id}").status_code == 404
    assert stranger.get(f"/api/v1/organizations/{org_id}/members").status_code == 404
    assert stranger.get(f"/api/v1/organizations/{org_id}/audit-logs").status_code == 404
    r = stranger.post("/api/v1/projects", json={"organization_id": org_id, "name": "Intrusion"})
    assert r.status_code == 404


def test_admin_cannot_grant_owner(app, owner, org_id):
    admin = add_member(app, owner, org_id, "ADMIN")
    r = admin.post(f"/api/v1/organizations/{org_id}/members", json={
        "email": "new-owner@example.com", "display_name": "N", "role": "OWNER", "initial_password": STRONG_PASSWORD,
    })
    assert r.status_code == 403


def test_last_owner_cannot_be_demoted(owner, org_id):
    members = owner.get(f"/api/v1/organizations/{org_id}/members").json()
    me = next(m for m in members if m["email"] == "owner@example.com")
    r = owner.patch(f"/api/v1/organizations/{org_id}/members/{me['membership_id']}", json={"role": "ADMIN"})
    assert r.status_code == 409


def test_api_key_lifecycle_and_scope(app, owner, org_id, project_id):
    # DEVELOPER keys must be project-scoped.
    r = owner.post(f"/api/v1/organizations/{org_id}/api-keys", json={"name": "ci", "role": "DEVELOPER"})
    assert r.status_code == 422
    r = owner.post(f"/api/v1/organizations/{org_id}/api-keys",
                   json={"name": "ci", "role": "DEVELOPER", "project_id": project_id})
    assert r.status_code == 201
    key = r.json()["key"]
    assert key.startswith("slk_")
    c = new_client(app)
    auth = {"Authorization": f"Bearer {key}"}
    assert c.get(f"/api/v1/projects/{project_id}", headers=auth).status_code == 200
    # No CSRF needed for bearer credentials, but role limits still apply.
    assert c.delete(f"/api/v1/projects/{project_id}", headers=auth).status_code == 403
    assert c.get(f"/api/v1/organizations/{org_id}/audit-logs", headers=auth).status_code == 403
    # The key never appears again.
    listed = owner.get(f"/api/v1/organizations/{org_id}/api-keys").json()
    assert all("key" not in k for k in listed)
    key_id = r.json()["id"]
    assert owner.delete(f"/api/v1/organizations/{org_id}/api-keys/{key_id}").status_code == 200
    assert c.get(f"/api/v1/projects/{project_id}", headers=auth).status_code == 401


def test_api_key_cannot_exceed_creator_role(app, owner, org_id):
    admin = add_member(app, owner, org_id, "ADMIN")
    r = admin.post(f"/api/v1/organizations/{org_id}/api-keys", json={"name": "k", "role": "OWNER"})
    assert r.status_code == 403


def test_audit_log_records_actions(owner, org_id, project_id):
    r = owner.get(f"/api/v1/organizations/{org_id}/audit-logs")
    actions = {item["action"] for item in r.json()["items"]}
    assert {"instance.bootstrap", "auth.login", "project.create"} <= actions


def test_security_headers(client):
    r = client.get("/api/v1/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_oversized_json_body_rejected(owner, org_id):
    big = "x" * (3 * 1024 * 1024)
    r = owner.post("/api/v1/projects", json={"organization_id": org_id, "name": "big", "description": big})
    assert r.status_code == 413


def test_rate_limit(monkeypatch, app):
    from securelens.core import ratelimit

    ratelimit._general = ratelimit.SlidingWindowLimiter(3)
    c = new_client(app)
    codes = [c.get("/api/v1/auth/status").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429
