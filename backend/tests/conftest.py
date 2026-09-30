"""Shared fixtures.

Each test gets a fresh SQLite database in a temporary directory and a fresh
FastAPI app. Worker jobs are executed explicitly with ``run_jobs()`` — never
inside the API process.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

os.environ.setdefault("SECURELENS_ENVIRONMENT", "test")


@dataclass
class Account:
    email: str
    password: str
    user_id: str
    csrf: str
    client: object  # starlette TestClient with this user's cookies

    def headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf}

    def get(self, url: str, **kw):
        return self.client.get(url, **kw)

    def post(self, url: str, **kw):
        kw.setdefault("headers", {}).update(self.headers())
        return self.client.post(url, **kw)

    def patch(self, url: str, **kw):
        kw.setdefault("headers", {}).update(self.headers())
        return self.client.patch(url, **kw)

    def delete(self, url: str, **kw):
        kw.setdefault("headers", {}).update(self.headers())
        return self.client.delete(url, **kw)


@pytest.fixture()
def settings_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SECURELENS_ENVIRONMENT", "test")
    monkeypatch.setenv("SECURELENS_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("SECURELENS_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("SECURELENS_SECRET_KEY", "test-secret-key-" + "x" * 40)
    monkeypatch.setenv("SECURELENS_OSV_ENABLED", "false")
    monkeypatch.setenv("SECURELENS_AI_PROVIDER", "none")
    monkeypatch.setenv("SECURELENS_EXTERNAL_SCANNERS", "")
    monkeypatch.setenv("SECURELENS_RATE_LIMIT_PER_MINUTE", "100000")
    monkeypatch.setenv("SECURELENS_LOGIN_RATE_LIMIT_PER_MINUTE", "1000")
    from securelens.core.config import reset_settings_cache
    from securelens.core.ratelimit import reset_limiters

    reset_settings_cache()
    reset_limiters()
    return tmp_path


@pytest.fixture()
def app(settings_env: Path):
    from securelens.core import database
    from securelens.main import create_app
    from securelens.models import Base

    database.configure()
    Base.metadata.create_all(database.get_engine())
    application = create_app()
    yield application
    database.get_engine().dispose()


@pytest.fixture()
def client(app) -> Iterator:
    from fastapi.testclient import TestClient

    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def db(app):
    from securelens.core.database import session_factory

    session = session_factory()()
    yield session
    session.close()


def new_client(app):
    from fastapi.testclient import TestClient

    return TestClient(app, base_url="https://testserver")


STRONG_PASSWORD = "Correct-Horse-Battery-42"


def login(app, email: str, password: str = STRONG_PASSWORD) -> Account:
    c = new_client(app)
    r = c.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    data = r.json()
    return Account(email=email, password=password, user_id=data["user"]["id"], csrf=data["csrf_token"], client=c)


@pytest.fixture()
def owner(app) -> Account:
    c = new_client(app)
    r = c.post("/api/v1/auth/bootstrap", json={
        "email": "owner@example.com", "display_name": "Olivia Owner", "password": STRONG_PASSWORD,
        "organization_name": "Acme Security",
    })
    assert r.status_code == 201, r.text
    data = r.json()
    return Account(email="owner@example.com", password=STRONG_PASSWORD, user_id=data["user"]["id"],
                   csrf=data["csrf_token"], client=c)


@pytest.fixture()
def org_id(owner: Account) -> str:
    r = owner.get("/api/v1/auth/me")
    return r.json()["memberships"][0]["organization_id"]


def add_member(app, owner: Account, org_id: str, role: str, email: str | None = None) -> Account:
    email = email or f"{role.lower()}-{uuid.uuid4().hex[:6]}@example.com"
    r = owner.post(f"/api/v1/organizations/{org_id}/members", json={
        "email": email, "display_name": role.title(), "role": role, "initial_password": STRONG_PASSWORD,
    })
    assert r.status_code == 201, r.text
    return login(app, email)


@pytest.fixture()
def project_id(owner: Account, org_id: str) -> str:
    r = owner.post("/api/v1/projects", json={"organization_id": org_id, "name": "Payments API"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def run_jobs(max_jobs: int = 50) -> int:
    """Drain the job queue the way the worker does (in-process for tests)."""
    from securelens.worker.runner import process_available_jobs

    return process_available_jobs(worker_id="pytest", max_jobs=max_jobs, sandbox=False)
