"""Mounts every API router under /api/v1."""

from __future__ import annotations

from fastapi import APIRouter

from securelens.api import auth, findings, health, organizations, projects, retests, scans

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(projects.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(retests.router)
