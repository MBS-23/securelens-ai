"""Mounts every API router under /api/v1."""

from __future__ import annotations

from fastapi import APIRouter

from securelens.api import auth, health, organizations, projects

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(projects.router)
