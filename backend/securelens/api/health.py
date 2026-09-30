"""Liveness, readiness and platform capability status."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from securelens.api.deps import get_principal
from securelens.core.config import get_settings
from securelens.core.database import get_db
from securelens.core.principal import Principal
from securelens.version import __version__

router = APIRouter(tags=["system"])


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready"}


@router.get("/system/status")
def system_status(_: Principal = Depends(get_principal)) -> dict:
    """What this deployment can do — shown in the UI so nothing pretends to work."""
    from securelens.ai.providers import provider_status
    from securelens.scanners.external import external_scanner_status

    settings = get_settings()
    return {
        "version": __version__,
        "environment": settings.environment,
        "ai": provider_status(),
        "dependency_intelligence": {
            "osv_enabled": settings.osv_enabled,
            "osv_api_url": settings.osv_api_url if settings.osv_enabled else None,
            "offline_database": str(settings.advisory_db_dir) if settings.advisory_db_dir else None,
        },
        "external_scanners": external_scanner_status(settings.external_scanners),
        "limits": {
            "max_upload_mb": settings.max_upload_mb,
            "max_extracted_mb": settings.max_extracted_mb,
            "max_files": settings.max_files,
            "max_file_kb": settings.max_file_kb,
            "scan_timeout_seconds": settings.scan_timeout_seconds,
        },
        "git_allowed_hosts": settings.git_allowed_hosts,
        "insecure_default_key": settings.uses_insecure_default_key,
    }
