"""Dashboard metrics and organization settings (risk weights, default security gate)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy.orm import Session

from securelens.api.deps import accessible_project_ids, get_principal, load_project, require_org_permission
from securelens.core import audit
from securelens.core.database import get_db
from securelens.core.errors import AppError, NotFound
from securelens.core.permissions import Permission
from securelens.core.principal import Principal
from securelens.findings import risk as risk_engine
from securelens.findings.gate import GatePolicy as EngineGatePolicy
from securelens.models import Organization
from securelens.schemas.common import APIModel
from securelens.schemas.project import GatePolicy
from securelens.services import metrics

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/summary")
def dashboard_summary(organization_id: uuid.UUID | None = Query(None), principal: Principal = Depends(get_principal),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    """Security metrics across every project the caller can see."""
    if organization_id is not None and principal.role_in(organization_id) is None:
        raise NotFound("Organization not found")
    return metrics.summary(db, accessible_project_ids(db, principal, organization_id))


@router.get("/projects/{project_id}/metrics")
def project_metrics(project_id: uuid.UUID, principal: Principal = Depends(get_principal),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    project = load_project(db, principal, project_id, Permission.FINDING_READ)
    return {**metrics.summary(db, [project.id]), **metrics.project_extras(db, project)}


# --------------------------------------------------------------- settings


class OrganizationSettingsIn(APIModel):
    risk_weights: dict[str, Any] | None = Field(default=None, description="Overrides of the SRI weights")
    reset_risk_weights: bool = False
    gate_policy: GatePolicy | None = None


def validate_risk_overrides(overrides: dict[str, Any]) -> dict[str, Any]:
    """Reject unknown weight names and out-of-range values instead of silently ignoring them."""
    defaults = risk_engine.DEFAULT_WEIGHTS
    clean: dict[str, Any] = {}
    for key, value in overrides.items():
        if key not in defaults:
            raise AppError(f"Unknown risk weight group: {key}", code="invalid_risk_weights", status_code=422)
        if key == "saturation":
            if not isinstance(value, int | float) or isinstance(value, bool) or not 1 <= value <= 10_000:
                raise AppError("saturation must be a number between 1 and 10000", code="invalid_risk_weights",
                               status_code=422)
            clean[key] = float(value)
            continue
        if not isinstance(value, dict):
            raise AppError(f"{key} must be an object of weights", code="invalid_risk_weights", status_code=422)
        group: dict[str, float] = {}
        for name, number in value.items():
            if name not in defaults[key]:
                raise AppError(f"Unknown weight {key}.{name}", code="invalid_risk_weights", status_code=422)
            if not isinstance(number, int | float) or isinstance(number, bool) or not 0 <= number <= 100:
                raise AppError(f"{key}.{name} must be a number between 0 and 100", code="invalid_risk_weights",
                               status_code=422)
            group[name] = float(number)
        clean[key] = group
    return clean


def _settings_out(org: Organization) -> dict[str, Any]:
    settings = org.settings or {}
    overrides = settings.get("risk_weights") or {}
    return {
        "risk_weights": risk_engine.merge_weights(overrides),
        "risk_overrides": overrides,
        "risk_defaults": risk_engine.DEFAULT_WEIGHTS,
        "risk_methodology": risk_engine.METHODOLOGY,
        "gate_policy": EngineGatePolicy.from_dict(settings.get("gate_policy")).as_dict(),
    }


@router.get("/organizations/{organization_id}/settings")
def get_settings_(organization_id: uuid.UUID, principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_db)) -> dict[str, Any]:
    require_org_permission(principal, organization_id, Permission.SETTINGS_READ)
    org = db.get(Organization, organization_id)
    if org is None:
        raise NotFound("Organization not found")
    return _settings_out(org)


@router.patch("/organizations/{organization_id}/settings")
def update_settings(organization_id: uuid.UUID, body: OrganizationSettingsIn,
                    principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_org_permission(principal, organization_id, Permission.SETTINGS_MANAGE)
    org = db.get(Organization, organization_id)
    if org is None:
        raise NotFound("Organization not found")
    settings = dict(org.settings or {})
    changes: dict[str, Any] = {}
    if body.reset_risk_weights:
        settings.pop("risk_weights", None)
        changes["risk_weights"] = "reset"
    elif body.risk_weights is not None:
        settings["risk_weights"] = validate_risk_overrides(body.risk_weights)
        changes["risk_weights"] = settings["risk_weights"]
    if body.gate_policy is not None:
        settings["gate_policy"] = body.gate_policy.model_dump(mode="json")
        changes["gate_policy"] = settings["gate_policy"]
    org.settings = settings
    audit.record(db, "settings.update", principal=principal, organization_id=org.id, target_type="organization",
                 target_id=org.id, details=changes)
    db.commit()
    return _settings_out(org)
