"""Authentication endpoints: first-run bootstrap, login, logout, current user."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from securelens.api.deps import CSRF_COOKIE, SESSION_COOKIE, get_principal, get_user_principal
from securelens.core.config import get_settings
from securelens.core.database import get_db
from securelens.core.errors import AppError
from securelens.core.principal import Principal, load_roles
from securelens.core.ratelimit import client_ip, login_limiter
from securelens.core.security import csrf_token_for
from securelens.schemas.common import Message
from securelens.schemas.identity import (
    BootstrapIn,
    ChangePasswordIn,
    LoginIn,
    LoginOut,
    MeOut,
    UserOut,
)
from securelens.services import identity

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookies(response: Response, token: str, csrf: str, max_age: int) -> None:
    secure = get_settings().cookie_secure
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True, secure=secure,
                        samesite="strict", path="/api")
    # Readable by the SPA so it can echo the value in the X-CSRF-Token header.
    response.set_cookie(CSRF_COOKIE, csrf, max_age=max_age, httponly=False, secure=secure,
                        samesite="strict", path="/")


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/api")
    response.delete_cookie(CSRF_COOKIE, path="/")


def _throttle_login(request: Request) -> None:
    allowed, retry_after = login_limiter().hit(f"login:{client_ip(request)}")
    if not allowed:
        raise AppError("Too many login attempts. Try again later.", code="rate_limited", status_code=429,
                       details={"retry_after_seconds": int(retry_after) + 1})


@router.get("/status")
def instance_status(db: Session = Depends(get_db)) -> dict:
    """Whether the instance still needs its first owner account."""
    return {"initialised": identity.users_exist(db)}


@router.post("/bootstrap", response_model=LoginOut, status_code=201)
def bootstrap(body: BootstrapIn, request: Request, response: Response, db: Session = Depends(get_db)) -> LoginOut:
    _throttle_login(request)
    ip = client_ip(request)
    identity.bootstrap(db, email=str(body.email), display_name=body.display_name, password=body.password,
                       organization_name=body.organization_name, bootstrap_token=body.bootstrap_token, ip=ip)
    result = identity.login(db, email=str(body.email), password=body.password, ip=ip,
                            user_agent=request.headers.get("user-agent"))
    return _login_response(db, result, response)


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> LoginOut:
    _throttle_login(request)
    result = identity.login(db, email=body.email, password=body.password, ip=client_ip(request),
                            user_agent=request.headers.get("user-agent"))
    return _login_response(db, result, response)


def _login_response(db: Session, result: identity.LoginResult, response: Response) -> LoginOut:
    settings = get_settings()
    _set_session_cookies(response, result.token, result.csrf_token, settings.session_ttl_minutes * 60)
    principal = Principal(user=result.user, api_key=None, session=result.session,
                          roles=load_roles(db, result.user.id))
    return LoginOut(
        user=UserOut.model_validate(result.user),
        memberships=identity.memberships_for(db, principal),
        csrf_token=result.csrf_token,
        expires_at=result.session.expires_at,
    )


@router.post("/logout", response_model=Message)
def logout(response: Response, principal: Principal = Depends(get_user_principal),
           db: Session = Depends(get_db)) -> Message:
    identity.logout(db, principal)
    _clear_session_cookies(response)
    return Message(message="Signed out")


@router.get("/me", response_model=MeOut)
def me(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> MeOut:
    return MeOut(
        user=UserOut.model_validate(principal.user) if principal.user else None,
        api_key_prefix=principal.api_key.prefix if principal.api_key else None,
        memberships=identity.memberships_for(db, principal),
        csrf_token=csrf_token_for(principal.session.token_hash) if principal.session else None,
    )


@router.post("/change-password", response_model=Message)
def change_password(body: ChangePasswordIn, principal: Principal = Depends(get_user_principal),
                    db: Session = Depends(get_db)) -> Message:
    identity.change_password(db, principal, current=body.current_password, new=body.new_password)
    return Message(message="Password changed. Other sessions were signed out.")
