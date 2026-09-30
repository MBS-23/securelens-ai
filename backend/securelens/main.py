"""FastAPI application factory."""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from securelens.api.router import api_router
from securelens.core import database
from securelens.core.config import get_settings
from securelens.core.errors import error_body, install_error_handlers
from securelens.core.ratelimit import client_ip, general_limiter
from securelens.version import __version__

log = logging.getLogger("securelens")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Upload endpoints stream and enforce their own, larger limit.
_STREAMING_UPLOAD_SUFFIXES = ("/uploads", "/retests/upload")
_JSON_BODY_LIMIT = 2 * 1024 * 1024
_IMPORT_BODY_LIMIT = 32 * 1024 * 1024

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.configure()
    settings = get_settings()
    if settings.uses_insecure_default_key:
        log.warning("SECURELENS_SECRET_KEY is using the insecure development default")
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SecureLens AI",
        description="AI-Powered Application & LLM Security Testing Platform",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    install_error_handlers(app)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
        )

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        supplied = request.headers.get("x-request-id", "")
        request.state.request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
        path = request.url.path

        if path.startswith("/api/") and not path.endswith(("/healthz", "/readyz")):
            allowed, retry_after = general_limiter().hit(f"ip:{client_ip(request)}")
            if not allowed:
                return JSONResponse(error_body(request, "rate_limited", "Too many requests"), status_code=429,
                                    headers={"Retry-After": str(int(retry_after) + 1)})

        length = request.headers.get("content-length")
        if length is None and "chunked" in request.headers.get("transfer-encoding", "").lower():
            # Size limits are enforced on Content-Length; unbounded chunked bodies are refused.
            return JSONResponse(error_body(request, "length_required", "Content-Length is required"),
                                status_code=411)
        if path.endswith(_STREAMING_UPLOAD_SUFFIXES) and request.method == "POST":
            # Multipart bodies are spooled to disk before the endpoint runs, so bound them up front.
            limit = settings.max_upload_mb * 1024 * 1024 + 1024 * 1024
            if length is None:
                return JSONResponse(error_body(request, "length_required", "Content-Length is required"),
                                    status_code=411)
            try:
                too_big = int(length) > limit
            except ValueError:
                too_big = True
            if too_big:
                return JSONResponse(error_body(request, "payload_too_large",
                                               f"Upload exceeds the limit of {settings.max_upload_mb} MB"),
                                    status_code=413)
        elif length is not None:
            limit = _IMPORT_BODY_LIMIT if path.endswith("/scans/import") else _JSON_BODY_LIMIT
            try:
                too_big = int(length) > limit
            except ValueError:
                too_big = True
            if too_big:
                return JSONResponse(error_body(request, "payload_too_large", "Request body too large"),
                                    status_code=413)

        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
            if path not in ("/api/docs",):
                response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    app.include_router(api_router)
    return app


app = create_app()
