"""Consistent, non-leaky error responses.

Clients receive ``{"error": {"code", "message", "request_id"}}``. Stack traces
and — importantly — the *values* submitted in an invalid request (which may be
passwords or tokens) are never echoed back.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("securelens.errors")


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        self.details = details or {}


class NotFound(AppError):
    status_code = 404
    code = "not_found"


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"


class Unauthorized(AppError):
    status_code = 401
    code = "unauthorized"


class Conflict(AppError):
    status_code = 409
    code = "conflict"


class ServiceUnavailable(AppError):
    status_code = 503
    code = "unavailable"


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def error_body(request: Request, code: str, message: str, details: dict[str, Any] | None = None) -> dict:
    body: dict[str, Any] = {"code": code, "message": message, "request_id": _request_id(request)}
    if details:
        body["details"] = details
    return {"error": body}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(error_body(request, exc.code, exc.message, exc.details), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [
            {"location": [str(p) for p in err.get("loc", [])], "message": err.get("msg", "invalid")}
            for err in exc.errors()
        ]
        return JSONResponse(
            error_body(request, "validation_error", "The request is invalid", {"problems": problems[:50]}),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed",
                413: "payload_too_large", 429: "rate_limited"}.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(error_body(request, code, message), status_code=exc.status_code,
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"request_id": _request_id(request)})
        return JSONResponse(error_body(request, "internal_error", "An internal error occurred"), status_code=500)
