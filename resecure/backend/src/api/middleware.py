"""
CalmStacks ReSecure API Tier - Security Guardrails & Exception Handling Middleware
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.api.middleware
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from typing import Any, Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..core.manifest import ManifestTamperedError
from ..core.reedsolomon import (
    IntegrityInvariantError,
    NonDestructiveViolationError,
    RedundancyExceededError,
)
from ..services.protection_service import PayloadTooLargeError

logger = logging.getLogger("resecure.api.middleware")


def get_current_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class PathTraversalGuardMiddleware(BaseHTTPMiddleware):
    """
    Guards API endpoints against path traversal attacks.
    Inspects URL query parameters and JSON request bodies for '..', null bytes, or directory escapes.
    """

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        # Check query parameters
        for key, value in request.query_params.items():
            if ".." in value or "\x00" in value:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error_code": "ERR_PATH_TRAVERSAL",
                        "message": "Security Error: Illegal path traversal sequence detected in query parameter.",
                        "timestamp": get_current_timestamp(),
                        "details": {"parameter": key, "value": value},
                    },
                )

        # Check JSON request body if present
        if request.method in ("POST", "PUT", "PATCH") and "application/json" in request.headers.get("content-type", ""):
            body_bytes = await request.body()
            if body_bytes:
                try:
                    body_json = json.loads(body_bytes.decode("utf-8"))
                    if isinstance(body_json, dict):
                        for field, val in body_json.items():
                            if isinstance(val, str) and (".." in val or "\x00" in val):
                                return JSONResponse(
                                    status_code=400,
                                    content={
                                        "error_code": "ERR_PATH_TRAVERSAL",
                                        "message": "Security Error: Illegal path traversal sequence detected in request payload.",
                                        "timestamp": get_current_timestamp(),
                                        "details": {"field": field, "value": val},
                                    },
                                )
                except Exception:
                    pass

                # Reconstruct request receive stream for downstream handlers
                async def receive() -> dict[str, Any]:
                    return {"type": "http.request", "body": body_bytes}

                request = Request(request.scope, receive=receive)

        return await call_next(request)


def register_exception_handlers(app: Any) -> None:
    """Registers standard HTTP exception handlers conforming to contracts/resecure/api.yaml."""

    @app.exception_handler(ManifestTamperedError)
    async def manifest_tampered_handler(request: Request, exc: ManifestTamperedError) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "error_code": "ERR_MANIFEST_TAMPERED",
                "message": str(exc),
                "timestamp": get_current_timestamp(),
                "details": None,
            },
        )

    @app.exception_handler(RedundancyExceededError)
    async def redundancy_exceeded_handler(request: Request, exc: RedundancyExceededError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error_code": "ERR_EXCEEDS_REDUNDANCY",
                "verdict": "UNRECOVERABLE_EXACT",
                "message": str(exc),
                "damaged_chunks_count": exc.damaged_count,
                "parity_chunks_available": exc.parity_available,
                "deficit": exc.deficit,
                "damaged_indices": exc.damaged_indices,
                "safe_action_taken": "No files written to output destination. Temporary buffers purged.",
            },
        )

    @app.exception_handler(PayloadTooLargeError)
    async def payload_too_large_handler(request: Request, exc: PayloadTooLargeError) -> JSONResponse:
        return JSONResponse(
            status_code=413,
            content={
                "error_code": "ERR_PAYLOAD_TOO_LARGE",
                "message": str(exc),
                "timestamp": get_current_timestamp(),
                "details": None,
            },
        )

    @app.exception_handler(FileNotFoundError)
    async def file_not_found_handler(request: Request, exc: FileNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={
                "error_code": "ERR_FILE_NOT_FOUND",
                "message": str(exc),
                "timestamp": get_current_timestamp(),
                "details": None,
            },
        )

    @app.exception_handler(NonDestructiveViolationError)
    async def non_destructive_handler(request: Request, exc: NonDestructiveViolationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error_code": "ERR_NON_DESTRUCTIVE_VIOLATION",
                "message": str(exc),
                "timestamp": get_current_timestamp(),
                "details": None,
            },
        )

    @app.exception_handler(IntegrityInvariantError)
    async def integrity_invariant_handler(request: Request, exc: IntegrityInvariantError) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error_code": "ERR_INTEGRITY_VIOLATION",
                "message": str(exc),
                "timestamp": get_current_timestamp(),
                "details": None,
            },
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error_code": "ERR_BAD_REQUEST",
                "message": str(exc),
                "timestamp": get_current_timestamp(),
                "details": None,
            },
        )
