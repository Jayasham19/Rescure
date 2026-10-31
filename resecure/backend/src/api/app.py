"""
CalmStacks ReSecure Application Factory
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.api.app
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..db.schema import init_db
from .middleware import PathTraversalGuardMiddleware, register_exception_handlers
from .routes import router

logger = logging.getLogger("resecure.api.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle manager."""
    logger.info("Initializing ReSecure SQLite schema...")
    init_db()
    logger.info("ReSecure Core Engine initialized and operational.")
    yield
    logger.info("ReSecure Core Engine shutting down.")


def create_app() -> FastAPI:
    """Creates and configures the FastAPI application instance."""
    app = FastAPI(
        title="ReSecure Core REST API",
        version="1.0.0",
        description=(
            "Cryptographic file integrity verification, HMAC-SHA256 manifest authentication, "
            "Reed-Solomon GF(2^8) exact file recovery, and deep format validation."
        ),
        lifespan=lifespan,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Path Traversal Guard Middleware
    app.add_middleware(PathTraversalGuardMiddleware)

    # Register Global Exception Handlers
    register_exception_handlers(app)

    # Include API Router
    app.include_router(router)

    return app


app = create_app()
