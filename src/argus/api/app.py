"""FastAPI application."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from argus.api.routers import scans, health
from argus.core.config import get_settings
from argus.core.logging import setup_logging
from argus.version import __version__


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler."""
    from argus.database import init_db, close_db

    setup_logging()

    # Initialize database
    await init_db()

    yield

    # Close database connection
    await close_db()


app = FastAPI(
    title="Argus API",
    description="Argus - The all-seeing eye for your security",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware - configured via CORS_ORIGINS environment variable
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(scans.router, prefix="/api/v1", tags=["Scans"])
