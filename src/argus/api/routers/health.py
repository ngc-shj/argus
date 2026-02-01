"""Health check endpoints."""

from fastapi import APIRouter

from argus.version import __version__

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": __version__,
    }


@router.get("/")
async def root() -> dict:
    """Root endpoint."""
    return {
        "name": "Argus API",
        "version": __version__,
        "docs": "/docs",
    }
