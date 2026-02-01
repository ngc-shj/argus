"""Scan API endpoints."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from argus.database import get_session, ScanRepository
from argus.models import ScanTarget, ScanOptions, ScanSession
from argus.models.base import ScanStatus
from argus.orchestration.coordinator import ScanCoordinator


router = APIRouter()


class ScanTargetInput(BaseModel):
    """Target input for scan request."""

    domain: str | None = Field(default=None, examples=["example.com"])
    ip_address: str | None = Field(default=None, examples=["192.168.1.1"])


class ScanOptionsInput(BaseModel):
    """Scan options input."""

    dns_enabled: bool = True
    dns_subdomain_enum: bool = True
    whois_enabled: bool = True
    rdap_enabled: bool = True
    port_scan_enabled: bool = True
    port_scan_profile: Literal["top_20", "top_100", "top_1000"] = "top_100"
    webtech_enabled: bool = True
    ai_analysis_enabled: bool = False
    ai_provider: Literal["anthropic", "openai", "ollama"] = "anthropic"
    output_language: str = "en"


class CreateScanRequest(BaseModel):
    """Request to create a new scan."""

    target: ScanTargetInput
    options: ScanOptionsInput | None = None


class ScanResponse(BaseModel):
    """Scan response model."""

    id: UUID
    target: str
    status: ScanStatus
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    errors: list[str] = []

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """List of scans response."""

    items: list[ScanResponse]
    total: int


@router.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    request: CreateScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    """
    Create and start a new reconnaissance scan.

    The scan runs in the background. Use GET /scans/{scan_id} to check status.
    """
    try:
        target = ScanTarget(
            domain=request.target.domain,
            ip_address=request.target.ip_address,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

    options_input = request.options or ScanOptionsInput()
    options = ScanOptions(
        dns_enabled=options_input.dns_enabled,
        dns_subdomain_enum=options_input.dns_subdomain_enum,
        whois_enabled=options_input.whois_enabled,
        rdap_enabled=options_input.rdap_enabled,
        port_scan_enabled=options_input.port_scan_enabled,
        port_scan_profile=options_input.port_scan_profile,
        webtech_enabled=options_input.webtech_enabled,
        ai_analysis_enabled=options_input.ai_analysis_enabled,
        ai_provider=options_input.ai_provider,
        output_language=options_input.output_language,
    )

    # Create session
    session = ScanSession(
        target=target,
        options=options,
        status=ScanStatus.PENDING,
    )

    # Store in database
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        await repo.create(session)

    # Run scan in background
    background_tasks.add_task(_run_scan, session.id)

    return ScanResponse(
        id=session.id,
        target=target.identifier,
        status=session.status,
        created_at=session.created_at.isoformat(),
        started_at=session.started_at.isoformat() if session.started_at else None,
        completed_at=session.completed_at.isoformat() if session.completed_at else None,
        duration_seconds=session.duration_seconds,
        errors=session.errors,
    )


async def _run_scan(scan_id: UUID) -> None:
    """Run scan in background."""
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        record = await repo.get_by_id(scan_id)
        if not record:
            return

        session = repo.record_to_session(record)

    coordinator = ScanCoordinator()
    result = await coordinator.run_scan(session.target, session.options)

    # Update database with results
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        await repo.update_from_session(result)


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    status: ScanStatus | None = None,
    limit: int = 20,
    offset: int = 0,
) -> ScanListResponse:
    """List all scans with optional filtering."""
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        status_str = status.value if status else None
        records, total = await repo.list_scans(
            status=status_str,
            limit=limit,
            offset=offset,
        )

        return ScanListResponse(
            items=[
                ScanResponse(
                    id=r.id,
                    target=r.target_identifier,
                    status=ScanStatus(r.status),
                    created_at=r.created_at.isoformat() if r.created_at else "",
                    started_at=r.started_at.isoformat() if r.started_at else None,
                    completed_at=r.completed_at.isoformat() if r.completed_at else None,
                    duration_seconds=r.duration_seconds,
                    errors=r.errors,
                )
                for r in records
            ],
            total=total,
        )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: UUID) -> ScanResponse:
    """Get scan details by ID."""
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        record = await repo.get_by_id(scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResponse(
            id=record.id,
            target=record.target_identifier,
            status=ScanStatus(record.status),
            created_at=record.created_at.isoformat() if record.created_at else "",
            started_at=record.started_at.isoformat() if record.started_at else None,
            completed_at=record.completed_at.isoformat() if record.completed_at else None,
            duration_seconds=record.duration_seconds,
            errors=record.errors,
        )


@router.get("/scans/{scan_id}/results")
async def get_scan_results(scan_id: UUID) -> dict:
    """Get complete scan results."""
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        results = await repo.get_full_results(scan_id)
        if results is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        return results


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: UUID) -> None:
    """Delete a scan."""
    async with get_session() as db_session:
        repo = ScanRepository(db_session)
        deleted = await repo.delete(scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Scan not found")
