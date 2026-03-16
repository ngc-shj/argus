"""Repository layer for database operations."""

import json
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.logging import get_logger
from argus.database.models import ScanRecord
from argus.models import ScanOptions, ScanSession, ScanTarget
from argus.models.base import ScanStatus

logger = get_logger("repository")

_BLOB_WARN_BYTES = 10 * 1024 * 1024  # 10MB
_BLOB_LIMIT_BYTES = 50 * 1024 * 1024  # 50MB


class ScanRepository:
    """Repository for scan operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, session: ScanSession) -> ScanRecord:
        """Create a new scan record."""
        record = ScanRecord(
            id=session.id,
            target_domain=session.target.domain,
            target_ip=session.target.ip_address,
            status=session.status.value,
            created_at=session.created_at,
            started_at=session.started_at,
            completed_at=session.completed_at,
        )
        record.options = session.options.model_dump(mode="json")
        record.errors = session.errors

        self.session.add(record)
        await self.session.flush()
        return record

    async def get_by_id(self, scan_id: UUID) -> ScanRecord | None:
        """Get a scan record by ID."""
        result = await self.session.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
        return result.scalar_one_or_none()

    async def update(self, record: ScanRecord) -> ScanRecord:
        """Update a scan record."""
        self.session.add(record)
        await self.session.flush()
        return record

    async def update_from_session(self, session: ScanSession) -> ScanRecord | None:
        """Update a scan record from a ScanSession."""
        record = await self.get_by_id(session.id)
        if not record:
            return None

        record.status = session.status.value
        record.started_at = session.started_at
        record.completed_at = session.completed_at
        record.errors = session.errors

        # Store full results as JSON
        results_dict = session.to_json_dict()
        results_blob = json.dumps(results_dict, default=str)
        blob_size = len(results_blob.encode("utf-8"))

        if blob_size > _BLOB_LIMIT_BYTES:
            raise ValueError("Scan results exceed 50MB size limit")
        if blob_size > _BLOB_WARN_BYTES:
            size_mb = blob_size / (1024 * 1024)
            logger.warning("Scan results blob size exceeds 10MB (%.1fMB)", size_mb)

        record.results_json = results_blob

        self.session.add(record)
        await self.session.flush()
        return record

    async def delete(self, scan_id: UUID) -> bool:
        """Delete a scan record."""
        record = await self.get_by_id(scan_id)
        if not record:
            return False

        await self.session.delete(record)
        await self.session.flush()
        return True

    async def list_scans(
        self,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[ScanRecord], int]:
        """List scan records with optional filtering."""
        # Build query
        query = select(ScanRecord)

        if status:
            query = query.where(ScanRecord.status == status)

        # Get total count
        count_query = select(func.count()).select_from(ScanRecord)
        if status:
            count_query = count_query.where(ScanRecord.status == status)
        total_result = await self.session.execute(count_query)
        total = total_result.scalar() or 0

        # Apply ordering and pagination
        query = query.order_by(ScanRecord.created_at.desc())
        query = query.offset(offset).limit(limit)

        result = await self.session.execute(query)
        records = list(result.scalars().all())

        return records, total

    async def get_full_results(self, scan_id: UUID) -> dict | None:
        """Get full scan results as dictionary."""
        record = await self.get_by_id(scan_id)
        if not record:
            return None
        return record.results

    def record_to_session(self, record: ScanRecord) -> ScanSession:
        """Convert a database record to a ScanSession.

        Note: This only creates a minimal session for API responses.
        Full results should be retrieved via get_full_results().
        """
        options_data = record.options
        target = ScanTarget(
            domain=record.target_domain,
            ip_address=record.target_ip,
        )
        options = ScanOptions(**options_data) if options_data else ScanOptions()

        return ScanSession(
            id=record.id,
            target=target,
            options=options,
            status=ScanStatus(record.status),
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            errors=record.errors,
        )
