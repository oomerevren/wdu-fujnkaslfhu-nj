from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import text
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.models.user import User
from app.models.finding import Finding, FindingStatus, Severity
from app.schemas.finding import FindingResponse, FindingStatusUpdate
from app.schemas.pagination import PaginatedResponse
from app.services.auth_service import get_current_user
from app.services.audit_service import log_event

router = APIRouter()

# ── Performance indexes (applied in migration 263319850224) ──────────────
# The following indexes were added via migration 263319850224_add_performance_indexes
# using CREATE INDEX CONCURRENTLY for zero-downtime production deploys.
#
#   ix_findings_user_severity_scan
#     ON findings (user_id, severity, scan_id, created_at DESC)
#     → Covers the filtered+ordered list_findings query in a single index scan.
#
#   ix_findings_scan_id  ON findings (scan_id)
#     → Accelerates scan → findings joins.
#
#   ix_findings_target_id  ON findings (target_id)
#     → Accelerates target → findings joins.
#
# For the scans and targets tables, the following indexes were also enhanced:
#   ix_scans_user_target  ON scans (user_id, target_id, created_at DESC)
#   ix_targets_user_id    ON targets (user_id, created_at DESC)

COMPOSITE_INDEX_HINT = """
-- Performance indexes for findings queries (migration 263319850224):
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_user_severity_scan
    ON findings (user_id, severity, scan_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_scan_id ON findings (scan_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_target_id ON findings (target_id);
"""


@router.get("/", response_model=PaginatedResponse[FindingResponse])
def list_findings(
    scan_id: Optional[UUID] = None,
    target_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List findings with optional filters.

    Performance: Uses joinedload for scan/target relationships to avoid N+1 queries.
    The composite index ix_findings_user_severity_scan covers the common filter/sort pattern.
    """
    query = (
        db.query(Finding)
        .options(
            joinedload(Finding.scan),
            joinedload(Finding.target),
        )
        .filter(Finding.user_id == current_user.id)
    )
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if target_id:
        query = query.filter(Finding.target_id == target_id)
    if severity:
        query = query.filter(Finding.severity == severity)

    total = query.count()
    findings = (
        query.order_by(Finding.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )
    return PaginatedResponse.create(items=findings, total=total, page=page, size=size)


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a single finding by ID.

    Performance: Uses joinedload for scan/target relationships.
    """
    finding = (
        db.query(Finding)
        .options(
            joinedload(Finding.scan),
            joinedload(Finding.target),
        )
        .filter(
            Finding.id == finding_id,
            Finding.user_id == current_user.id
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    finding_id: UUID,
    data: FindingStatusUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update a finding's status with audit logging."""
    # 1. Finding'i bul (user_id ile kısıtla)
    finding = (
        db.query(Finding)
        .options(
            joinedload(Finding.scan),
            joinedload(Finding.target),
        )
        .filter(
            Finding.id == finding_id,
            Finding.user_id == current_user.id
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # 2. Status değerini doğrula (FindingStatus enum'ında mı?)
    try:
        new_status = FindingStatus(data.status)
    except ValueError:
        valid_values = [s.value for s in FindingStatus]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status: '{data.status}'. Valid values: {', '.join(valid_values)}"
        )

    # 3. Eski status'u sakla, ardından güncelle
    old_status = finding.status
    finding.status = new_status

    # 4. Audit log'a kaydet
    log_event(
        db,
        user_id=current_user.id,
        action="finding.status_updated",
        resource_type="finding",
        resource_id=str(finding.id),
        details={
            "old_status": old_status.value if hasattr(old_status, "value") else str(old_status),
            "new_status": new_status.value if hasattr(new_status, "value") else str(new_status),
            "comment": data.comment,
        },
    )

    db.commit()
    db.refresh(finding)

    # 5. Döndür
    return finding


@router.get("/stats")
def get_finding_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get finding severity distribution stats for the current user."""
    from sqlalchemy import func

    stats = db.query(
        Finding.severity,
        func.count(Finding.id)
    ).filter(Finding.user_id == current_user.id).group_by(Finding.severity).all()

    # Format results
    result = {s.value: 0 for s in Severity}
    for severity_enum, count in stats:
        result[severity_enum.value] = count

    return {
        "severity_distribution": result,
        "total_findings": sum(result.values())
    }
