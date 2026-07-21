import asyncio
import json
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.cache.redis_pool import redis_pool
from app.database import get_db
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan, ScanType
from app.schemas.scan import ScanCreate, ScanResponse, AIScanCreate, AIScanResponse
from app.schemas.pagination import PaginatedResponse
from app.services.auth_service import get_current_user
from app.services.audit_service import log_event
from app.tasks.scan_tasks import run_scan, run_ai_scan
from app.config import settings

router = APIRouter()

SCAN_ORDER = [ScanType.NUCLEI, ScanType.ZAP, ScanType.PROMPTFOO]


# ── List scans (offset-based + cursor-based) ────────────────────────────────

@router.get("/", response_model=PaginatedResponse[ScanResponse])
def list_scans(
    target_id: Optional[UUID] = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None, description="Cursor-based pagination: pass the last scan `created_at` ISO timestamp"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List scans with optional cursor-based pagination.

    - Use `page` & `size` for offset-based pagination (legacy).
    - Use `cursor` & `size` for cursor-based pagination (preferred for large datasets).
      Pass the `created_at` ISO timestamp of the last item as `cursor`.
    """
    query = db.query(Scan).options(joinedload(Scan.target)).filter(Scan.user_id == current_user.id)
    if target_id:
        query = query.filter(Scan.target_id == target_id)

    # Cursor-based pagination
    if cursor:
        try:
            from datetime import datetime
            cursor_dt = datetime.fromisoformat(cursor)
            query = query.filter(Scan.created_at < cursor_dt)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid cursor format. Use ISO 8601 timestamp.")

    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).limit(size + 1).all()

    has_more = len(scans) > size
    scans = scans[:size]

    response = PaginatedResponse.create(items=scans, total=total, page=page if not cursor else 1, size=size)

    # Attach next cursor if more results exist
    if has_more and scans:
        next_cursor = scans[-1].created_at.isoformat()
        response_dict = response.model_dump()
        response_dict["next_cursor"] = next_cursor
        return response_dict

    return response


# ── Create scan ─────────────────────────────────────────────────────────────

@router.post("/", response_model=List[ScanResponse], status_code=201)
def create_scan(
    data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(
        Target.id == data.target_id,
        Target.user_id == current_user.id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    from app.services.usage_service import increment_scan_usage
    if not increment_scan_usage(current_user.id, db):
        raise HTTPException(status_code=402, detail="Scan limit reached. Please upgrade your plan.")

    if data.scan_type == ScanType.FULL.value:
        scan_types = SCAN_ORDER
    else:
        scan_types = [ScanType(data.scan_type)]

    created_scans = []
    for st in scan_types:
        scan = Scan(
            target_id=target.id,
            user_id=current_user.id,
            scan_type=st,
        )
        db.add(scan)
        db.flush()
        created_scans.append(scan)
        run_scan.delay(str(scan.id))

    scan_ids = [str(s.id) for s in created_scans]
    log_event(
        db,
        user_id=current_user.id,
        action="scan.created",
        resource_type="scan",
        resource_id=",".join(scan_ids),
        details={
            "target_id": str(target.id),
            "scan_types": [st.value for st in scan_types],
            "scan_ids": scan_ids,
        },
    )

    db.commit()
    for s in created_scans:
        db.refresh(s)
    return created_scans


# ── AI-Driven Scan (new) ─────────────────────────────────────────────────────

@router.post("/ai", response_model=AIScanResponse, status_code=201)
async def create_ai_scan(
    data: AIScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create an AI-driven scan that uses the full agent pipeline.

    Unlike regular scans which run fixed scanners, AI-driven scans use
    the PentestOrchestrator LangGraph pipeline:
      1. Recon — analyze target, fingerprint tech stack
      2. Plan — dynamically select optimal scanners
      3. Execute — run selected scanners in parallel
      4. Exploit — verify findings with PoC exploits (NO false positives)
      5. Analyze — correlate, CVSS score, prioritize
      6. Report — generate structured report data

    The pipeline automatically selects the best scanners based on
    the target's technology stack and attack surface.
    """
    target = db.query(Target).filter(
        Target.id == data.target_id,
        Target.user_id == current_user.id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    from app.services.usage_service import increment_scan_usage
    if not increment_scan_usage(current_user.id, db):
        raise HTTPException(
            status_code=402,
            detail="Scan limit reached. Please upgrade your plan."
        )

    # Create scan record
    scan = Scan(
        target_id=target.id,
        user_id=current_user.id,
        scan_type=ScanType.AI_DRIVEN,
    )
    db.add(scan)
    db.flush()

    log_event(
        db,
        user_id=current_user.id,
        action="ai_scan.created",
        resource_type="scan",
        resource_id=str(scan.id),
        details={
            "target_id": str(target.id),
            "target_url": target.url,
            "target_type": data.target_type,
            "scan_type": "ai_driven",
        },
    )

    db.commit()
    db.refresh(scan)

    # Dispatch Celery task for AI-driven scan
    run_ai_scan.delay(
        scan_id=str(scan.id),
        target_url=target.url,
        target_type=data.target_type,
        auth_header=target.auth_header,
        user_id=str(current_user.id),
        target_id=str(target.id),
    )

    return AIScanResponse(
        scan_id=scan.id,
        target_id=target.id,
        target_url=target.url,
        status=scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
        progress=scan.progress,
        pipeline_stage="init",
        created_at=scan.created_at,
    )


# ── Get scan progress ───────────────────────────────────────────────────────

@router.get("/{scan_id}/progress")
def get_scan_progress(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": str(scan.id),
        "status": scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
        "progress": scan.progress,
        "scan_type": scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "error_message": scan.error_message,
    }


# ── SSE endpoint with Redis pub/sub ─────────────────────────────────────────

@router.get("/{scan_id}/events")
async def scan_progress_events(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """SSE endpoint for real-time scan progress updates.

    Uses Redis pub/sub to receive progress events pushed by the Celery worker,
    instead of polling the database every second.

    Falls back to polling if Redis is unavailable.
    """
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        redis_available = False
        pubsub = None
        redis_client = None

        # Try to set up Redis pub/sub subscription
        try:
            redis_client = redis_pool.get_async_client()
            await redis_client.ping()
            channel = f"scan:{scan_id}:progress"
            pubsub = redis_client.pubsub()
            await pubsub.subscribe(channel)
            redis_available = True
        except Exception:
            logger = __import__('logging').getLogger(__name__)
            logger.warning("Redis unavailable for SSE, falling back to DB polling")

        last_progress = -1

        try:
            while True:
                if redis_available and pubsub:
                    # ── Redis pub/sub mode ──────────────────────────────
                    try:
                        message = await pubsub.get_message(
                            timeout=1.0,
                            ignore_subscribe_messages=True,
                        )
                        if message:
                            data = json.loads(message["data"])
                            yield f"data: {json.dumps(data)}\n\n"
                            if data.get("status") in ("completed", "failed"):
                                break
                            last_progress = data.get("progress", last_progress)
                            continue
                    except (asyncio.TimeoutError, json.JSONDecodeError):
                        pass

                    # Poll Redis for latest progress as fallback within pubsub mode
                    try:
                        latest = await redis_client.get(f"scan:{scan_id}:latest")
                        if latest:
                            data = json.loads(latest)
                            if data.get("progress", -1) != last_progress or data.get("status") in ("completed", "failed"):
                                yield f"data: {json.dumps(data)}\n\n"
                                last_progress = data["progress"]
                                if data.get("status") in ("completed", "failed"):
                                    break
                    except Exception:
                        pass
                else:
                    # ── Fallback: DB polling mode ───────────────────────
                    await asyncio.sleep(1)

                    from app.database import SessionLocal
                    sse_db = SessionLocal()
                    try:
                        current_scan = sse_db.query(Scan).filter(Scan.id == scan_id).first()
                        if not current_scan:
                            yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found'})}\n\n"
                            break

                        progress = current_scan.progress
                        status = (
                            current_scan.status.value
                            if hasattr(current_scan.status, "value")
                            else str(current_scan.status)
                        )

                        if progress != last_progress or status in ("completed", "failed"):
                            data = {
                                "type": "progress",
                                "scan_id": str(scan_id),
                                "progress": progress,
                                "status": status,
                            }
                            yield f"data: {json.dumps(data)}\n\n"
                            last_progress = progress

                        if status in ("completed", "failed"):
                            break
                    finally:
                        sse_db.close()

        finally:
            if pubsub:
                try:
                    await pubsub.unsubscribe(channel)
                    await pubsub.close()
                except Exception:
                    pass
            if redis_available:
                try:
                    await redis_client.aclose()
                except Exception:
                    pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
