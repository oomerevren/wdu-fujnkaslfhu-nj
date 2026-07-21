"""
Celery tasks for PentestAI scans.

Architecture
------------
- ``run_scan`` — Synchronous scanner workers (Nuclei, ZAP, PromptFoo).
- ``run_ai_scan`` — Async agent pipeline via ``asyncio.run()``.

The AI scan (``run_ai_scan``) uses ``asyncio.run()`` to execute the
LangGraph-based orchestrator pipeline in a **fresh** event loop on every
invocation. This avoids a subtle class of bugs where the Celery worker
process already has a running event loop (e.g. from the event bus) —
``asyncio.run()`` creates a new loop, runs the coroutine, and closes it
cleanly regardless of the surrounding context.

Progress is published via Redis pub/sub (non-critical; failures are
swallowed to avoid disrupting the scan). Scan status is persisted to
PostgreSQL through Celery's synchronous DB session.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Optional

from celery import shared_task
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded

from app.cache.redis_pool import redis_pool
from app.core.logging import logger
from app.database import SessionLocal
from app.middleware.metrics import SCAN_DURATION
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus, ScanType
from app.utils.security import decrypt_value

# ── Transient vs. permanent error classification ──────────────────────────

_TRANSIENT_ERROR_BASES = (
    ConnectionError,
    TimeoutError,
    OSError,
    BlockingIOError,
    InterruptedError,
    BrokenPipeError,
    ConnectionResetError,
    ConnectionRefusedError,
    ConnectionAbortedError,
)

_TRANSIENT_KEYWORDS = [
    "connection",
    "timeout",
    "temporary failure",
    "reset",
    "refused",
    "unreachable",
    "name resolution",
    "no route to host",
    "network is unreachable",
    "the read operation timed out",
]


def _is_transient_error(exc: Exception) -> bool:
    """Return True if *exc* is a transient error (safe to retry)."""
    if isinstance(exc, SoftTimeLimitExceeded):
        return False
    if isinstance(exc, _TRANSIENT_ERROR_BASES):
        return True
    msg = str(exc).lower()
    return any(kw in msg for kw in _TRANSIENT_KEYWORDS)


# ── Redis progress ────────────────────────────────────────────────────────


def _publish_progress(scan_id: str, progress: int, status: Optional[str] = None) -> None:
    """Publish scan progress to Redis pub/sub channel.

    The SSE endpoint subscribes to this channel for real-time updates.
    Also stores the latest progress in a Redis key for late-joining subscribers.
    Uses the shared Redis connection pool — no new TCP connection per call.
    """
    try:
        r = redis_pool.get_client()
        data = {
            "type": "progress",
            "scan_id": scan_id,
            "progress": progress,
            "status": status or "running",
        }
        r.publish(f"scan:{scan_id}:progress", json.dumps(data))
        r.setex(f"scan:{scan_id}:latest", 3600, json.dumps(data))
        r.close()
    except Exception as exc:
        logger.debug("Redis publish failed (non-critical)", extra={"scan_id": scan_id, "error": str(exc)})


# ── DB helpers ────────────────────────────────────────────────────────────


def _get_scan(scan_id: str):
    """Fetch a scan record by id; returns None if not found."""
    db = SessionLocal()
    try:
        return db.query(Scan).filter(Scan.id == scan_id).first()
    finally:
        db.close()


def _update_scan_status(
    scan_id: str,
    status: ScanStatus,
    progress: Optional[int] = None,
    error_message: Optional[str] = None,
) -> None:
    """Update scan status fields in a single DB round-trip."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.warning("Scan record not found for status update", extra={"scan_id": scan_id})
            return
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if error_message:
            scan.error_message = error_message[:500]
        if status == ScanStatus.RUNNING and not scan.started_at:
            scan.started_at = datetime.utcnow()
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            scan.completed_at = datetime.utcnow()
            if status == ScanStatus.FAILED and error_message:
                scan.error_message = error_message[:500]
        db.commit()
    except Exception as exc:
        logger.warning(
            "Failed to update scan status",
            extra={"scan_id": scan_id, "status": status.value, "error": str(exc)},
        )
    finally:
        db.close()


def _bulk_insert_findings(db, scan: Scan, findings: list[dict], target_id: str, user_id: str) -> int:
    """Insert findings via bulk_insert_mappings; returns the count."""
    if not findings:
        return 0
    mappings = []
    for f in findings:
        mappings.append({
            "scan_id": scan.id,
            "target_id": getattr(scan, "target_id", None) or target_id,
            "user_id": getattr(scan, "user_id", None) or user_id,
            "source": f.get("source_scanner", f.get("source", "ai_pipeline")),
            "template_id": f.get("template_id"),
            "name": f.get("name", "Unknown finding"),
            "severity": f.get("severity", "info"),
            "description": f.get("description"),
            "remediation": f.get("remediation"),
            "evidence": f.get("evidence"),
            "cvss_score": f.get("cvss_score"),
            "cve_id": f.get("cve_id"),
            "status": f.get("status", "open"),
        })
    db.bulk_insert_mappings(Finding, mappings)
    return len(mappings)


# ── Orchestrator runner (async → sync bridge) ────────────────────────────


def _run_orchestrator(
    scan_id: str,
    target_url: str,
    target_type: str,
    decrypted_auth: Optional[str],
    user_id: Optional[str],
    target_id: Optional[str],
) -> dict:
    """Run the PentestOrchestrator pipeline in a **fresh** event loop.

    ``asyncio.run()`` is the safest way to call async code from a sync
    Celery task:
      * It always creates a **new** event loop, so there is never a
        conflict with a pre-existing loop (event bus, etc.).
      * It properly closes the loop and all associated resources when
        the coroutine finishes, preventing memory leaks.
      * It's the recommended approach in Python 3.10+.

    Compare with the old approach that tried ``get_running_loop()`` first
    and fell back to ``new_event_loop()`` — that could crash if a loop
    was already running (``RuntimeError``) or leak resources if an old
    loop was reused.
    """
    from app.agents.orchestrator import PentestOrchestrator

    llm_client = _init_llm_client(scan_id)

    async def _pipeline() -> dict:
        orchestrator = PentestOrchestrator(llm_client=llm_client)
        return await orchestrator.run(
            target_url=target_url,
            user_id=user_id,
            target_id=target_id,
            scan_id=scan_id,
            auth_header=decrypted_auth,
            target_type=target_type,
        )

    # ── asyncio.run() — the fix ──────────────────────────────────────
    # This replaces the old pattern:
    #   try: loop = asyncio.get_running_loop()
    #   except RuntimeError: loop = asyncio.new_event_loop()
    #   loop.run_until_complete(...)
    #
    # The old pattern had two bugs:
    #   1. If Celery worker was already inside an event loop (e.g. event
    #      bus consumer), get_running_loop() succeeded but
    #      run_until_complete() would nest and potentially deadlock.
    #   2. If no loop existed, a new one was created but never closed,
    #      leaking resources across task invocations.
    return asyncio.run(_pipeline())


def _init_llm_client(scan_id: str):
    """Initialize the LLM client if OPENAI_API_KEY is configured."""
    from app.config import settings

    openai_api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not openai_api_key:
        logger.info(
            "No OPENAI_API_KEY configured, proceeding without LLM reasoning",
            extra={"scan_id": scan_id},
        )
        return None

    try:
        from langchain_openai import ChatOpenAI

        client = ChatOpenAI(
            model=getattr(settings, "OPENAI_MODEL", "gpt-4o-mini"),
            temperature=0.1,
            api_key=openai_api_key,
        )
        logger.info("LLM client initialized for AI scan", extra={"scan_id": scan_id})
        return client
    except Exception as exc:
        logger.warning(
            "Failed to initialize LLM client, proceeding without AI reasoning",
            extra={"scan_id": scan_id, "error": str(exc)},
        )
        return None


# ═══════════════════════════════════════════════════════════════════════════
# run_scan — synchronous scanner workers
# ═══════════════════════════════════════════════════════════════════════════

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_scan(self, scan_id: str):
    """Run a scan as a Celery task with retry support.

    Performance improvements:
    - Single DB session throughout (was 3 separate sessions).
    - Bulk insert for findings using bulk_insert_mappings.
    - Redis pub/sub for real-time progress updates.
    """
    from app.workers.nuclei_worker import run_nuclei_scan
    from app.workers.zap_worker import run_zap_scan
    from app.workers.promptfoo_worker import run_promptfoo_scan

    start_time = time.time()

    # ── Single DB session ──────────────────────────────────────────────
    db = SessionLocal()
    try:
        # ── Fetch scan with target ─────────────────────────────────────
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.warning("Scan bulunamadı", extra={"scan_id": scan_id})
            return

        # ── Initial state: mark as RUNNING ─────────────────────────────
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.progress = 10
        db.commit()

        # Publish progress via Redis
        _publish_progress(scan_id, 10, "running")

        # 20%: worker çağrılıyor
        _publish_progress(scan_id, 20, "running")

        # ── Decrypt auth header ────────────────────────────────────────
        # Eager-load target before session is potentially closed
        db.refresh(scan, ["target"])
        decrypted_auth_header = (
            decrypt_value(scan.target.auth_header) if scan.target.auth_header else None
        )

        # ── Run the actual scanner ─────────────────────────────────────
        if scan.scan_type == ScanType.NUCLEI:
            results = run_nuclei_scan(scan.target.url, decrypted_auth_header)
        elif scan.scan_type == ScanType.ZAP:
            results = run_zap_scan(scan.target.url, decrypted_auth_header)
        elif scan.scan_type == ScanType.PROMPTFOO:
            results = run_promptfoo_scan(scan.target.url, decrypted_auth_header)
        else:
            results = {"findings": [], "scan_summary": {"error": "Bilinmeyen tarama türü"}}

        # 80%: scanner tamam
        _publish_progress(scan_id, 80, "running")

        # ── Persist results with bulk insert ───────────────────────────
        scan.raw_results = results
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100

        findings_data = results.get("findings", [])

        # FIX: Bulk insert for findings instead of individual db.add()
        if findings_data:
            findings_mappings = []
            for f in findings_data:
                findings_mappings.append({
                    "scan_id": scan.id,
                    "target_id": scan.target_id,
                    "user_id": scan.user_id,
                    "source": scan.scan_type.value,
                    "template_id": f.get("template_id"),
                    "name": f.get("name", "Bilinmeyen bulgu"),
                    "severity": f.get("severity", "info"),
                    "description": f.get("description"),
                    "remediation": f.get("remediation"),
                    "evidence": f.get("evidence"),
                    "cvss_score": f.get("cvss_score"),
                    "cve_id": f.get("cve_id"),
                })
            db.bulk_insert_mappings(Finding, findings_mappings)

        db.commit()

        # Scan duration metric
        duration = time.time() - start_time
        SCAN_DURATION.labels(scan_type=scan.scan_type.value, status="completed").observe(duration)

        # Publish final progress
        _publish_progress(scan_id, 100, "completed")

    except Exception as e:
        db.rollback()
        logger.error(
            "Tarama sırasında hata oluştu",
            extra={"scan_id": str(scan_id), "error": str(e)},
        )
        _publish_progress(scan_id, 0, "failed")

        # Retry with exponential backoff
        countdown = self.default_retry_delay * (2**self.request.retries)
        try:
            raise self.retry(exc=e, countdown=countdown)
        except MaxRetriesExceededError:
            logger.error(
                "Max retries exceeded for scan",
                extra={"scan_id": str(scan_id)},
            )
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# run_ai_scan — async agent pipeline
# ═══════════════════════════════════════════════════════════════════════════

@shared_task(
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    acks_late=True,
    soft_time_limit=1800,   # 30 min — raises SoftTimeLimitExceeded
    time_limit=2000,         # 33 min ~10% buffer — hard kill
)
def run_ai_scan(
    self,
    scan_id: str,
    target_url: str,
    target_type: str = "web",
    auth_header: Optional[str] = None,
    user_id: Optional[str] = None,
    target_id: Optional[str] = None,
):
    """Run an AI-driven scan using the PentestOrchestrator agent pipeline.

    This task invokes the full LangGraph agent pipeline:
      1. Recon     → Analyze target, fingerprint tech stack, discover endpoints
      2. Plan      → Dynamically select optimal scanner configuration
      3. Execute   → Run selected scanners (Nuclei, ZAP, PromptFoo) in parallel
      4. Exploit   → Verify high/critical findings with PoC exploits
      5. Analyze   → Correlate findings, assign CVSS, prioritize remediation
      6. Report    → Build final structured report data

    Key differentiator: Every finding is exploit-verified — ZERO false positives.

    The pipeline auto-selects scanners based on the target's tech stack:
    - Web apps → Nuclei + ZAP (deep spider + active scan)
    - API endpoints → Nuclei + PromptFoo (LLM security)
    - LLM targets → PromptFoo focused

    **Async bridging:** Uses ``asyncio.run()`` to safely execute the async
    orchestrator from a sync Celery worker. Each invocation gets a fresh
    event loop, eliminating ``RuntimeError`` from ``get_running_loop()``
    conflicts.
    """
    start_time = time.time()
    scan_id_str = str(scan_id)

    # ── Phase 1: Mark scan as RUNNING in DB ────────────────────────────
    try:
        scan = _get_scan(scan_id_str)
        if not scan:
            logger.warning("Scan record not found", extra={"scan_id": scan_id_str})
            return

        _update_scan_status(scan_id_str, ScanStatus.RUNNING, progress=5)
        _publish_progress(scan_id_str, 5, "running")
    except Exception as exc:
        logger.error("Failed to initialize AI scan", extra={"scan_id": scan_id_str, "error": str(exc)})
        _publish_progress(scan_id_str, 0, "failed")
        return

    # ── Decrypt auth header (best-effort) ──────────────────────────────
    decrypted_auth: Optional[str] = None
    if auth_header:
        try:
            decrypted_auth = decrypt_value(auth_header)
        except Exception as exc:
            logger.warning(
                "Failed to decrypt auth header, proceeding without auth",
                extra={"scan_id": scan_id_str, "error": str(exc)},
            )

    # ── Phase 2: Run the orchestrator pipeline ─────────────────────────
    try:
        _publish_progress(scan_id_str, 10, "running")

        # asyncio.run() is the fix — see _run_orchestrator docstring
        final_state = _run_orchestrator(
            scan_id=scan_id_str,
            target_url=target_url,
            target_type=target_type,
            decrypted_auth=decrypted_auth,
            user_id=user_id,
            target_id=target_id,
        )

    except SoftTimeLimitExceeded:
        logger.error(
            "AI scan timed out after 30 minutes",
            extra={"scan_id": scan_id_str, "target_url": target_url},
        )
        _publish_progress(scan_id_str, 0, "failed")
        _update_scan_status(scan_id_str, ScanStatus.FAILED, progress=0, error_message="Task timed out after 30 minutes")
        # SoftTimeLimitExceeded is NOT retryable — task took too long
        return

    except Exception as exc:
        logger.error(
            "AI scan pipeline failed",
            extra={"scan_id": scan_id_str, "error": str(exc), "target_url": target_url},
        )
        _publish_progress(scan_id_str, 0, "failed")
        _update_scan_status(scan_id_str, ScanStatus.FAILED, progress=0, error_message=str(exc)[:500])

        # ── Retry logic: transient only ────────────────────────────────
        if _is_transient_error(exc):
            countdown = self.default_retry_delay * (2 ** self.request.retries)
            try:
                logger.info(
                    "Retrying AI scan (transient error)",
                    extra={"scan_id": scan_id_str, "retry": self.request.retries + 1, "countdown": countdown},
                )
                raise self.retry(exc=exc, countdown=countdown)
            except MaxRetriesExceededError:
                logger.error(
                    "Max retries exceeded for AI scan pipeline",
                    extra={"scan_id": scan_id_str},
                )
        else:
            logger.info(
                "Not retrying AI scan (permanent error)",
                extra={"scan_id": scan_id_str, "error_type": type(exc).__name__},
            )
        return

    # ── Phase 3: Persist results ───────────────────────────────────────
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id_str).first()
        if not scan:
            logger.warning("AI scan record disappeared before persist", extra={"scan_id": scan_id_str})
            return

        report_data = final_state.get("report_data", {})
        analyzed_findings = final_state.get("findings_analyzed", [])

        scan.raw_results = {
            "pipeline": report_data.get("pipeline", {}),
            "summary": final_state.get("analysis_summary", {}),
            "scan_plan": final_state.get("scan_plan", {}),
            "scanner_results": final_state.get("scanner_results", {}),
            "tech_stack": final_state.get("tech_stack", []),
            "attack_surface": final_state.get("attack_surface", {}),
            "remediation_priorities": final_state.get("remediation_priorities", []),
            "knowledge_graph_id": final_state.get("knowledge_graph_id"),
        }
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100

        # Bulk-insert findings
        inserted = _bulk_insert_findings(db, scan, analyzed_findings, target_id or "", user_id or "")

        db.commit()

        duration = time.time() - start_time
        SCAN_DURATION.labels(scan_type="ai_driven", status="completed").observe(duration)

        _publish_progress(scan_id_str, 100, "completed")

        logger.info(
            "AI-driven scan completed successfully",
            extra={
                "scan_id": scan_id_str,
                "target_url": target_url,
                "findings": len(analyzed_findings),
                "confirmed": sum(1 for f in analyzed_findings if f.get("exploit_verified")),
                "false_positives": sum(1 for f in analyzed_findings if f.get("status") == "false_positive"),
                "duration_seconds": round(duration, 2),
                "inserted_findings": inserted,
                "scanners_used": final_state.get("scan_plan", {}).get("scanners", []),
            },
        )

    except Exception as exc:
        db.rollback()
        logger.error(
            "Failed to persist AI scan results",
            extra={"scan_id": scan_id_str, "error": str(exc)},
        )
        _publish_progress(scan_id_str, 0, "failed")
        _update_scan_status(scan_id_str, ScanStatus.FAILED, progress=0, error_message=f"Persist error: {str(exc)[:480]}")

        # Transient errors in the persist phase are also retryable
        if _is_transient_error(exc):
            countdown = self.default_retry_delay * (2 ** self.request.retries)
            try:
                raise self.retry(exc=exc, countdown=countdown)
            except MaxRetriesExceededError:
                logger.error(
                    "Max retries exceeded for AI scan persist",
                    extra={"scan_id": scan_id_str},
                )
    finally:
        db.close()
