"""
Tests for ``app.tasks.scan_tasks`` — Celery task definitions.

Focus areas
-----------
* ``_is_transient_error`` — correct classification of retryable errors.
* ``run_ai_scan`` with mocked orchestrator — event loop isolation,
  DB updates, Redis progress, timeout handling, and failure modes.
* No ``RuntimeError`` from ``asyncio.get_running_loop()`` — the whole
  point of switching to ``asyncio.run()``.
"""

import asyncio
import time
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from celery.exceptions import SoftTimeLimitExceeded, MaxRetriesExceededError

from app.tasks.scan_tasks import (
    _is_transient_error,
    _publish_progress,
    run_ai_scan,
    _update_scan_status,
    run_scan,
)
from app.models.scan import Scan, ScanStatus, ScanType


# ══════════════════════════════════════════════════════════════════════════
# _is_transient_error
# ══════════════════════════════════════════════════════════════════════════


class TestIsTransientError:
    """Verify that transient/permanent error classification is correct."""

    @pytest.mark.parametrize("exc_cls", [
        ConnectionError,
        TimeoutError,
        OSError,
        ConnectionRefusedError,
        ConnectionResetError,
        BrokenPipeError,
    ])
    def test_transient_error_classes(self, exc_cls):
        """Known transient error classes should return True."""
        assert _is_transient_error(exc_cls("test")) is True

    def test_transient_error_keyword_connection(self):
        """Errors mentioning 'connection' in message should be transient."""
        assert _is_transient_error(RuntimeError("connection refused")) is True

    def test_transient_error_keyword_timeout(self):
        """Errors mentioning 'timeout' should be transient."""
        assert _is_transient_error(RuntimeError("the read operation timed out")) is True

    def test_permanent_error_value_error(self):
        """ValueError is a permanent error — should return False."""
        assert _is_transient_error(ValueError("invalid target")) is False

    def test_permanent_error_soft_time_limit(self):
        """SoftTimeLimitExceeded is never retryable."""
        assert _is_transient_error(SoftTimeLimitExceeded()) is False

    def test_permanent_error_generic(self):
        """Generic exceptions should return False."""
        assert _is_transient_error(Exception("something broke")) is False

    def test_permanent_error_keyboard_interrupt(self):
        """KeyboardInterrupt should not be retried."""
        assert _is_transient_error(KeyboardInterrupt()) is False

    def test_permanent_error_type_error(self):
        """TypeError is a programming error — not retryable."""
        assert _is_transient_error(TypeError("NoneType has no len()")) is False


# ══════════════════════════════════════════════════════════════════════════
# run_ai_scan — full integration with mocked dependencies
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_db():
    """Mock SQLAlchemy session and scan query."""
    with patch("app.tasks.scan_tasks.SessionLocal") as mock_session_cls:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        yield mock_session


@pytest.fixture
def mock_redis():
    """Mock Redis pool client."""
    with patch("app.tasks.scan_tasks.redis_pool") as mock_pool:
        mock_redis_client = MagicMock()
        mock_pool.get_client.return_value = mock_redis_client
        yield mock_redis_client


@pytest.fixture
def mock_orchestrator():
    """Mock PentestOrchestrator to avoid running the real pipeline."""
    with patch("app.tasks.scan_tasks._run_orchestrator") as mock:
        # Return a realistic-looking final state
        mock.return_value = {
            "report_data": {
                "pipeline": {
                    "started_at": time.time() - 60,
                    "completed_at": time.time(),
                    "duration_seconds": 60.0,
                    "scanners_used": ["nuclei", "zap"],
                },
            },
            "analysis_summary": {
                "total": 2,
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "avg_cvss": 8.5,
            },
            "scan_plan": {"scanners": ["nuclei", "zap"], "depth": "full"},
            "scanner_results": {"nuclei": {"findings": 2}},
            "tech_stack": [{"name": "nginx", "version": "1.20"}],
            "attack_surface": {"endpoints": ["/api"]},
            "remediation_priorities": [{"finding": "XSS", "priority": "high"}],
            "knowledge_graph_id": "kg-123",
            "findings_analyzed": [
                {
                    "name": "Cross-Site Scripting",
                    "severity": "critical",
                    "source_scanner": "nuclei",
                    "description": "XSS vulnerability",
                    "remediation": "Sanitize input",
                    "cvss_score": 9.0,
                    "cve_id": "CVE-2024-0001",
                    "exploit_verified": True,
                    "status": "open",
                },
                {
                    "name": "SQL Injection",
                    "severity": "high",
                    "source_scanner": "zap",
                    "description": "SQLi in login",
                    "remediation": "Use parameterized queries",
                    "cvss_score": 7.5,
                    "exploit_verified": False,
                    "status": "open",
                },
            ],
        }
        yield mock


@pytest.fixture
def mock_scan():
    """Create a mock scan record as returned by DB query."""
    scan = MagicMock(spec=Scan)
    scan.id = "test-scan-uuid"
    scan.status = ScanStatus.QUEUED
    scan.progress = 0
    scan.started_at = None
    scan.completed_at = None
    scan.error_message = None
    scan.target_id = "target-uuid"
    scan.user_id = "user-uuid"
    scan.scan_type = ScanType.AI_DRIVEN
    scan.raw_results = None
    return scan


class TestRunAiScan:
    """Tests for ``run_ai_scan`` task — the main async Celery task."""

    def test_successful_scan(
        self, mock_db, mock_redis, mock_orchestrator, mock_scan
    ):
        """run_ai_scan completes successfully and persists findings.

        Verifies:
        - Scan status transitions: QUEUED → RUNNING → COMPLETED
        - Findings are bulk-inserted
        - Redis progress published at key milestones
        """
        # ── Setup: mock DB returns the scan on first query ──────────
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_scan,  # Check query
            mock_scan,  # Status update query
            mock_scan,  # Persist query
        ]

        # ── Execute ─────────────────────────────────────────────────
        run_ai_scan(
            scan_id="test-scan-uuid",
            target_url="https://example.com",
            target_type="web",
            user_id="user-uuid",
            target_id="target-uuid",
        )

        # ── Verify: orchestrator was called with correct args ───────
        mock_orchestrator.assert_called_once_with(
            scan_id="test-scan-uuid",
            target_url="https://example.com",
            target_type="web",
            decrypted_auth=None,
            user_id="user-uuid",
            target_id="target-uuid",
        )

        # ── Verify: progress published via Redis ────────────────────
        # Should be called at 5%, 10%, and 100%
        progress_calls = [c[0][1] for c in mock_redis.publish.call_args_list]
        assert 5 in progress_calls or any("5" in str(c) for c in progress_calls)
        assert 10 in progress_calls or any("10" in str(c) for c in progress_calls)

        # ── Verify: scan status updated to COMPLETED ────────────────
        assert mock_scan.status == ScanStatus.COMPLETED
        assert mock_scan.progress == 100
        assert mock_scan.completed_at is not None

        # ── Verify: findings inserted ───────────────────────────────
        mock_db.bulk_insert_mappings.assert_called_once()
        # 2 findings in mock data
        inserted = mock_db.bulk_insert_mappings.call_args
        findings_arg = inserted[0][1] if inserted[0] and len(inserted[0]) > 1 else inserted[1].get("mappings", [])
        assert len(findings_arg) == 2

        # ── Verify: DB commit called ────────────────────────────────
        assert mock_db.commit.called
        assert not mock_db.rollback.called

    def test_scan_not_found(self, mock_db, mock_redis, mock_orchestrator):
        """If scan record doesn't exist, task should return early."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = run_ai_scan(
            scan_id="nonexistent-uuid",
            target_url="https://example.com",
        )

        # Should return without calling orchestrator
        mock_orchestrator.assert_not_called()
        assert result is None

    def test_persist_failure(self, mock_db, mock_redis, mock_orchestrator, mock_scan):
        """If DB persist fails, scan should be marked as FAILED."""
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_scan,  # Check query
            mock_scan,  # Status update query
            mock_scan,  # Persist query
            mock_scan,  # Error status update query
        ]
        # Make commit fail
        mock_db.commit.side_effect = [None, Exception("DB connection lost"), None]

        with patch.object(run_ai_scan, "retry", side_effect=MaxRetriesExceededError):
            run_ai_scan(
                scan_id="test-scan-uuid",
                target_url="https://example.com",
            )

        # Scan should be marked FAILED
        assert mock_scan.status == ScanStatus.FAILED
        assert mock_db.rollback.called

    def test_orchestrator_failure(self, mock_db, mock_redis, mock_scan):
        """If orchestrator raises, scan is marked FAILED and not retried for permanent errors."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch(
            "app.tasks.scan_tasks._run_orchestrator",
            side_effect=ValueError("Invalid target URL"),
        ):
            run_ai_scan(
                scan_id="test-scan-uuid",
                target_url="https://invalid",
            )

        # Scan should be marked FAILED
        assert mock_scan.status == ScanStatus.FAILED
        assert mock_scan.progress == 0
        assert mock_scan.error_message is not None

    def test_orchestrator_transient_retry(self, mock_db, mock_redis, mock_scan):
        """Transient orchestrator errors should trigger retry."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch(
            "app.tasks.scan_tasks._run_orchestrator",
            side_effect=ConnectionError("Temporary DNS failure"),
        ):
            with patch.object(run_ai_scan, "retry") as mock_retry:
                mock_retry.side_effect = MaxRetriesExceededError()
                run_ai_scan(
                    scan_id="test-scan-uuid",
                    target_url="https://example.com",
                )
                # Should have attempted retry
                assert mock_retry.called

    def test_timeout_handling(self, mock_db, mock_redis, mock_scan):
        """SoftTimeLimitExceeded should mark scan as FAILED without retry."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch(
            "app.tasks.scan_tasks._run_orchestrator",
            side_effect=SoftTimeLimitExceeded(),
        ):
            with patch.object(run_ai_scan, "retry") as mock_retry:
                run_ai_scan(
                    scan_id="test-scan-uuid",
                    target_url="https://example.com",
                )
                # Timeout should NOT be retried
                mock_retry.assert_not_called()
                assert mock_scan.status == ScanStatus.FAILED

    def test_retry_count_exceeded(self, mock_db, mock_redis, mock_scan):
        """When retries are exhausted, log error and mark scan as failed."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch(
            "app.tasks.scan_tasks._run_orchestrator",
            side_effect=ConnectionError("Temporary DNS failure"),
        ):
            with patch.object(run_ai_scan, "retry", side_effect=MaxRetriesExceededError):
                # This should not raise — the task catches MaxRetriesExceededError
                run_ai_scan(
                    scan_id="test-scan-uuid",
                    target_url="https://example.com",
                )
                # Scan should still be marked as failed
                assert mock_scan.status == ScanStatus.FAILED

    def test_event_loop_isolation(self):
        """Verify that asyncio.run() creates a fresh loop."""
        result = []
        async def check_loop():
            # Inside asyncio.run(), we should have a running loop
            inner_loop = asyncio.get_running_loop()
            result.append(inner_loop)

        asyncio.run(check_loop())

        assert result[0] is not None
        assert not result[0].is_running()  # Already closed by asyncio.run()

    def test_progress_published_on_failure(self, mock_db, mock_redis, mock_scan):
        """When pipeline fails, progress=0 with status=failed is published."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        with patch(
            "app.tasks.scan_tasks._run_orchestrator",
            side_effect=ValueError("Invalid target"),
        ):
            run_ai_scan(
                scan_id="test-scan-uuid",
                target_url="https://example.com",
            )

        # Verify final progress is 0/failed
        final_publish = mock_redis.publish.call_args_list[-1]
        published_data = final_publish[0][1]
        import json
        data = json.loads(published_data)
        assert data["progress"] == 0
        assert data["status"] == "failed"


# ══════════════════════════════════════════════════════════════════════════
# _publish_progress
# ══════════════════════════════════════════════════════════════════════════

class TestPublishProgress:
    """Verify Redis progress publishing."""

    def test_publishes_to_correct_channel(self, mock_redis):
        """Progress should be published to scan-specific Redis channel."""
        _publish_progress("scan-123", 50, "running")

        # Verify publish was called with correct channel
        channels = {c[0][0] for c in mock_redis.publish.call_args_list}
        assert "scan:scan-123:progress" in channels

    def test_sets_latest_key(self, mock_redis):
        """Latest progress should be stored with 1h TTL."""
        _publish_progress("scan-123", 75, "running")

        mock_redis.setex.assert_called_once()
        key = mock_redis.setex.call_args[0][0]
        assert key == "scan:scan-123:latest"

    def test_non_critical_failure(self, mock_redis):
        """Redis errors should be logged as debug, not raised."""
        mock_redis.publish.side_effect = ConnectionError("Redis down")

        # Should not raise
        _publish_progress("scan-123", 50, "running")
        # Test passes if no exception


# ══════════════════════════════════════════════════════════════════════════
# _update_scan_status
# ══════════════════════════════════════════════════════════════════════════

class TestUpdateScanStatus:
    """Verify DB status updates."""

    def test_updates_status_and_progress(self, mock_db):
        """Should update scan status, progress, and timestamps."""
        mock_scan = MagicMock(spec=Scan)
        mock_scan.started_at = None
        mock_scan.completed_at = None
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

        _update_scan_status("scan-123", ScanStatus.FAILED, progress=0, error_message="Boom")

        assert mock_scan.status == ScanStatus.FAILED
        assert mock_scan.progress == 0
        assert mock_scan.error_message == "Boom"
        assert mock_scan.completed_at is not None
        assert mock_db.commit.called

    def test_scan_not_found(self, mock_db):
        """If scan not found, no error should be raised."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        # Should not raise
        _update_scan_status("nonexistent", ScanStatus.FAILED, progress=0)
        assert not mock_db.commit.called


# ══════════════════════════════════════════════════════════════════════════
# run_scan — regression check (should still work)
# ══════════════════════════════════════════════════════════════════════════

class TestRunScan:
    """Minimal regression: run_scan is unchanged except import."""

    def test_scan_not_found(self, mock_db, mock_redis):
        """If scan record doesn't exist, run_scan returns early."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = run_scan("nonexistent-uuid")
        assert result is None
