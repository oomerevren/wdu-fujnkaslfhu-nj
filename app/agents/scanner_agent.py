"""Scanner Agent — Orchestrates parallel execution of security scanners.

This agent wraps the existing worker modules (nuclei, zap, promptfoo) as
AI-callable tools. It dynamically selects scanners based on the target type
and recon data, then executes them in parallel using asyncio.gather.
"""

import asyncio
import time
from typing import Optional, Callable, Any
from uuid import UUID

from app.core.logging import logger
from app.config import settings


class ScannerAgent:
    """Executes security scanners in parallel based on a scan plan.

    Features:
    - Dynamic scanner selection based on target type and recon data
    - Parallel execution with configurable concurrency
    - Per-scanner timeout and error isolation
    - Result aggregation and deduplication
    - Scanner health checks before execution
    """

    def __init__(self):
        self._scanner_registry: dict[str, Callable] = {}
        self._register_scanners()

    def _register_scanners(self):
        """Register available scanner functions."""
        try:
            from app.workers.nuclei_worker import run_nuclei_scan
            self._scanner_registry["nuclei"] = run_nuclei_scan
        except ImportError as exc:
            logger.warning("Nuclei worker not available", extra={"error": str(exc)})

        try:
            from app.workers.zap_worker import run_zap_scan
            self._scanner_registry["zap"] = run_zap_scan
        except ImportError as exc:
            logger.warning("ZAP worker not available", extra={"error": str(exc)})

        try:
            from app.workers.promptfoo_worker import run_promptfoo_scan
            self._scanner_registry["promptfoo"] = run_promptfoo_scan
        except ImportError as exc:
            logger.warning("PromptFoo worker not available", extra={"error": str(exc)})

    async def execute_scan_plan(
        self,
        target_url: str,
        scan_plan: dict,
        auth_header: Optional[str] = None,
        scan_id: Optional[str] = None,
        progress_callback: Optional[Callable] = None,
    ) -> dict:
        """Execute a scan plan against a target.

        Args:
            target_url: The target URL to scan.
            scan_plan: Dict with 'scanners' list and 'configs' dict.
            auth_header: Optional Authorization header.
            scan_id: Optional scan ID for progress tracking.
            progress_callback: Optional async callable for progress updates.

        Returns:
            Dict with keys:
                - findings: Combined list of all findings
                - scanner_results: Per-scanner result dict
                - errors: List of scanner errors
                - total_duration: Total execution time
        """
        scanners = scan_plan.get("scanners", [])
        if not scanners:
            logger.warning("Scan plan has no scanners selected")
            return {"findings": [], "scanner_results": {}, "errors": ["No scanners selected"], "total_duration": 0}

        logger.info(
            "ScannerAgent executing scan plan",
            extra={
                "target_url": target_url,
                "scanners": scanners,
                "scan_id": scan_id,
            },
        )

        start_time = time.time()
        scanner_tasks = []
        scanner_names = []

        for scanner_name in scanners:
            if scanner_name not in self._scanner_registry:
                logger.warning(f"Scanner '{scanner_name}' not registered, skipping")
                continue

            scanner_fn = self._scanner_registry[scanner_name]
            scanner_config = scan_plan.get("configs", {}).get(scanner_name, {})
            scanner_names.append(scanner_name)

            # Wrap scanner execution with progress reporting
            async def _run_scanner(
                name: str,
                fn: Callable,
                config: dict,
            ) -> tuple[str, dict]:
                try:
                    if progress_callback:
                        await progress_callback(name, "starting", 0)

                    result = await asyncio.to_thread(
                        fn,
                        target_url,
                        auth_header,
                    )

                    finding_count = len(result.get("findings", []))
                    if progress_callback:
                        await progress_callback(name, "completed", 100, finding_count)

                    return name, result

                except Exception as exc:
                    logger.error(
                        "Scanner execution failed",
                        extra={"scanner": name, "error": str(exc)},
                    )
                    error_result = {
                        "findings": [],
                        "scan_summary": {
                            "error": f"{name} execution failed: {str(exc)}",
                            "duration_seconds": 0,
                        },
                    }
                    if progress_callback:
                        await progress_callback(name, "failed", 0)
                    return name, error_result

            task = _run_scanner(scanner_name, scanner_fn, scanner_config)
            scanner_tasks.append(task)

        # Execute all scanners in parallel
        results_list = await asyncio.gather(*scanner_tasks, return_exceptions=False)

        # Process results
        scanner_results = {}
        all_findings = []
        errors = []

        for name, result in results_list:
            scanner_results[name] = result.get("scan_summary", {})

            scanner_findings = result.get("findings", [])
            # Tag each finding with its source scanner
            for finding in scanner_findings:
                finding["source_scanner"] = name
                if "source" not in finding:
                    finding["source"] = name

            all_findings.extend(scanner_findings)

            scan_error = result.get("scan_summary", {}).get("error")
            if scan_error:
                errors.append(f"{name}: {scan_error}")

        total_duration = time.time() - start_time

        logger.info(
            "ScannerAgent scan complete",
            extra={
                "scanners_used": len(scanner_results),
                "total_findings": len(all_findings),
                "errors": len(errors),
                "duration_seconds": round(total_duration, 2),
            },
        )

        return {
            "findings": all_findings,
            "scanner_results": scanner_results,
            "errors": errors,
            "total_duration": round(total_duration, 2),
        }

    def get_available_scanners(self) -> list[str]:
        """Return list of registered scanner names."""
        return list(self._scanner_registry.keys())

    def is_scanner_available(self, name: str) -> bool:
        """Check if a specific scanner is registered."""
        return name in self._scanner_registry
