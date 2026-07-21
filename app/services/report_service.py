import logging
import os
from datetime import datetime
from functools import lru_cache
from uuid import UUID

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import Scan
from app.models.finding import Finding

logger = logging.getLogger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

# Template environment with caching for performance
@lru_cache(maxsize=1)
def _get_template_env() -> Environment:
    """Return a cached Jinja2 environment with template caching enabled."""
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        cache_size=50,  # Cache up to 50 compiled templates
        auto_reload=False,  # Disable auto-reload in production for speed
    )
    return env


def _compute_duration_seconds(scan: Scan) -> int:
    """Compute scan duration in seconds from started_at / completed_at."""
    if scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        return int(delta.total_seconds())
    return 0


def _build_finding_data(findings: list[Finding]) -> list[dict]:
    """Build serializable finding data from ORM objects."""
    findings_data = []
    for f in findings:
        findings_data.append({
            "name": f.name,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "source": f.source,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "description": f.description,
            "remediation": f.remediation,
        })
    return findings_data


def _compute_severity_counts(findings: list[Finding]) -> dict:
    """Compute severity distribution from findings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        if sev in counts:
            counts[sev] += 1
    return counts


# ── Sync version ─────────────────────────────────────────────────────────────

def generate_scan_report_pdf(scan_id: UUID, user_id: UUID, db: Session) -> bytes:
    """Generate a PDF report for a scan.

    Performance notes:
    - Uses joinedload to eager-load scan.target and scan.findings (fixes N+1).
    - Computes duration_seconds from started_at/completed_at timestamps.
    - Uses cached Jinja2 environment for template rendering.
    """
    # FIX: Use joinedload to eager-load target relationship (fixes N+1)
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )
    if not scan:
        raise ValueError("Scan not found")

    from weasyprint import HTML

    # FIX: Use joinedload to eager-load findings (fixes N+1)
    findings = (
        db.query(Finding)
        .options(joinedload(Finding.scan))
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    severity_counts = _compute_severity_counts(findings)

    # FIX: Compute duration_seconds properly instead of hardcoding 0
    summary = {
        "total": len(findings),
        **severity_counts,
        "duration_seconds": _compute_duration_seconds(scan),
    }
    if scan.raw_results and isinstance(scan.raw_results, dict):
        summary.update(scan.raw_results.get("scan_summary", {}))

    findings_data = _build_finding_data(findings)

    # FIX: Use cached template environment
    env = _get_template_env()
    template = env.get_template("report.html")
    html_content = template.render(
        target_url=scan.target.url,
        scan_type=scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type),
        scan_id=str(scan.id),
        report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        findings=findings_data,
    )

    pdf = HTML(string=html_content).write_pdf()
    return pdf


# ── Async version ────────────────────────────────────────────────────────────

async def generate_scan_report_pdf_async(scan_id: UUID, user_id: UUID, db: AsyncSession) -> bytes:
    """Async version of generate_scan_report_pdf.

    Uses await on async queries while keeping the same performance optimizations
    (joinedload, cached templates, proper duration computation).
    """
    # Async query with joinedload for N+1 prevention
    result = await db.execute(
        select(Scan)
        .options(joinedload(Scan.target))
        .where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.unique().scalar_one_or_none()
    if not scan:
        raise ValueError("Scan not found")

    from weasyprint import HTML

    # Async query for findings
    result = await db.execute(
        select(Finding)
        .options(joinedload(Finding.scan))
        .where(Finding.scan_id == scan_id)
    )
    findings = list(result.unique().scalars().all())

    severity_counts = _compute_severity_counts(findings)

    summary = {
        "total": len(findings),
        **severity_counts,
        "duration_seconds": _compute_duration_seconds(scan),
    }
    if scan.raw_results and isinstance(scan.raw_results, dict):
        summary.update(scan.raw_results.get("scan_summary", {}))

    findings_data = _build_finding_data(findings)

    env = _get_template_env()
    template = env.get_template("report.html")
    html_content = template.render(
        target_url=scan.target.url,
        scan_type=scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type),
        scan_id=str(scan.id),
        report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        findings=findings_data,
    )

    pdf = HTML(string=html_content).write_pdf()
    return pdf
