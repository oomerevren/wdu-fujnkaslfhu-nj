"""Service for calculating and managing security scores."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.finding import Finding, Severity
from app.models.security_score import SecurityScore
from app.models.target import Target

logger = logging.getLogger(__name__)


# ── Score Weights ───────────────────────────────────────────────────────
# These define the impact of each severity level on the 0-100 score.
# Higher deduction = more severe finding.
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 1,
}

# Maximum deductions per severity to avoid negative scores
MAX_DEDUCTIONS: dict[str, int] = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
    "info": 10,
}


def calculate_score(findings: list[Finding]) -> int:
    """Calculate a 0-100 security score from a list of findings.

    The scoring algorithm:
    1. Start with a perfect score of 100.
    2. Deduct points based on severity and count of findings.
    3. Higher severity findings have higher per-unit deductions.
    4. Each severity tier has a maximum deduction cap.
    5. The final score is clamped to [0, 100].

    Args:
        findings: List of Finding objects (typically open findings).

    Returns:
        Integer score between 0 and 100.
    """
    if not findings:
        return 100

    score = 100.0

    # Count findings by severity (only open/acknowledged findings affect score)
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in counts:
            counts[sev] += 1

    # Apply deductions with caps
    total_deduction = 0.0
    for severity, count in counts.items():
        weight = SEVERITY_WEIGHTS.get(severity, 1)
        max_ded = MAX_DEDUCTIONS.get(severity, 10)

        # Each finding of this severity deducts `weight` points
        # but total deduction for this severity is capped at `max_ded`
        deduction = min(count * weight, max_ded)
        total_deduction += deduction

        logger.debug(
            "Score deduction: severity=%s, count=%d, weight=%d, deduction=%.1f, capped_at=%d",
            severity,
            count,
            weight,
            deduction,
            max_ded,
        )

    score -= total_deduction
    score = max(0, min(100, round(score)))

    return int(score)


def calculate_grade(score: int) -> str:
    """Convert a numeric score to a letter grade.

    Grade scale:
        A+: 95-100
        A:  85-94
        B:  70-84
        C:  55-69
        D:  40-54
        F:  0-39

    Args:
        score: Numeric score (0-100).

    Returns:
        Letter grade string.
    """
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def calculate_trend(scores: list[int]) -> str:
    """Calculate the trend direction from a list of historical scores.

    Compares the average of the last 3 scores to the average of the 3 before that.
    If fewer than 3 data points, compares first to last.

    Args:
        scores: List of historical scores, ordered chronologically (oldest first).

    Returns:
        "improving", "declining", or "stable".
    """
    if len(scores) < 2:
        return "stable"

    if len(scores) >= 6:
        recent = sum(scores[-3:]) / 3
        previous = sum(scores[-6:-3]) / 3
    elif len(scores) >= 3:
        recent = sum(scores[-3:]) / 3
        previous = sum(scores[:-3]) / (len(scores) - 3) if len(scores) > 3 else scores[0]
    else:
        recent = scores[-1]
        previous = scores[0]

    diff = recent - previous
    if diff > 3:
        return "improving"
    if diff < -3:
        return "declining"
    return "stable"


def update_score(domain: str, findings: list[Finding], db: Session) -> SecurityScore:
    """Calculate and persist the security score for a domain.

    This is called after a scan completes to update the domain's score.

    Args:
        domain: The domain (extracted from the target URL).
        findings: All open findings for this domain.
        db: Database session.

    Returns:
        The updated or created SecurityScore record.
    """
    score_value = calculate_score(findings)
    grade = calculate_grade(score_value)

    # Count by severity
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in counts:
            counts[sev] += 1

    # Get or create score record
    score_record = db.query(SecurityScore).filter(SecurityScore.domain == domain).first()

    historical_scores: list[int] = []
    if score_record:
        historical_scores = [score_record.score]

    historical_scores.append(score_value)
    trend = calculate_trend(historical_scores)

    if score_record:
        # Check if score actually changed to calculate trend properly
        old_score = score_record.score
        score_record.score = score_value
        score_record.grade = grade
        score_record.total_scans += 1
        score_record.critical_count = counts["critical"]
        score_record.high_count = counts["high"]
        score_record.medium_count = counts["medium"]
        score_record.low_count = counts["low"]
        score_record.trend = trend
        score_record.last_scan_at = datetime.utcnow()
        score_record.updated_at = datetime.utcnow()
    else:
        score_record = SecurityScore(
            domain=domain,
            score=score_value,
            grade=grade,
            total_scans=1,
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            trend=trend,
            last_scan_at=datetime.utcnow(),
        )
        db.add(score_record)

    db.commit()
    db.refresh(score_record)

    logger.info(
        "Score updated for domain=%s score=%d grade=%s trend=%s",
        domain,
        score_value,
        grade,
        trend,
    )

    return score_record


def get_score(domain: str, db: Session) -> Optional[dict[str, Any]]:
    """Get the current security score for a domain with history.

    Args:
        domain: The domain to look up.
        db: Database session.

    Returns:
        Dict with score details, or None if not found.
    """
    record = db.query(SecurityScore).filter(SecurityScore.domain == domain).first()
    if not record:
        return None

    return {
        "id": str(record.id),
        "domain": record.domain,
        "score": record.score,
        "grade": record.grade,
        "total_scans": record.total_scans,
        "critical_count": record.critical_count,
        "high_count": record.high_count,
        "medium_count": record.medium_count,
        "low_count": record.low_count,
        "trend": record.trend,
        "last_scan_at": record.last_scan_at.isoformat() if record.last_scan_at else None,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def get_leaderboard(db: Session, limit: int = 100) -> list[dict[str, Any]]:
    """Get the top N domains by security score.

    Args:
        db: Database session.
        limit: Maximum number of entries (default 100).

    Returns:
        List of score dicts sorted descending by score.
    """
    records = (
        db.query(SecurityScore)
        .order_by(SecurityScore.score.desc(), SecurityScore.updated_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "rank": idx + 1,
            "domain": r.domain,
            "score": r.score,
            "grade": r.grade,
            "trend": r.trend,
            "total_scans": r.total_scans,
            "last_scan_at": r.last_scan_at.isoformat() if r.last_scan_at else None,
        }
        for idx, r in enumerate(records)
    ]


def get_global_stats(db: Session) -> dict[str, Any]:
    """Get global statistics across all domains.

    Args:
        db: Database session.

    Returns:
        Dict with global stats.
    """
    from sqlalchemy import func

    stats = db.query(
        func.count(SecurityScore.id).label("total_domains"),
        func.avg(SecurityScore.score).label("avg_score"),
        func.sum(SecurityScore.total_scans).label("total_scans"),
        func.sum(SecurityScore.critical_count).label("total_critical"),
        func.sum(SecurityScore.high_count).label("total_high"),
        func.sum(SecurityScore.medium_count).label("total_medium"),
        func.sum(SecurityScore.low_count).label("total_low"),
    ).first()

    if not stats:
        return {
            "total_domains": 0,
            "avg_score": 0.0,
            "total_scans": 0,
            "total_critical": 0,
            "total_high": 0,
            "total_medium": 0,
            "total_low": 0,
            "grade_distribution": {},
        }

    # Grade distribution
    grade_counts: dict[str, int] = {}
    for g in ["A+", "A", "B", "C", "D", "F"]:
        count = db.query(func.count(SecurityScore.id)).filter(SecurityScore.grade == g).scalar()
        if count:
            grade_counts[g] = count

    return {
        "total_domains": stats.total_domains or 0,
        "avg_score": round(float(stats.avg_score), 1) if stats.avg_score else 0.0,
        "total_scans": stats.total_scans or 0,
        "total_critical": stats.total_critical or 0,
        "total_high": stats.total_high or 0,
        "total_medium": stats.total_medium or 0,
        "total_low": stats.total_low or 0,
        "grade_distribution": grade_counts,
    }


def extract_domain(url: str) -> str:
    """Extract a clean domain name from a URL.

    Args:
        url: Full URL (e.g., https://www.example.com/path).

    Returns:
        Domain name (e.g., example.com).
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or url

    # Remove www. prefix
    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname
