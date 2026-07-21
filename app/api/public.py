"""Public API endpoints for security scores, badges, and global stats.

These endpoints are unauthenticated and provide read-only public information
about domain security scores, leaderboard, and global platform statistics.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.score_service import (
    extract_domain,
    get_global_stats,
    get_leaderboard,
    get_score,
)

router = APIRouter()


@router.get("/score/{domain}")
def public_get_score(
    domain: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get the public security score for a domain.

    This endpoint is unauthenticated and returns the current security score,
    grade, finding breakdown, and trend for the specified domain.

    Args:
        domain: Domain name to look up (e.g., example.com).

    Returns:
        Dict with score, grade, trend, and finding breakdown.
    """
    clean_domain = extract_domain(domain)
    result = get_score(clean_domain, db)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"No security score data found for domain: {clean_domain}",
        )
    return result


@router.get("/badge/{domain}")
def public_get_badge(
    domain: str,
    db: Session = Depends(get_db),
) -> Any:
    """Get an SVG badge for a domain's security score.

    This endpoint returns a Shields.io-style SVG badge that can be embedded
    in README files or websites to show the domain's security score.

    Args:
        domain: Domain name to look up.

    Returns:
        SVG badge as text/html content.
    """
    clean_domain = extract_domain(domain)
    result = get_score(clean_domain, db)

    if not result:
        score = 0
        grade = "N/A"
        label = "security"
    else:
        score = result["score"]
        grade = result["grade"]

    # Color based on score
    if score >= 85:
        color = "brightgreen"
    elif score >= 70:
        color = "green"
    elif score >= 55:
        color = "yellowgreen"
    elif score >= 40:
        color = "yellow"
    elif score >= 25:
        color = "orange"
    else:
        color = "red"

    svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20" role="img" aria-label="PentestAI: {grade} ({score}/100)">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="140" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="80" height="20" fill="#555"/>
    <rect x="80" width="60" height="20" fill="#{"4c1" if color == "brightgreen" else "97CA00" if color == "green" else "a4a61d" if color == "yellowgreen" else "dfb317" if color == "yellow" else "fe7d37" if color == "orange" else "e05d44"}"/>
    <rect width="140" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="40" y="15" fill="#010101" fill-opacity=".3">PentestAI</text>
    <text x="40" y="14">PentestAI</text>
    <text x="109" y="15" fill="#010101" fill-opacity=".3">{grade} ({score})</text>
    <text x="109" y="14">{grade} ({score})</text>
  </g>
</svg>"""

    from fastapi.responses import Response

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@router.get("/leaderboard")
def public_leaderboard(
    limit: int = Query(100, ge=1, le=500, description="Number of top domains to return"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get the leaderboard of top domains by security score.

    Returns up to 100 domains sorted by security score descending.

    Args:
        limit: Maximum number of entries (1-500, default 100).

    Returns:
        Dict with leaderboard entries.
    """
    entries = get_leaderboard(db, limit=limit)
    return {
        "count": len(entries),
        "entries": entries,
    }


@router.get("/stats")
def public_stats(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get global platform statistics.

    Returns aggregated statistics across all domains including total scans,
    finding counts by severity, average score, and grade distribution.

    Args:
        db: Database session.

    Returns:
        Dict with global stats.
    """
    return get_global_stats(db)
