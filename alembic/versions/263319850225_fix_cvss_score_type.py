"""Fix cvss_score column type — ensure Float with proper data cleanup

This migration ensures the cvss_score column on the findings table is
properly typed as FLOAT (not INTEGER or VARCHAR), and cleans up any
string-encoded values that may have been inserted by external scanners
(e.g., Nuclei may return cvss-score as a string from JSON).

Steps:
1. Drop NOT NULL if somehow set (idempotent — cvss_score is nullable).
2. Convert any string values to numeric (safer ALTER).
3. ALTER the column type to FLOAT using PostgreSQL's USING clause.
4. Add a CHECK constraint to enforce 0.0–10.0 range.

Revision ID: 263319850225
Revises: 263319850224
Create Date: 2026-07-21 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '263319850225'
down_revision: Union[str, None] = '263319850224'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Step 1: Ensure column is nullable (idempotent) ────────────────────
    # If previous migration partially applied or DB state is inconsistent,
    # this makes sure we can proceed with the ALTER.
    op.execute(
        "ALTER TABLE findings ALTER COLUMN cvss_score DROP NOT NULL"
    )

    # ── Step 2: Convert string-encoded values to numeric ──────────────────
    # Nuclei and other scanners may return cvss-score as a string like "7.5".
    # Set invalid strings to NULL so the ALTER doesn't fail.
    op.execute(
        """
        UPDATE findings
        SET cvss_score = NULL
        WHERE cvss_score IS NOT NULL
          AND cvss_score::text ~ E'^\\s*$'
        """
    )
    op.execute(
        """
        UPDATE findings
        SET cvss_score = NULL
        WHERE cvss_score IS NOT NULL
          AND cvss_score::text ~ '[^0-9\\.\\-]'
        """
    )

    # ── Step 3: Cast to FLOAT ─────────────────────────────────────────────
    # PostgreSQL's ALTER TABLE ... TYPE FLOAT USING works for both
    # INTEGER and TEXT -> FLOAT conversions.
    op.execute(
        "ALTER TABLE findings ALTER COLUMN cvss_score TYPE FLOAT "
        "USING cvss_score::double precision"
    )

    # ── Step 4: Add CHECK constraint for 0.0–10.0 range ───────────────────
    op.create_check_constraint(
        "ck_findings_cvss_score_range",
        "findings",
        sa.text("cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)"),
    )


def downgrade() -> None:
    # ── Reverse: remove CHECK constraint ──────────────────────────────────
    op.drop_constraint("ck_findings_cvss_score_range", "findings", type_="check")

    # ── Reverse: cast back to INTEGER ─────────────────────────────────────
    # Truncates fractional part — this is lossy but unavoidable when
    # going from Float back to Integer.
    op.execute(
        "ALTER TABLE findings ALTER COLUMN cvss_score TYPE INTEGER "
        "USING CASE "
        "  WHEN cvss_score IS NOT NULL THEN ROUND(cvss_score)::integer "
        "  ELSE NULL "
        "END"
    )
