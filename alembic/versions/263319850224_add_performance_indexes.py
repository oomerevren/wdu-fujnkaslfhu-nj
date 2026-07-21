"""add_performance_indexes

Merge migration that adds missing composite and FK indexes
for findings, scans, and targets to eliminate sequential scans
in common query patterns.

Indexes added (CONCURRENTLY for zero-downtime production deploys):
  - ix_findings_user_severity_scan ON findings (user_id, severity, scan_id, created_at DESC)
    Covering the most common filtered+ordered findings query.
  - ix_findings_scan_id ON findings (scan_id)
    Accelerates scan → findings join.
  - ix_findings_target_id ON findings (target_id)
    Accelerates target → findings join.
  - ix_scans_user_target ON scans (user_id, target_id, created_at DESC)
    Replaces missing-DESC variant from migration 263319850220.
  - ix_targets_user_id ON targets (user_id, created_at DESC)
    Replaces missing-DESC variant from migration 263319850222.

Revision ID: 263319850224
Revises: 26331985021g, 263319850223
Create Date: 2026-07-21 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "263319850224"
down_revision: Union[str, Sequence[str], None] = ("26331985021g", "263319850223")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Use autocommit_block for CONCURRENTLY operations ──────────────────
    # CREATE INDEX CONCURRENTLY cannot be run inside a transaction block.
    # Alembic's autocommit_block commits the current transaction, runs
    # the statements, then starts a new transaction.
    with op.get_context().autocommit_block():
        # 1. Composite index for the most common findings query pattern:
        #    WHERE user_id = ? [AND severity = ?] [AND scan_id = ?]
        #    ORDER BY created_at DESC
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_user_severity_scan
            ON findings (user_id, severity, scan_id, created_at DESC)
            """
        )

        # 2. FK join index: findings.scan_id → scans.id
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_scan_id
            ON findings (scan_id)
            """
        )

        # 3. FK join index: findings.target_id → targets.id
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_target_id
            ON findings (target_id)
            """
        )

        # 4. Replace ix_scans_user_target — add created_at DESC ordering
        #    Old index (from 263319850220): (user_id, target_id)
        #    New index: (user_id, target_id, created_at DESC)
        op.execute("DROP INDEX IF EXISTS ix_scans_user_target")
        op.execute(
            """
            CREATE INDEX CONCURRENTLY ix_scans_user_target
            ON scans (user_id, target_id, created_at DESC)
            """
        )

        # 5. Replace ix_targets_user_id — add created_at DESC ordering
        #    Old index (from 263319850222): (user_id)
        #    New index: (user_id, created_at DESC)
        op.execute("DROP INDEX IF EXISTS ix_targets_user_id")
        op.execute(
            """
            CREATE INDEX CONCURRENTLY ix_targets_user_id
            ON targets (user_id, created_at DESC)
            """
        )


def downgrade() -> None:
    # ── Remove indexes added in this migration ────────────────────────────
    op.drop_index("ix_findings_user_severity_scan", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_findings_target_id", table_name="findings")

    # Restore ix_scans_user_target to its pre-migration definition
    # (without created_at DESC, as originally created in 263319850220)
    op.drop_index("ix_scans_user_target", table_name="scans")
    op.create_index(
        "ix_scans_user_target",
        "scans",
        ["user_id", "target_id"],
    )

    # Restore ix_targets_user_id to its pre-migration definition
    # (without created_at DESC, as originally created in 263319850222)
    op.drop_index("ix_targets_user_id", table_name="targets")
    op.create_index(
        "ix_targets_user_id",
        "targets",
        ["user_id"],
    )
