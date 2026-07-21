"""add missing user fields (failed_login_attempts, locked_until) and fix cvss_score to Float

Revision ID: 26331985021g
Revises: 263319850222
Create Date: 2026-07-21 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = '26331985021g'
down_revision: Union[str, None] = '263319850222'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Add missing user fields ---
    op.add_column('users', sa.Column('failed_login_attempts', sa.Integer(),
                  server_default='0', nullable=False))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(), nullable=True))

    # --- Fix cvss_score from Integer to Float ---
    # NOTE: cvss_score is already nullable (from initial migration), so DROP NOT NULL is unnecessary.
    # The original code had `ALTER TABLE findings ALTER COLUMN cvss_type DROP NOT NULL`
    # which was a bug (cvss_type doesn't exist). Removed since cvss_score is already nullable.
    op.alter_column('findings', 'cvss_score',
                    existing_type=sa.Integer(),
                    type_=sa.Float(),
                    existing_nullable=True,
                    postgresql_using='cvss_score::double precision')

    # --- Add composite indexes for common query patterns ---
    op.create_index('ix_findings_user_severity_created',
                    'findings', ['user_id', 'severity', sa.text('created_at DESC')],
                    postgresql_using='btree')
    op.create_index('ix_scans_user_created',
                    'scans', ['user_id', sa.text('created_at DESC')],
                    postgresql_using='btree')

    # --- Add api_keys table ---
    op.create_table(
        'api_keys',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('key_prefix', sa.String(20), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    # --- Add security_scores table ---
    op.create_table(
        'security_scores',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('domain', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('score', sa.Integer(), default=50),
        sa.Column('grade', sa.String(3), default='C'),
        sa.Column('total_scans', sa.Integer(), default=0),
        sa.Column('critical_count', sa.Integer(), default=0),
        sa.Column('high_count', sa.Integer(), default=0),
        sa.Column('medium_count', sa.Integer(), default=0),
        sa.Column('low_count', sa.Integer(), default=0),
        sa.Column('trend', sa.String(20), default='stable'),
        sa.Column('last_scan_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('security_scores')
    op.drop_table('api_keys')
    op.drop_index('ix_scans_user_created', table_name='scans')
    op.drop_index('ix_findings_user_severity_created', table_name='findings')
    op.alter_column('findings', 'cvss_score',
                    existing_type=sa.Float(),
                    type_=sa.Integer(),
                    existing_nullable=True)
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_attempts')
