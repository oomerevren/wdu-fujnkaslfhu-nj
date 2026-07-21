"""add_api_keys_and_audit_enhancements

Revision ID: 263319850223
Revises: 263319850222
Create Date: 2026-07-21 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = '263319850223'
down_revision: Union[str, None] = '263319850222'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'api_keys',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_prefix', sa.String(8), nullable=False),
        sa.Column('key_hash', sa.String(128), nullable=False, unique=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    op.add_column('audit_logs', sa.Column('user_agent', sa.String(500), nullable=True))
    op.add_column('audit_logs', sa.Column('request_fingerprint', sa.String(64), nullable=True))
    op.add_column('audit_logs', sa.Column('hmac_signature', sa.String(128), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_logs', 'hmac_signature')
    op.drop_column('audit_logs', 'request_fingerprint')
    op.drop_column('audit_logs', 'user_agent')
    op.drop_table('api_keys')
