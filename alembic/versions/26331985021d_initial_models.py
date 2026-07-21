"""initial_models

Revision ID: 26331985021d
Revises: 
Create Date: 2026-07-20 01:59:03.172778

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ENUM

# revision identifiers, used by Alembic.
revision: str = '26331985021d'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- users tablosu ---
    op.create_table(
        'users',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('hashed_password', sa.String(255), nullable=True),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('company_name', sa.String(255), nullable=True),
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=False),
        sa.Column('is_verified', sa.Boolean(), default=False),
        sa.Column('is_superuser', sa.Boolean(), default=False),
        sa.Column('google_id', sa.String(255), unique=True, nullable=True),
        sa.Column('onboarding_step', sa.String(50), default='welcome'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # --- targets tablosu ---
    op.create_table(
        'targets',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('target_type', sa.String(50), default='web'),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('auth_header', sa.Text(), nullable=True),
        sa.Column('auth_type', sa.String(50), nullable=True),
        sa.Column('status', sa.String(50), default='pending'),
        sa.Column('metadata_json', sa.JSON(), default=dict),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # --- scans tablosu ---
    op.create_table(
        'scans',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('target_id', UUID(as_uuid=True), sa.ForeignKey('targets.id'), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), default='queued'),
        sa.Column('progress', sa.Integer(), default=0),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('raw_results', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    # --- findings tablosu ---
    op.create_table(
        'findings',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('scan_id', UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), sa.ForeignKey('targets.id'), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('source', sa.String(50), nullable=False),
        sa.Column('template_id', sa.String(255), nullable=True),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('cvss_score', sa.Integer(), nullable=True),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('status', sa.String(50), default='open'),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    # --- subscriptions tablosu ---
    op.create_table(
        'subscriptions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False, unique=True),
        sa.Column('plan', sa.String(50), default='free'),
        sa.Column('stripe_customer_id', sa.String(255), nullable=True),
        sa.Column('stripe_subscription_id', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('current_period_start', sa.DateTime(), nullable=True),
        sa.Column('current_period_end', sa.DateTime(), nullable=True),
        sa.Column('scans_used', sa.Integer(), default=0),
        sa.Column('scans_limit', sa.Integer(), default=1),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # --- audit_logs tablosu ---
    op.create_table(
        'audit_logs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('subscriptions')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('targets')
    op.drop_table('users')
