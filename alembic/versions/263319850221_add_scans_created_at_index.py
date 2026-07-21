"""add_scans_created_at_index

Revision ID: 263319850221
Revises: 263319850220
Create Date: 2026-07-21 00:00:04.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '263319850221'
down_revision: Union[str, None] = '263319850220'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        'ix_scans_created_at_desc',
        'scans',
        ['created_at'],
        postgresql_using='btree',
    )


def downgrade() -> None:
    op.drop_index('ix_scans_created_at_desc', table_name='scans')
