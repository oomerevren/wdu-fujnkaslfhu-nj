"""add_scans_user_target_index

Revision ID: 263319850220
Revises: 26331985021f
Create Date: 2026-07-21 00:00:03.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '263319850220'
down_revision: Union[str, None] = '26331985021f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index('ix_scans_user_target', 'scans', ['user_id', 'target_id'])


def downgrade() -> None:
    op.drop_index('ix_scans_user_target', table_name='scans')
