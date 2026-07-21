"""add_targets_user_id_index

Revision ID: 263319850222
Revises: 263319850221
Create Date: 2026-07-21 00:00:05.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '263319850222'
down_revision: Union[str, None] = '263319850221'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index('ix_targets_user_id', 'targets', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_targets_user_id', table_name='targets')
