"""add_findings_user_severity_index

Revision ID: 26331985021f
Revises: 26331985021e
Create Date: 2026-07-21 00:00:02.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '26331985021f'
down_revision: Union[str, None] = '26331985021e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index('ix_findings_user_severity', 'findings', ['user_id', 'severity'])


def downgrade() -> None:
    op.drop_index('ix_findings_user_severity', table_name='findings')
