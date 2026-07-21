"""add_findings_severity_index

Revision ID: 26331985021e
Revises: 26331985021d
Create Date: 2026-07-21 00:00:01.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '26331985021e'
down_revision: Union[str, None] = '26331985021d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index('ix_findings_severity', 'findings', ['severity'])


def downgrade() -> None:
    op.drop_index('ix_findings_severity', table_name='findings')
