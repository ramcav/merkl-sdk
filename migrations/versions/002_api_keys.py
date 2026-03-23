"""API keys table.

Revision ID: 002
Revises: 001
Create Date: 2026-03-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("key_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key_hash", sa.LargeBinary(), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scopes", postgresql.JSONB(), nullable=False, server_default="[]"),
    )

    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_api_keys_org_id", table_name="api_keys")
    op.drop_table("api_keys")
