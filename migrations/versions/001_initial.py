"""Initial schema — sessions, actions, merkle_batches.

Revision ID: 001
Revises: None
Create Date: 2026-03-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("session_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("allowed_tools", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("data_scope", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("policy_reference", sa.Text(), nullable=False, server_default=""),
        sa.Column("commitment_hash", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
        sa.Column("action_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "actions",
        sa.Column("action_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("input_hash", sa.LargeBinary(), nullable=False),
        sa.Column("output_hash", sa.LargeBinary(), nullable=False),
        sa.Column("drift_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("guardrail_result", sa.Text(), nullable=False, server_default="not_evaluated"),
        sa.Column("policy_reference", sa.Text(), nullable=False, server_default=""),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_index("ix_actions_session_id", "actions", ["session_id"])
    op.create_index("ix_actions_agent_id", "actions", ["agent_id"])
    op.create_index("ix_actions_timestamp", "actions", ["timestamp"])

    op.create_table(
        "merkle_batches",
        sa.Column("batch_id", sa.Text(), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("leaves", postgresql.ARRAY(sa.LargeBinary()), nullable=False, server_default="{}"),
        sa.Column("root", sa.LargeBinary(), nullable=True),
        sa.Column("sealed", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_table("merkle_batches")
    op.drop_index("ix_actions_timestamp", table_name="actions")
    op.drop_index("ix_actions_agent_id", table_name="actions")
    op.drop_index("ix_actions_session_id", table_name="actions")
    op.drop_table("actions")
    op.drop_table("sessions")
