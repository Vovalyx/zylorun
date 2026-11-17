"""add admin telemetry tables and user timestamps

These objects were previously created at startup with ad-hoc CREATE/ALTER
statements, so existing databases may already have them. Every step checks
first and only creates what is missing.

Revision ID: a9c4e7d21b6f
Revises: f7b8c9d0e1f2
Create Date: 2026-11-16 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a9c4e7d21b6f'
down_revision: Union[str, Sequence[str], None] = 'f7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(name: str) -> bool:
    return name in _inspector().get_table_names()


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in _inspector().get_columns(table)}


def _has_index(table: str, index: str) -> bool:
    return index in {i["name"] for i in _inspector().get_indexes(table)}


def _ensure_index(index: str, table: str, column: str) -> None:
    if not _has_index(table, index):
        op.create_index(index, table, [column], unique=False)


def upgrade() -> None:
    """Upgrade schema."""
    if not _has_column("users", "created_at"):
        op.add_column("users", sa.Column("created_at", sa.DateTime(), nullable=True))
    if not _has_column("users", "last_login_at"):
        op.add_column("users", sa.Column("last_login_at", sa.DateTime(), nullable=True))

    if not _has_table("visitor_logs"):
        op.create_table(
            "visitor_logs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("visitor_id", sa.String(), nullable=True),
            sa.Column("ip_address", sa.String(), nullable=True),
            sa.Column("user_agent", sa.String(), nullable=True),
            sa.Column("path", sa.String(), nullable=False),
            sa.Column("referrer", sa.String(), nullable=True),
            sa.Column("username", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
    _ensure_index("ix_visitor_logs_id", "visitor_logs", "id")
    _ensure_index("ix_visitor_logs_visitor_id", "visitor_logs", "visitor_id")
    _ensure_index("ix_visitor_logs_created_at", "visitor_logs", "created_at")

    if not _has_table("system_error_logs"):
        op.create_table(
            "system_error_logs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("error_type", sa.String(), nullable=False),
            sa.Column("severity", sa.String(), nullable=True),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("stack_trace", sa.Text(), nullable=True),
            sa.Column("path", sa.String(), nullable=True),
            sa.Column("method", sa.String(), nullable=True),
            sa.Column("status_code", sa.Integer(), nullable=True),
            sa.Column("username", sa.String(), nullable=True),
            sa.Column("resolved", sa.Boolean(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
    _ensure_index("ix_system_error_logs_id", "system_error_logs", "id")
    _ensure_index("ix_system_error_logs_created_at", "system_error_logs", "created_at")

    if not _has_table("contact_messages"):
        op.create_table(
            "contact_messages",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("subject", sa.String(), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("ip_address", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
    _ensure_index("ix_contact_messages_id", "contact_messages", "id")
    _ensure_index("ix_contact_messages_email", "contact_messages", "email")
    _ensure_index("ix_contact_messages_created_at", "contact_messages", "created_at")


def downgrade() -> None:
    """Downgrade schema."""
    for table in ("contact_messages", "system_error_logs", "visitor_logs"):
        if _has_table(table):
            op.drop_table(table)
    with op.batch_alter_table("users") as batch_op:
        if _has_column("users", "last_login_at"):
            batch_op.drop_column("last_login_at")
        if _has_column("users", "created_at"):
            batch_op.drop_column("created_at")
