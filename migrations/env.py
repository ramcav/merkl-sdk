import os

from alembic import context


def get_url() -> str:
    """Get database URL from -x argument, env var, or alembic.ini."""
    url = context.get_x_argument(as_dictionary=True).get("sqlalchemy.url")
    if url:
        return url
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    return context.config.get_main_option("sqlalchemy.url", "")


def run_migrations_offline() -> None:
    context.configure(url=get_url(), target_metadata=None, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    from sqlalchemy import create_engine

    connectable = create_engine(get_url())
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
