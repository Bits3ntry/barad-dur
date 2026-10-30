"""Database wiring: URL from PLATFORM_DATABASE_URL, one session dependency."""
import os
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app import models

_DEFAULT_URL = "postgresql+psycopg://barad:barad@127.0.0.1:15443/barad_platform"


def database_url() -> str:
    return os.environ.get("PLATFORM_DATABASE_URL") or _DEFAULT_URL


def create_database_engine():
    return create_engine(database_url(), future=True)


def session_factory(engine=None) -> sessionmaker:
    if engine is None:
        engine = create_database_engine()
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one session per request."""
    session = session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_migrations() -> None:
    """Alembic upgrade head, driven from the installable package."""
    from alembic import command
    from alembic.config import Config

    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url())
    command.upgrade(config, "head")
