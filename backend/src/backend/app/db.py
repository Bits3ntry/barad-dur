"""Database wiring: URL from PLATFORM_DATABASE_URL, one session dependency."""
import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app import models

_DEFAULT_URL = "postgresql+psycopg://barad:barad@127.0.0.1:15443/barad_platform"


def _dotenv_keys(path: Path) -> Iterator[tuple[str, str]]:
    """`KEY=value` pairs from one .env file; comments and blanks skipped."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        yield key, value.strip().strip('"').strip("'")


def load_workspace_env() -> None:
    """Read the workspace `.env` into the process env, never overriding it.

    The CLI and the API take credentials from the environment; reading the
    invocation workspace's `.env` keeps that contract while sparing callers
    from exporting every variable by hand. Anything already exported wins.
    """
    seen: set[Path] = set()
    for anchor in (Path.cwd(), Path(__file__).resolve()):
        for parent in [anchor, *anchor.parents]:
            candidate = parent / ".env"
            if candidate in seen or not candidate.is_file():
                continue
            seen.add(candidate)
            for key, value in _dotenv_keys(candidate):
                os.environ.setdefault(key, value)
            return


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
    """Alembic upgrade head, driven from the installable package.

    The project root is the nearest directory (walking up from the module file
    and then the working directory) that holds `alembic.ini`: checkouts put it
    next to `migrations/`, and the container image copies them into the workdir.
    """
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    candidates: list[Path] = [Path.cwd(), Path(__file__).resolve()]
    roots: list[Path] = []
    for candidate in candidates:
        current = candidate.resolve()
        for parent in [current, *current.parents]:
            if parent not in roots and (parent / "alembic.ini").is_file():
                roots.append(parent)
    if not roots:
        raise RuntimeError("alembic.ini not found from cwd nor the package module")
    root = roots[0]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url())
    command.upgrade(config, "head")
