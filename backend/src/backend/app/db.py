"""Database wiring: URL from PLATFORM_DATABASE_URL, one session dependency."""
import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app import models

_DEFAULT_URL = "postgresql+psycopg://barad:barad@127.0.0.1:15443/barad_platform"


def load_workspace_env(path: Path | None = None) -> None:
    """Load a checkout's .env only when the CLI explicitly asks for it.

    Library callers keep their process environment untouched, preventing tests
    and embedded uses from accidentally connecting to a developer's live stack.
    Existing exported variables always take precedence over file values.
    """
    env_path = path or Path.cwd() / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not key.replace("_", "a").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


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
