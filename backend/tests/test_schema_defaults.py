"""A NOT NULL column in a migration needs a value from the model.

This exists because of a real 500 in a running deployment: `chat_sessions.updated_at`
was created `NOT NULL` with no server default, while the model never declared the
attribute — so every `POST /api/v1/ai/sessions` failed on Postgres. `ai_providers` had
the same defect, waiting for the first operator who saved a key.

The rest of the suite could not catch it: the fixtures build the schema with
`create_all`, which reads the *models*. A column the model does not know about simply
does not exist there. The invariant below is the cheap half of the missing check; the
expensive half — building the schema from `alembic upgrade head` — needs Postgres,
because later migrations use `alter_column`.
"""
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from sqlalchemy import inspect  # noqa: E402

from backend.app import models  # noqa: E402

#: Tables this feature set created with `NOT NULL` columns that have no server
#: default, and the model attributes that must therefore supply the value.
MUST_SUPPLY = [
    (models.ChatSession, "updated_at"),
    (models.AiProvider, "updated_at"),
]


def test_models_supply_every_not_null_column_the_migrations_created():
    for model, column in MUST_SUPPLY:
        mapper = inspect(model)
        attribute = mapper.columns.get(column)
        assert attribute is not None, (
            f"{model.__tablename__}.{column} is NOT NULL in the migration; the model "
            f"must declare it")
        assert attribute.default is not None or attribute.nullable, (
            f"{model.__tablename__}.{column} is NOT NULL in the migration and the model "
            f"has no default: every insert will fail on Postgres")


def test_the_two_rows_that_broke_can_be_created(tmp_path, monkeypatch):
    """The end-to-end shape of the incident: create a session and a provider."""
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/defaults.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    from backend.app.auth import create_key
    from backend.app.db import session_factory
    from backend.app.main import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "k")
    session.commit()
    client = TestClient(app)
    headers = {"X-API-Key": key}

    created = client.post("/api/v1/ai/sessions", json={}, headers=headers)
    assert created.status_code == 201, created.text

    provider = client.post("/api/v1/ai/providers", json={
        "name": "local", "kind": "openai-compatible",
        "base_url": "http://127.0.0.1:11434/v1", "model": "small",
        "api_key": "x"}, headers=headers)
    assert provider.status_code == 201, provider.text

    stored = session.query(models.ChatSession).one()
    assert stored.updated_at is not None


def test_settings_defaults_are_the_investigation_ceiling():
    """A cap that truncates every CVE question teaches the operator to raise it."""
    columns = {column.name: column for column in inspect(models.AiSettings).columns}
    assert columns["max_steps"].default.arg == 12
    assert columns["max_specialists"].default.arg == 6
