"""Workspace .env discovery: the CLI finds credentials without manual exports.

The library itself never reads files — only `barad-platform` calls
`load_workspace_env()`, so a test or an embedded use can never pick up the
developer's real database by accident.
"""
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import db  # noqa: E402


def test_dotenv_is_loaded_from_the_workspace(tmp_path, monkeypatch):
    monkeypatch.delenv("PLATFORM_DATABASE_URL", raising=False)
    monkeypatch.delenv("BOOTSTRAP_TOKEN", raising=False)
    (tmp_path / ".env").write_text(
        "# comment\n\nPLATFORM_DATABASE_URL=postgresql+psycopg://u:p@h:1/db\n"
        "BOOTSTRAP_TOKEN='token-with-quotes'\n"
    )
    monkeypatch.chdir(tmp_path)

    db.load_workspace_env()

    assert os.environ["PLATFORM_DATABASE_URL"].endswith("@h:1/db")
    assert os.environ["BOOTSTRAP_TOKEN"] == "token-with-quotes"


def test_exported_variables_win_over_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", "postgresql+psycopg://real@db:5432/x")
    (tmp_path / ".env").write_text(
        "PLATFORM_DATABASE_URL=postgresql+psycopg://file@db:5432/x\n")
    monkeypatch.chdir(tmp_path)

    db.load_workspace_env()

    assert db.database_url() == "postgresql+psycopg://real@db:5432/x"


def test_missing_workspace_env_is_harmless(tmp_path, monkeypatch):
    monkeypatch.delenv("PLATFORM_DATABASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "is_file", lambda self: False)

    assert db.database_url() == db._DEFAULT_URL


def test_library_never_reads_the_workspace_on_import(tmp_path, monkeypatch):
    """Guards the leak that put real credentials into unrelated tests."""
    monkeypatch.delenv("PLATFORM_DATABASE_URL", raising=False)
    (tmp_path / ".env").write_text(
        "PLATFORM_DATABASE_URL=postgresql+psycopg://leak@db:5432/x\n")
    monkeypatch.chdir(tmp_path)

    assert "PLATFORM_DATABASE_URL" not in os.environ
    assert db.database_url() == db._DEFAULT_URL
