"""Seed a scratch stack for one scan flow, and print the ids to drive it with.

Deliberately isolated: `PLATFORM_DATABASE_URL` is set before the app is imported,
so nothing here can reach the compose stack. Run it, start the two servers, and
the flow can be walked with curl — which is the only proof that matters for the
contract.

    PLATFORM_DATABASE_URL=sqlite:////tmp/scan-demo/scan.db \
        python scripts/scan_flow_seed.py

    PLATFORM_DATABASE_URL=... uvicorn --factory backend.app.main:create_app \
        --port 8091
    SHAURON_BARAD_PUBKEY=<from GET /api/v1/scans/key> SHAURON_DB=/tmp/... \
        uvicorn --factory shauron.intake.app:create_app --port 9000
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))

if not os.environ.get("PLATFORM_DATABASE_URL"):
    raise SystemExit("set PLATFORM_DATABASE_URL first; this script never guesses")

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402

session = session_factory()()
models.Base.metadata.create_all(session.get_bind())

org = session.query(models.Organization).filter_by(slug="demo").one_or_none()
if org is None:
    org = models.Organization(slug="demo", name="Demo Workspace")
    session.add(org)
    session.flush()

project = session.query(models.Project).filter_by(org_id=org.id, slug="aurea").one_or_none()
if project is None:
    project = models.Project(org_id=org.id, slug="aurea", name="Aurea Web")
    session.add(project)
    session.flush()

repository = (session.query(models.Repository)
              .filter_by(org_id=org.id, remote_url="https://github.com/bitsentry/aurea-web")
              .one_or_none())
if repository is None:
    repository = models.Repository(
        org_id=org.id, provider="github", name="aurea-web",
        remote_url="https://github.com/bitsentry/aurea-web",
        last_commit_sha="3f9a1c0b8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f70")
    session.add(repository)
    session.flush()

link = (session.query(models.ProjectRepository)
        .filter_by(project_id=project.id, repository_id=repository.id,
                   removed_at=None).one_or_none())
if link is None:
    session.add(models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repository.id,
        added_by="seed"))

api_key = create_key(session, org.id, "demo")
session.commit()

print(json.dumps({
    "org_id": org.id, "project": project.slug,
    "repository": repository.remote_url,
    "commit": repository.last_commit_sha, "api_key": api_key,
}, indent=2))
