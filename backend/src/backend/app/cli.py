"""Bootstrap and serve the platform API from one entrypoint."""
import argparse
import sys


def _serve(args) -> int:
    initialize()
    import uvicorn

    uvicorn.run("backend.app.main:app", host=args.host, port=args.port, log_level="info")
    return 0


def initialize() -> None:
    from backend.app.db import run_migrations

    run_migrations()


def _key(args) -> int:
    from backend.app import models
    from backend.app.auth import create_key
    from backend.app.db import session_factory

    initialize()
    session = session_factory()()
    try:
        slug = args.org
        org = session.query(models.Organization).filter_by(slug=slug).one_or_none()
        if org is None:
            import re

            clean = re.sub(r"[^a-z0-9]+", "-", slug.lower()).strip("-") or "org"
            org = models.Organization(slug=clean, name=args.org or clean)
            session.add(org)
            session.flush()
        raw = create_key(session, org.id, args.label)
    finally:
        session.close()
    print(raw)
    print(f"organization={org.slug} label={args.label} (raw key shown once; "
          "store it in the caller's secrets, never in files)", file=sys.stderr)
    return 0


def _migrate(_args) -> int:
    initialize()
    print("migrations: head")
    return 0


def main(argv=None) -> int:
<<<<<<< Updated upstream
    from backend.app.db import load_workspace_env

    # Credentials stay environment variables; the workspace .env is just a
    # convenient source for them when the caller has not exported anything.
    load_workspace_env()
=======
>>>>>>> Stashed changes
    parser = argparse.ArgumentParser(prog="barad-platform")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="run migrations and start the API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8090)
    serve.set_defaults(handler=_serve)

    key = subparsers.add_parser("key", help="create an API key (and org) on first boot")
    key.add_argument("create", help="create subcommand")
    key.add_argument("--org", required=True, help="organization slug; creates it if missing")
    key.add_argument("--label", default="")
    key.set_defaults(handler=_key)

    migrate = subparsers.add_parser("migrate", help="apply migrations and exit")
    migrate.set_defaults(handler=_migrate)

    args = parser.parse_args(argv)
    return args.handler(args)
