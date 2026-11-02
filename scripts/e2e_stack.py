#!/usr/bin/env python3
"""Empty isolated stack for end-to-end acceptance runs.

Unlike `demo_v0.py` (which seeds a full fixture set and then walks the API),
this starts the console on a **blank organization**: everything the boards show
has to be loaded through the interface or through the documented import
endpoints. That is the point — an empty screen has to be honest, and a filled
one has to come from a real write.

    python scripts/e2e_stack.py --port 8099

Prints the API key and writes `barad_e2e_state.json` next to the system temp
dir, so a browser session can authenticate with the same credential.
"""
import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    db_path = args.db or str(Path(tempfile.mkdtemp(prefix="barad-e2e-")) / "e2e.db")
    os.environ["PLATFORM_DATABASE_URL"] = f"sqlite:///{db_path}"

    from backend.app import auth_local, models
    from backend.app.auth import create_key
    from backend.app.db import session_factory
    from backend.app.main import create_app

    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "e2e")
    # A human account, so the flows that need a session (MFA, SSO) can be
    # exercised. Demo credentials on a throwaway database, printed below.
    password = os.environ.get("E2E_PASSWORD") or "bitsentry-demo"
    session.add(models.User(
        org_id=org.id, email="ana@bitsentry.xyz", display_name="Ana (demo)",
        role="owner", status="active",
        password_hash=auth_local.hash_password(password),
        created_at=models.utcnow(), updated_at=models.utcnow()))
    session.commit()
    session.close()

    dist = ROOT / "frontend" / "dist"
    if not dist.is_dir():
        print("frontend/dist missing: run `npm run build --prefix frontend` first")
        return 2
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(dist), html=True), name="console")

    state = Path(tempfile.gettempdir()) / "barad_e2e_state.json"
    state.write_text(json.dumps({"api_key": key, "db": db_path,
                                 "url": f"http://127.0.0.1:{args.port}"}, indent=2))
    print(f"console: http://127.0.0.1:{args.port}/")
    print(f"state:   {state}")
    print("organization: Bitsentry (empty — load data through the interface)")
    print(f"user: ana@bitsentry.xyz · password: {password} (throwaway)")

    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
