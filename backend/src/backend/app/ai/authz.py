"""Who is asking, and may they spend the operator's money (D44).

One implementation for every AI route: the run carries the caller's identity and
role, and a `viewer` can read but not start anything that costs tokens. A service
API key is the org's own machine identity (it already bypasses RBAC by design in
`auth.py`), and it is allowed — a worker token is not: a worker drives jobs, it does
not ask questions on somebody's behalf.
"""
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app import auth
from backend.app.db import get_session


def principal(request: Request, session: Session = Depends(get_session),
              x_api_key: str = Header(default="", alias="X-API-Key"),
              authorization: str = Header(default=""),
              x_worker_token: str = Header(default="", alias="X-Worker-Token")) -> dict:
    return auth.resolve_principal(session, x_api_key, authorization, x_worker_token)


def require_analyst(principal: dict) -> None:
    if principal["kind"] == "api_key":
        return
    if principal["kind"] == "worker":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "worker tokens cannot start AI work")
    if auth.ROLE_RANK.get(principal["role"], -1) < auth.ROLE_RANK["analyst"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"role '{principal['role']}' cannot start an AI run (requires analyst)")


def actor_of(principal: dict) -> str:
    return str(principal.get("email") or principal.get("user_id") or principal["kind"])
