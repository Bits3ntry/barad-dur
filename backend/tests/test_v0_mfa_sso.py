"""Optional TOTP second factor and SSO for pre-registered users."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import auth_local, mfa, models  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

PASSWORD = "correct horse battery staple"


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/mfa.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    session.add(org)
    session.flush()
    user = models.User(org_id=org.id, email="ana@bitsentry.xyz", display_name="Ana",
                       role="admin", status="active",
                       password_hash=auth_local.hash_password(PASSWORD),
                       created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(user)
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), session, user


def _login(test_client, **overrides):
    body = {"email": "ana@bitsentry.xyz", "password": PASSWORD}
    body.update(overrides)
    return test_client.post("/api/v1/auth/login", json=body)


def _session_headers(test_client):
    response = _login(test_client)
    assert response.status_code == 200
    token = response.json()["session"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _code(secret: str) -> str:
    import time

    return mfa.code_at(secret, int(time.time() // mfa.STEP_SECONDS))


def test_mfa_is_off_by_default_and_login_issues_a_session(seeded):
    test_client, _session, _user = seeded
    body = _login(test_client).json()
    assert body["session"]["access_token"]
    assert "mfa_required" not in body["data"]


def test_enrolment_needs_the_password_and_activation_needs_a_code(seeded):
    test_client, _session, _user = seeded
    headers = _session_headers(test_client)

    assert test_client.get("/api/v1/auth/mfa", headers=headers).json()["data"] == {
        "enabled": False, "enrolled_at": None, "pending": False,
        "recovery_codes_left": 0}

    wrong = test_client.post("/api/v1/auth/mfa/enroll", json={"password": "nope"},
                             headers=headers)
    assert wrong.status_code == 403

    enrol = test_client.post("/api/v1/auth/mfa/enroll",
                             json={"password": PASSWORD}, headers=headers).json()["data"]
    assert enrol["otpauth"].startswith("otpauth://totp/")
    secret = enrol["secret"]

    status = test_client.get("/api/v1/auth/mfa", headers=headers).json()["data"]
    assert status["enabled"] is False and status["pending"] is True

    # A wrong code must not switch the factor on.
    assert test_client.post("/api/v1/auth/mfa/activate", json={"code": "000000"},
                            headers=headers).status_code == 400
    activated = test_client.post("/api/v1/auth/mfa/activate",
                                 json={"code": _code(secret)}, headers=headers).json()["data"]
    assert activated["enabled"] is True
    assert len(activated["recovery_codes"]) == 8


def test_login_returns_a_challenge_until_the_code_is_proven(seeded):
    test_client, _session, _user = seeded
    headers = _session_headers(test_client)
    secret = test_client.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD},
                              headers=headers).json()["data"]["secret"]
    test_client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)},
                     headers=headers)

    challenged = _login(test_client)
    assert challenged.status_code == 200
    body = challenged.json()["data"]
    assert body["mfa_required"] is True
    assert "session" not in challenged.json()
    challenge = body["challenge"]

    bad = test_client.post("/api/v1/auth/mfa/verify",
                           json={"challenge": challenge, "code": "000000"})
    assert bad.status_code == 401

    ok = test_client.post("/api/v1/auth/mfa/verify",
                          json={"challenge": challenge, "code": _code(secret)})
    assert ok.status_code == 200
    assert ok.json()["session"]["access_token"]

    # The challenge is single use.
    again = test_client.post("/api/v1/auth/mfa/verify",
                             json={"challenge": challenge, "code": _code(secret)})
    assert again.status_code == 401


def test_a_recovery_code_works_once_and_only_for_its_owner(seeded):
    test_client, _session, _user = seeded
    headers = _session_headers(test_client)
    secret = test_client.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD},
                              headers=headers).json()["data"]["secret"]
    codes = test_client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)},
                             headers=headers).json()["data"]["recovery_codes"]

    first = _login(test_client).json()["data"]
    ok = test_client.post("/api/v1/auth/mfa/verify",
                          json={"challenge": first["challenge"], "code": codes[0]})
    assert ok.status_code == 200

    second = _login(test_client).json()["data"]
    reused = test_client.post("/api/v1/auth/mfa/verify",
                              json={"challenge": second["challenge"], "code": codes[0]})
    assert reused.status_code == 401, "a recovery code is a one-time secret"


def test_disable_requires_a_valid_code_and_clears_the_factor(seeded):
    test_client, session, user = seeded
    headers = _session_headers(test_client)
    secret = test_client.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD},
                              headers=headers).json()["data"]["secret"]
    test_client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)},
                     headers=headers)

    assert test_client.post("/api/v1/auth/mfa/disable", json={"code": "000000"},
                            headers=headers).status_code == 400
    assert test_client.post("/api/v1/auth/mfa/disable", json={"code": _code(secret)},
                            headers=headers).status_code == 200
    session.expire_all()
    assert session.get(models.User, user.id).totp_secret is None
    # And login is single-factor again.
    assert "session" in _login(test_client).json()


def test_mfa_settings_refuse_api_keys(seeded):
    test_client, session, user = seeded
    key = auth_local.new_session_token()
    session.add(models.ApiKey(org_id=user.org_id,
                              key_hash=auth_local.token_hash(key), label="svc"))
    session.commit()
    response = test_client.get("/api/v1/auth/mfa", headers={"X-API-Key": key})
    assert response.status_code == 403


def _sso_env(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("OIDC_CLIENT_ID", "client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://barad.test/api/v1/auth/oidc/callback")


def test_sso_does_not_create_accounts(seeded, monkeypatch):
    test_client, session, user = seeded
    _sso_env(monkeypatch)
    monkeypatch.setattr(auth_local, "exchange_code", lambda code: {"id_token": "x"})
    monkeypatch.setattr(auth_local, "verify_id_token",
                        lambda token, nonce=None: {"email": "stranger@elsewhere.test"})
    state = "state-unknown"
    session.add(models.OidcState(
        org_id=user.org_id, state_hash=auth_local.token_hash(state), nonce="n",
        created_at=models.utcnow(), expires_at=auth_local.session_expiry(24)))
    session.commit()

    response = test_client.get(f"/api/v1/auth/oidc/callback?code=c&state={state}")
    assert response.status_code == 403
    assert response.json()["detail"].startswith("no account")
    assert session.query(models.User).filter_by(
        email="stranger@elsewhere.test").one_or_none() is None


def test_sso_signs_in_a_registered_user(seeded, monkeypatch):
    test_client, session, user = seeded
    _sso_env(monkeypatch)
    monkeypatch.setattr(auth_local, "exchange_code", lambda code: {"id_token": "x"})
    monkeypatch.setattr(auth_local, "verify_id_token",
                        lambda token, nonce=None: {"email": "ana@bitsentry.xyz"})
    state = "state-known"
    session.add(models.OidcState(
        org_id=user.org_id, state_hash=auth_local.token_hash(state), nonce="n",
        created_at=models.utcnow(), expires_at=auth_local.session_expiry(24)))
    session.commit()

    response = test_client.get(f"/api/v1/auth/oidc/callback?code=c&state={state}")
    assert response.status_code == 200
    assert response.json()["session"]["access_token"]


def test_sso_still_asks_for_the_second_factor(seeded, monkeypatch):
    test_client, session, user = seeded
    _sso_env(monkeypatch)
    monkeypatch.setattr(auth_local, "exchange_code", lambda code: {"id_token": "x"})
    monkeypatch.setattr(auth_local, "verify_id_token",
                        lambda token, nonce=None: {"email": "ana@bitsentry.xyz"})
    headers = _session_headers(test_client)
    secret = test_client.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD},
                              headers=headers).json()["data"]["secret"]
    test_client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)},
                     headers=headers)

    state = "state-mfa"
    session.add(models.OidcState(
        org_id=user.org_id, state_hash=auth_local.token_hash(state), nonce="n",
        created_at=models.utcnow(), expires_at=auth_local.session_expiry(24)))
    session.commit()
    response = test_client.get(f"/api/v1/auth/oidc/callback?code=c&state={state}")
    assert response.status_code == 200
    assert response.json()["data"]["mfa_required"] is True
    assert "session" not in response.json()
