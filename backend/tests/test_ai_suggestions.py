"""The buttons under an answer: offered from a closed vocabulary, verified before shown.

The failure this prevents is a button that 404s. An assistant inventing affordances
teaches the operator to stop clicking, so the model picks from four actions and the
platform drops anything the estate cannot honour — a finding id that does not exist, a
run id from another org, a screen that is not a screen.
"""
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import auth_local, models  # noqa: E402
from backend.app.ai import engine  # noqa: E402
from backend.app.ai import suggestions as suggest  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/suggest.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "suggest")
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def _provider(db):
    db.add(models.AiProvider(name="stub", kind="openai-compatible",
                            base_url="http://llm.test/v1", model="small",
                            secret_cipher="sealed", price_in=1.0, price_out=1.0,
                            is_default=True))
    db.commit()


def test_a_block_becomes_buttons_and_the_prose_stays_clean(client, monkeypatch):
    http, headers, db = client
    org = db.query(models.Organization).one()
    finding = models.Finding(org_id=org.id, kind="vulnerability", source="scanner",
                             title="CVE-1", severity="high", status="open",
                             fingerprint="fp-1")
    db.add(finding)
    _provider(db)
    block = json.dumps({"suggestions": [
        {"action": "validate_finding", "label": "Validar en campo",
         "finding_id": finding.id},
        {"action": "open_screen", "label": "Ver hallazgos", "screen": "findings"},
        {"action": "ask", "label": "¿Y el resto?", "prompt": "¿qué otros proyectos?"},
    ]})
    answer = f"Hay un hallazgo abierto.\n\n```json\n{block}\n```"
    # `monkeypatch`, never a bare assignment: a module global mutated in a test is a
    # global every later test inherits, and the crypto suites fail 41 times in a row
    # with a message about Ed25519 that has nothing to do with the AI code.
    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    monkeypatch.setattr(engine, "complete",
                        lambda *a, **k: {"content": answer, "tool_calls": [],
                                         "tokens_in": 10, "tokens_out": 5})
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    turn = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "¿estamos expuestos?"},
                     headers=headers).json()["data"]["turn"]
    assert turn["content"] == "Hay un hallazgo abierto.", \
        "the json block never reaches the prose"
    assert [s["action"] for s in turn["suggestions"]] == \
        ["validate_finding", "open_screen", "ask"]
    assert turn["suggestions"][0]["prompt"] == \
        f"@angmar validá el impacto de {finding.id}"
    assert turn["suggestions"][1]["href"] == "#findings"


def test_a_button_the_estate_cannot_honour_is_dropped_not_rendered(client):
    http, headers, db = client
    org = db.query(models.Organization).one()
    ok = models.Finding(org_id=org.id, kind="vulnerability", source="scanner",
                        title="CVE-2", severity="high", status="open", fingerprint="fp-2")
    db.add(ok)
    db.commit()
    kept = suggest.validate(db, org, [
        {"action": "validate_finding", "label": "sí", "finding_id": ok.id},
        {"action": "validate_finding", "label": "no", "finding_id": "0" * 32},
        {"action": "create_cycle", "label": "crear ciclo"},        # not in vocabulary
        {"action": "open_screen", "label": "x", "screen": "../etc/passwd"},
        {"action": "open_run", "label": "y", "run_id": "nope"},
        {"action": "ask", "label": "z", "prompt": "ok"},
        {"action": "ask", "label": "cuarta", "prompt": "tercera y última"},
    ])
    # Three survive: one real finding and the two questions. Everything the estate
    # cannot honour is gone — an invented action, a traversal, a missing run.
    assert [s["label"] for s in kept] == ["sí", "z", "cuarta"]
    assert len(kept) == 3, "at most three buttons, always"


def test_no_block_means_no_buttons():
    prose = "Nada que ofrecer."
    text, buttons = suggest.extract(None, None, prose)
    assert text == prose and buttons == []
    text, buttons = suggest.extract(None, None, prose + "\n\n```json\n{broken\n```")
    assert buttons == [], "a malformed block costs the buttons, not the answer"
