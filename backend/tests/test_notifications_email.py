"""Email notification channels against a real local SMTP server."""
import socket
import sys
import threading
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

MESSAGES = []


def _smtp_server():
    """Minimal SMTP sink: enough of the protocol for smtplib.send_message."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)

    def handle(conn):
        data_buffer = []
        conn.sendall(b"220 stub ESMTP\r\n")
        in_data = False
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            if in_data:
                data_buffer.append(chunk)
                if b"\r\n.\r\n" in chunk:
                    in_data = False
                    MESSAGES.append(b"".join(data_buffer))
                    data_buffer = []
                    conn.sendall(b"250 queued\r\n")
                continue
            # smtplib may pipeline several commands into one recv
            for raw_line in chunk.split(b"\r\n"):
                # smtplib lowercases commands until EHLO succeeds
                line = raw_line.strip().upper()
                if not line:
                    continue
                if line.startswith((b"EHLO", b"HELO")):
                    conn.sendall(b"250-stub\r\n250 8BITMIME\r\n")
                elif line.startswith(b"MAIL FROM") or line.startswith(b"RCPT TO"):
                    conn.sendall(b"250 ok\r\n")
                elif line.startswith(b"DATA"):
                    in_data = True
                    conn.sendall(b"354 go ahead\r\n")
                elif line.startswith(b"QUIT"):
                    conn.sendall(b"221 bye\r\n")
                    return conn.close()
                else:
                    conn.sendall(b"250 ok\r\n")
        conn.close()

    def loop():
        while True:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return sock, sock.getsockname()[1]


@pytest.fixture(scope="module")
def smtp_server():
    sock, port = _smtp_server()
    yield port
    sock.close()


@pytest.fixture()
def mail_client(tmp_path, monkeypatch, smtp_server):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/mail.db")
    monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_PORT", str(smtp_server))
    monkeypatch.setenv("SMTP_FROM", "barad@example.dev")
    MESSAGES.clear()
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "mail")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}


def test_email_channel_validation(mail_client):
    test_client, headers = mail_client
    no_at = test_client.post("/api/v1/notifications/channels", json={
        "name": "bad-email", "kind": "email", "url": "not-an-address",
        "actor": "santiago"}, headers=headers)
    assert no_at.status_code == 422
    bad_kind = test_client.post("/api/v1/notifications/channels", json={
        "name": "x", "kind": "pager", "url": "https://example.dev",
        "actor": "santiago"}, headers=headers)
    assert bad_kind.status_code == 422


def test_email_test_delivery(mail_client):
    test_client, headers = mail_client
    channel = test_client.post("/api/v1/notifications/channels", json={
        "name": "secops", "kind": "email", "url": "secops@example.dev",
        "events": ["test"], "actor": "santiago"}, headers=headers).json()["data"]
    response = test_client.post(
        f"/api/v1/notifications/channels/{channel['id']}/test",
        json={"actor": "santiago"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["data"]["delivered"] is True
    assert MESSAGES, "the SMTP sink received nothing"
    raw = MESSAGES[0].decode(errors="replace")
    assert "To: secops@example.dev" in raw
    assert "From: barad@example.dev" in raw
    assert "Barad-dûr" in raw


def test_email_sla_tick_and_unconfigured_smtp(mail_client, monkeypatch):
    test_client, headers = mail_client
    channel = test_client.post("/api/v1/notifications/channels", json={
        "name": "sla-mail", "kind": "email", "url": "oncall@example.dev",
        "events": ["sla.breached"], "actor": "santiago"}, headers=headers).json()["data"]
    tick = test_client.post("/api/v1/notifications/tick",
                            json={"actor": "cron"}, headers=headers).json()["data"]
    # no overdue findings in this fixture: nothing to send, and that is honest
    assert tick["breached"] == 0
    assert tick["deliveries"] == []

    monkeypatch.delenv("SMTP_HOST", raising=False)
    sent = test_client.post(
        f"/api/v1/notifications/channels/{channel['id']}/test",
        json={"actor": "santiago"}, headers=headers).json()["data"]
    assert sent["delivered"] is False
    assert sent["error"].startswith("smtp_not_configured")
