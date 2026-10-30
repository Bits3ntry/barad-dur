"""platform_api adapter contract: statuses verified against a stubbed transport."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cli"))
sys.path.insert(0, str(ROOT / "."))

import pytest  # noqa: E402

from integrations import platform_api  # noqa: E402


class _Response:
    def __init__(self, body):
        self._body = body.encode() if isinstance(body, str) else body

    def json(self):
        return json.loads(self._body.decode())


class _StubClient:
    """Replaces HttpClient; records the call and answers with a canned body."""

    def __init__(self, body=None, error=None):
        self.body = body
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.error is not None:
            raise self.error
        return _Response(json.dumps(self.body))


class _Block(dict):
    def __getattribute__(self, item):
        return dict.get(self, item)


class _Settings:
    def __init__(self, enabled=True, endpoint="http://platform.local:8090", token="k-1"):
        self._block = {"enabled": enabled, "endpoint": endpoint, "token_env": "PLATFORM_API_KEY",
                       "timeout_seconds": 15, "max_attempts": 2}
        self.environ = {"PLATFORM_API_KEY": token}

    def block(self, name):
        return self._block

    def endpoint(self, name):
        return self.environ.get("PLATFORM_API_URL") or self._block.get("endpoint")

    def secret_values(self):
        return ["k-1"]


def _manifest(count=3, version="1.0.0"):
    return {
        "project": {"name": "fixture"},
        "application_version": {"value": version},
        "inventory": {"components": count},
        "source": {"target_type": "fs", "target": "/fixture"},
    }


def _receipt_body(status="created", received=3):
    return {"status": status,
            "import_id": "i-1",
            "receipt": {"import_id": "i-1", "project": "fixture", "version": "1.0.0",
                        "counts": {"components_received": received}}}


@pytest.fixture()
def sbom_path(tmp_path):
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [], "dependencies": []}))
    return path


def test_disabled_yields_not_configured(monkeypatch, sbom_path):
    settings = _Settings(enabled=False)
    result = platform_api.synchronize(settings, _manifest(), sbom_path)
    assert result == {"status": "NOT_CONFIGURED"}


def test_missing_configuration_fails(monkeypatch, sbom_path):
    settings = _Settings(endpoint=None)
    result = platform_api.synchronize(settings, _manifest(), sbom_path)
    assert result == {"status": "FAILED", "reason": "connection_not_configured"}


def test_published_requires_matching_remote_count(monkeypatch, sbom_path):
    stub = _StubClient(body=_receipt_body(received=3))
    monkeypatch.setattr(platform_api, "HttpClient", lambda **kwargs: stub)
    manifest = _manifest(count=3)
    result = platform_api.synchronize(_Settings(), manifest, sbom_path)
    assert result["status"] == "PUBLISHED"
    assert result["import_id"] == "i-1"

    stub_mismatch = _StubClient(body=_receipt_body(received=7))
    monkeypatch.setattr(platform_api, "HttpClient", lambda **kwargs: stub_mismatch)
    result = platform_api.synchronize(_Settings(), manifest, sbom_path)
    assert result == {"status": "FAILED", "reason": "inventory_count_mismatch",
                      "remote_components": 7, "local_components": 3}


def test_duplicate_content_is_unchanged(monkeypatch, sbom_path):
    stub = _StubClient(body=_receipt_body(status="duplicate"))
    monkeypatch.setattr(platform_api, "HttpClient", lambda **kwargs: stub)
    result = platform_api.synchronize(_Settings(), _manifest(), sbom_path)
    assert result == {"status": "UNCHANGED", "reason": "content_receipt_verified",
                      "import_id": "i-1"}


def test_identity_mismatch_fails(monkeypatch, sbom_path):
    stub = _StubClient(body={"status": "created", "import_id": "i-1",
                             "receipt": {"import_id": "i-1", "project": "other",
                                         "version": "9.9.9",
                                         "counts": {"components_received": 3}}})
    monkeypatch.setattr(platform_api, "HttpClient", lambda **kwargs: stub)
    result = platform_api.synchronize(_Settings(), _manifest(), sbom_path)
    assert result["status"] == "FAILED"
    assert result["reason"] == "identity_mismatch"


def test_remote_error_is_bounded_and_secret_redacted(monkeypatch, sbom_path):
    from barad.core.http import HttpStatusError, HttpTransportError

    error = HttpStatusError(500, b'{"detail": "k-1 leaked"}', 2, "http://platform.local")
    stub = _StubClient(error=error)
    monkeypatch.setattr(platform_api, "HttpClient", lambda **kwargs: stub)
    result = platform_api.synchronize(_Settings(), _manifest(), sbom_path)
    assert result["status"] == "FAILED"
    assert "k-1" not in json.dumps(result)
    transport = HttpTransportError("connection refused", 2, "http://platform.local")
    stub2 = _StubClient(error=transport)
    monkeypatch.setattr(platform_api, "HttpClient", lambda **kwargs: stub2)
    result = platform_api.synchronize(_Settings(), _manifest(), sbom_path)
    assert result == {"status": "FAILED", "reason": "remote_error", "http_status": None}
