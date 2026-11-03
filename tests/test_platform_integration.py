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


def test_findings_mapping_builds_v1_payload_without_match_lines(tmp_path):
    """Secret match text never crosses the boundary; identities become relative."""
    import json

    import integrations.platform_api as adapter

    manifest = {'source': {'target_type': 'fs', 'target': str(tmp_path)}}
    sanitized = tmp_path / 'security.sanitized.json'
    sanitized.write_text(json.dumps({
        'Results': [{
            'Class': 'secret', 'Type': 'aws', 'Target': 'settings.py',
            'Secrets': [{
                'RuleID': 'aws-access-key-id', 'Severity': 'CRITICAL',
                'MatchData': [{'Lines': 'AKIA4TB7NIQKDXL9WP2X', 'Line': 2}],
            }],
        }, {
            'Class': 'config', 'Type': 'dockerfile', 'Target': 'Dockerfile',
            'Misconfigurations': [{
                'ID': 'DS-0002', 'Severity': 'HIGH', 'Title': 'Image user should not be root',
                'CauseMetadata': {'StartLine': 2},
            }],
        }]},))
    sast = tmp_path / 'sast.json'
    sast.write_text(json.dumps({'results': [{
        'check_id': 'cli.barad.rules.python-subprocess-shell-true',
        'path': str(tmp_path / 'app.py'), 'start': {'line': 6},
        'extra': {'severity': 'ERROR', 'message': 'Avoid shell=True', 'lines': 'subprocess.run(cmd, shell=True)'},
    }]}))

    rows = (adapter._trivy_findings(sanitized, manifest)
            + adapter._opengrep_findings(sast, manifest))
    kinds = {row['kind'] for row in rows}
    assert kinds == {'secret', 'misconfiguration', 'code-weakness'}
    secret = rows[0]
    assert secret['rule_id'] == 'aws-access-key-id' and secret['line'] == 2
    blob = json.dumps(rows)
    # Redaction contract: secret match text and SAST match lines never travel.
    # The OpenGrep rule MESSAGE may explain the rule ("Avoid shell=True") but
    # the matched source line must not.
    assert 'AKIA4TB7NIQKDXL9WP2X' not in blob and 'subprocess.run(cmd' not in blob
    opengrep = rows[-1]
    assert opengrep['rule_id'] == 'python-subprocess-shell-true'
    assert opengrep['path'] == 'app.py'  # relative to the scan target
    assert opengrep['severity'] == 'HIGH'


def test_findings_push_reports_ingest_counts(tmp_path, monkeypatch):
    import json

    import integrations.platform_api as adapter

    manifest = {'source': {'target_type': 'fs', 'target': str(tmp_path)},
                'project': {'name': 'fixture'},
                'application_version': {'value': '1.2.0'}}
    sanitized = tmp_path / 'security.sanitized.json'
    sanitized.write_text(json.dumps({'Results': []}))
    sast = tmp_path / 'sast.json'
    sast.write_text(json.dumps({'results': [
        {'check_id': 'r.x', 'path': str(tmp_path / 'a.py'), 'start': {'line': 1},
         'extra': {'severity': 'ERROR', 'message': 'm', 'lines': 'one-liner'}}]}))

    class _Stub:
        def request(self, method, url, **kwargs):
            self.planet = json.loads(kwargs['body'])
            self.url = url
            return type('R', (), {'json': lambda self: {
                'status': 'ingested', 'project': 'fixture', 'version': '1.2.0',
                'counts': {'received': 1, 'created': 1, 'refreshed': 0,
                           'suppressed_by_rule': 0, 'skipped_missing_identity': 0}}})()

    stub = _Stub()
    monkeypatch.setattr(adapter, 'HttpClient', lambda **kwargs: stub)
    settings = _Settings()
    result = adapter.synchronize_findings(settings, manifest, sanitized, sast)
    assert result['status'] == 'INGESTED'
    assert result['counts']['created'] == 1
    assert stub.planet['schema'] == 'barad-findings-v1'
    assert '/api/v1/findings/ingest?source=cli&project=fixture&version=1.2.0' in stub.url


def test_findings_push_skipped_when_sbom_disabled(monkeypatch, tmp_path):
    import integrations.platform_api as adapter

    settings = _Settings(enabled=False)
    result = adapter.synchronize_findings(settings, {}, tmp_path / 'a', tmp_path / 'b')
    assert result == {'status': 'NOT_CONFIGURED'}


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
