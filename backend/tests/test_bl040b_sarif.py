"""BL-040b acceptance: SARIF ingestion and baseline diff."""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


def _run(results, rules=None):
    return {
        "tool": {"driver": {"name": "OpenGrep", "rules": rules or []}},
        "results": results,
    }


def _result(rule, path, line=1, level="error", text=None, security=None):
    out = {
        "ruleId": rule, "level": level,
        "message": {"text": text or f"issue {rule}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line}}}],
    }
    if security is not None:
        out["properties"] = {"security-severity": security}
    return out


@pytest.fixture()
def sarif_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sarif.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "sarif")
    other_key = create_key(session, other.id, "sarif2")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    session.add_all([
        models.ProjectVersion(project_id=project.id, version="1.0"),
        models.ProjectVersion(project_id=project.id, version="1.1"),
    ])
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key},
            {"X-API-Key": other_key}, session)


def _ingest(test_client, headers, version, run):
    return test_client.post(
        f"/api/v1/sarif?project=saria&version={version}",
        json={"run": run}, headers=headers)


def test_sarif_ingest_creates_findings_and_occurrences(sarif_client):
    test_client, headers, _other, _session = sarif_client
    run = _run([
        _result("python.lang.security.audit.subprocess-shell-true",
                "app/main.py", 42, text="Use of shell=True"),
        _result("python.lang.security.deserialization.pickle",
                "app/io.py", 7, level="warning"),
    ])
    response = _ingest(test_client, headers, "1.0", run)
    assert response.status_code == 200, response.text
    counts = response.json()["counts"]
    assert counts == {"received": 2, "created": 2, "existing": 0, "skipped": 0}

    findings = test_client.get("/api/v1/findings?project=saria&version=1.0",
                               headers=headers).json()
    assert findings["total"] == 2
    rows = {row["rule_id"]: row for row in findings["data"]}
    shell = rows["python.lang.security.audit.subprocess-shell-true"]
    assert shell["severity"] == "HIGH"
    assert shell["path"] == "app/main.py"
    assert shell["line"] == 42
    assert shell["kind"] == "code-weakness"
    assert shell["tool"] == "OpenGrep"

    occ = test_client.get(f"/api/v1/findings/{shell['id']}/occurrences",
                          headers=headers).json()
    assert occ["total"] == 1

    # Idempotent re-ingest: same findings, no duplicates.
    again = _ingest(test_client, headers, "1.0", run).json()["counts"]
    assert again == {"received": 2, "created": 0, "existing": 2, "skipped": 0}


def test_security_severity_property_overrides_level(sarif_client):
    test_client, headers, _other, _session = sarif_client
    run = _run([
        _result("py/hardcoded-creds", "config.py", 3, level="note",
                security="9.8"),
    ])
    assert _ingest(test_client, headers, "1.0", run).status_code == 200
    finding = test_client.get("/api/v1/findings?project=saria&version=1.0",
                              headers=headers).json()["data"][0]
    assert finding["severity"] == "CRITICAL"


def test_diff_labels_new_and_absent_without_fixed_claims(sarif_client):
    test_client, headers, _other, _session = sarif_client
    base_run = _run([
        _result("rule-a", "a.py"), _result("rule-b", "b.py"),
    ])
    current_run = _run([
        _result("rule-a", "a.py"), _result("rule-c", "c.py"),
    ])
    _ingest(test_client, headers, "1.0", base_run)
    _ingest(test_client, headers, "1.1", current_run)

    diff = test_client.get(
        "/api/v1/sarif/diff?project=saria&version=1.1&baseline=1.0",
        headers=headers).json()["data"]
    assert [row["rule_id"] for row in diff["new"]] == ["rule-c"]
    assert [row["rule_id"] for row in diff["absent_from_current_scan"]] == ["rule-b"]
    assert diff["common"] == 1
    assert "does not" in diff["note"] and "assert remediation" in diff["note"]


def test_rbac_isolation_and_bad_payloads(sarif_client):
    test_client, headers, other_headers, _session = sarif_client
    run = _run([_result("r", "f.py")])
    _ingest(test_client, headers, "1.0", run)
    # foreign org cannot see the project's findings
    foreign = _ingest(test_client, other_headers, "1.0", run)
    assert foreign.status_code == 404
    # skipped results without location
    partial = _run([{"ruleId": "no-loc", "message": {"text": "x"}}])
    counts = _ingest(test_client, headers, "1.0", partial).json()["counts"]
    assert counts["skipped"] == 1 and counts["received"] == 0
    # unknown version
    bad = _ingest(test_client, headers, "9.9", run)
    assert bad.status_code == 404
