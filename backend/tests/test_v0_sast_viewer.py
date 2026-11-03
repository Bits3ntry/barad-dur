"""v0 SAST viewer intake: SARIF + OpenGrep, snapshots, diff and baseline labels.

Both formats are implemented end to end here. The tests also pin the two things
the viewer must never overstate: code that was not supplied (no snapshot), and
the difference between "on a modified line" and "introduced by the change".
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


SARIF = {
    "tool": {"driver": {"name": "OpenGrep", "version": "1.33.1",
                        "rules": [{"id": "python.lang.security.audit.sqli",
                                   "shortDescription": {"text": "SQL injection"},
                                   "properties": {"cwe": "CWE-89",
                                                  "security-severity": "8.8"}}]}},
    "results": [
        {"ruleId": "python.lang.security.audit.sqli", "level": "error",
         "message": {"text": "Query built with user input"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "app/api/reports.py"},
             "region": {"startLine": 12, "endLine": 12,
                        "snippet": {"text": "cursor.execute(sql % name)"}}}}]},
        {"ruleId": "python.lang.security.audit.sqli", "level": "warning",
         "message": {"text": "Second sink"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "app/api/reports.py"},
             "region": {"startLine": 40}}}]},
    ],
}

@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sast.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    other_project = models.Project(org_id=other.id, name="Other", slug="other")
    session.add_all([project, other_project])
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="v3"))
    session.flush()
    key = create_key(session, org.id, "sast")
    other_key = create_key(session, other.id, "sast-other")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key}


SOURCE = "\n".join(f"line {index}" for index in range(1, 61))
DIFF = """--- a/app/api/reports.py
+++ b/app/api/reports.py
@@ -8,7 +8,8 @@ def export(request):
 context 1
 context 2
 context 3
-old line
+cursor.execute(sql % name)
+another added line
 context 4
 context 5
 context 6
"""


def _import(test_client, headers, **overrides):
    body = {
        "project": "aurea", "version": "v3", "format": "sarif",
        "report": SARIF, "coverage": "full", "revision": "deadbeef",
        "branch": "main", "diff": DIFF,
        "files": [{"path": "app/api/reports.py", "content": SOURCE}],
        "actor": "tester",
    }
    body.update(overrides)
    response = test_client.post("/api/v1/analysis/import", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["data"]


def test_sarif_import_creates_findings_files_and_diff_positions(seeded):
    test_client, headers, _other = seeded
    run = _import(test_client, headers)
    counters = run["counters"]
    assert counters["results"] == 2
    assert counters["created"] == 1, "rule+path is the identity; the second line is a sighting"
    assert counters["no_reference"] == 2
    assert counters["on_modified_line"] == 1, "only line 12 is inside the added set"
    assert run["baseline"].startswith("no reference")
    assert run["report_format"] == "sarif"

    files = test_client.get(f"/api/v1/analysis/runs/{run['id']}/files",
                            headers=headers).json()
    assert files["content_available"] is True
    row = files["data"][0]
    assert row["path"] == "app/api/reports.py" and row["findings"] == 2
    assert row["line_count"] == 60

    opened = test_client.get(f"/api/v1/analysis/runs/{run['id']}/file",
                             params={"path": "app/api/reports.py"},
                             headers=headers).json()["data"]
    assert opened["content"] == SOURCE
    assert [item["line"] for item in opened["findings"]] == [12, 40]
    assert opened["findings"][0]["cwe"] == "CWE-89"
    assert opened["findings"][0]["severity"] == "HIGH", "security-severity 8.8 maps to HIGH"
    assert opened["findings"][0]["on_modified_line"] is True
    assert opened["findings"][0]["finding_id"]

    diff = test_client.get(f"/api/v1/analysis/runs/{run['id']}/diff",
                           headers=headers).json()["data"]
    assert diff["available"] is True
    assert diff["touched_lines"] == {"added": 2, "removed": 1}
    assert 12 in diff["files"][0]["added"]
    assert diff["files"][0]["findings"], "the finding is positioned on the diff"
    assert "not thereby" in diff["note"]


def test_reimport_does_not_duplicate_findings(seeded):
    test_client, headers, _other = seeded
    first = _import(test_client, headers)
    second = _import(test_client, headers)
    assert first["counters"]["created"] == 1
    assert second["counters"]["created"] == 0
    assert second["counters"]["existing"] == 2

    findings = test_client.get("/api/v1/findings?project=aurea", headers=headers).json()
    assert findings["total"] == 1, "identity is the rule+path recipe, not the import"


def test_opengrep_json_is_supported(seeded):
    test_client, headers, _other = seeded
    report = {
        "tool": {"name": "opengrep", "version": "1.33.1"},
        "results": [{
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "app/config.py",
            "start": {"line": 5, "col": 1},
            "end": {"line": 5, "col": 30},
            "extra": {"message": "Hardcoded secret", "severity": "ERROR",
                      "lines": "PASSWORD = 'hunter2'",
                      "metadata": {"cwe": ["CWE-798"]}},
        }],
        "errors": [{"message": "skipped vendor/", "type": "PartialParsing"}],
    }
    run = _import(test_client, headers, format="opengrep", report=report,
                  diff=None, files=[])
    assert run["report_format"] == "opengrep"
    assert run["counters"]["created"] == 1

    detail = test_client.get(f"/api/v1/analysis/runs/{run['id']}/findings",
                             headers=headers).json()
    assert detail["data"][0]["cwe"] == "CWE-798"
    assert detail["data"][0]["severity"] == "HIGH"
    assert run["uninterpreted"]["count"] == 1

    files = test_client.get(f"/api/v1/analysis/runs/{run['id']}/files",
                            headers=headers).json()
    reported = files["data"][0]
    assert reported["available"] is False and reported["kind"] == "reported-only"
    opened = test_client.get(f"/api/v1/analysis/runs/{run['id']}/file",
                             params={"path": "app/config.py"}, headers=headers).json()["data"]
    assert opened["available"] is False
    assert "no code snapshot" in opened["reason"]


def test_baseline_labels_new_persistent_resolved(seeded):
    test_client, headers, _other = seeded
    base = _import(test_client, headers)

    extended = {
        "tool": SARIF["tool"],
        "results": SARIF["results"] + [{
            "ruleId": "python.lang.security.audit.sqli", "level": "note",
            "message": {"text": "New on another file"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/web/views.py"},
                "region": {"startLine": 3}}}]}],
    }
    second = _import(test_client, headers, report=extended, base_run_id=base["id"])
    assert second["counters"]["new"] == 1
    assert second["counters"]["persistent"] == 2
    assert second["baseline"] == "comparable"

    shrunk = {"tool": SARIF["tool"], "results": SARIF["results"][:1]}
    third = _import(test_client, headers, report=shrunk, base_run_id=second["id"])
    assert third["counters"]["resolved"] == 1

    resolved = test_client.get(f"/api/v1/analysis/runs/{third['id']}/findings",
                               params={"classification": "resolved"},
                               headers=headers).json()
    assert resolved["total"] == 1
    assert resolved["data"][0]["path"] == "app/web/views.py"


def test_baseline_must_match_tool_and_version(seeded):
    test_client, headers, _other = seeded
    base = _import(test_client, headers)
    other_tool = dict(SARIF["tool"])
    other_tool["driver"] = {**SARIF["tool"]["driver"], "name": "CodeQL"}
    mismatch = test_client.post("/api/v1/analysis/import", json={
        "project": "aurea", "version": "v3", "format": "sarif",
        "report": {"tool": other_tool, "results": SARIF["results"]},
        "base_run_id": base["id"]}, headers=headers)
    assert mismatch.status_code == 409
    assert "another" not in mismatch.json()["detail"] or "tool" in mismatch.json()["detail"]

    unknown = test_client.post("/api/v1/analysis/import", json={
        "project": "aurea", "version": "v3", "format": "sarif",
        "report": SARIF, "base_run_id": "not-a-run"}, headers=headers)
    assert unknown.status_code == 404


def test_viewer_is_isolated_and_validates(seeded):
    test_client, headers, other_headers = seeded
    run = _import(test_client, headers)
    assert test_client.get(f"/api/v1/analysis/runs/{run['id']}/files",
                           headers=other_headers).status_code == 404
    assert test_client.get(f"/api/v1/analysis/runs/{run['id']}/file",
                           params={"path": "app/api/reports.py"},
                           headers=other_headers).status_code == 404
    assert test_client.get(f"/api/v1/analysis/runs/{run['id']}/diff",
                           headers=other_headers).status_code == 404

    bad_format = test_client.post("/api/v1/analysis/import", json={
        "project": "aurea", "format": "nessus", "report": {}}, headers=headers)
    assert bad_format.status_code == 422

    unknown_project = test_client.post("/api/v1/analysis/import", json={
        "project": "nope", "format": "sarif", "report": SARIF}, headers=headers)
    assert unknown_project.status_code == 404


def test_a_run_records_repository_and_pull_request(seeded):
    test_client, headers, _other = seeded
    repo = test_client.post("/api/v1/repositories", json={
        "remote_url": "https://github.com/bitsentry/aurea",
        "name": "aurea", "provider": "github"}, headers=headers).json()["data"]["id"]
    run = _import(test_client, headers, repository_id=repo, pull_request="77")
    assert run["repository"]["id"] == repo
    assert run["pull_request"] == "77"
    assert run["branch"] == "main"

    # The finding knows which run last evaluated it, so the viewer and the
    # finding can link to each other.
    rows = test_client.get(f"/api/v1/analysis/runs/{run['id']}/findings",
                           headers=headers).json()["data"]
    finding_id = rows[0]["finding_id"]
    detail = test_client.get(f"/api/v1/findings/{finding_id}",
                             headers=headers).json()["data"]
    assert detail["analysis_run"]["id"] == run["id"]
    assert detail["analysis_run"]["pull_request"] == "77"
    assert detail["analysis_run"]["revision"] == "deadbeef"


def test_an_unknown_repository_is_rejected(seeded):
    test_client, headers, _other = seeded
    response = test_client.post("/api/v1/analysis/import", json={
        "project": "aurea", "version": "v3", "format": "sarif",
        "report": SARIF, "coverage": "full", "repository_id": "does-not-exist",
        "actor": "tester"}, headers=headers)
    assert response.status_code == 404
