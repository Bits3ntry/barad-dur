"""F1 acceptance tests: OSV matching, advisory catalog, deduped findings."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, vulns  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


def test_parse_purl_maps_ecosystems():
    assert vulns.parse_purl("pkg:pypi/requests@2.32.3") == {
        "ecosystem": "PyPI", "name": "requests"}
    # pypi normalization: underscores and case
    assert vulns.parse_purl("pkg:pypi/Some_Package.Name@1.0") == {
        "ecosystem": "PyPI", "name": "some-package-name"}
    # npm scoped, url-encoded
    assert vulns.parse_purl("pkg:npm/%40scope/lib@1.2.3") == {
        "ecosystem": "npm", "name": "@scope/lib"}
    # unmapped purl type is skipped, never guessed
    assert vulns.parse_purl("pkg:generic/foo@1.0") is None
    assert vulns.parse_purl("not-a-purl") is None


def test_severity_of_database_specific_and_cvss():
    vuln = {"database_specific": {"severity": "MEDIUM"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}]}
    assert vulns.severity_of(vuln) == ("MEDIUM", "CVSS:3.1/AV:N/AC:L")
    assert vulns.severity_of({}) == (None, None)


def _stub(source_id, cve="CVE-2024-0001", severity="HIGH"):
    """Full advisory record as OSV's detail endpoint would return it."""
    return {"id": source_id, "aliases": [cve], "summary": f"Bad thing in {source_id}",
            "modified": "2024-05-20T00:00:00Z",
            "database_specific": {"severity": severity},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N"}],
            "references": [{"type": "WEB", "url": f"https://osv.dev/vulnerability/{source_id}"}],
            "published": "2024-05-20T00:00:00Z"}


def _batch_response(*source_ids):
    """OSV querybatch shape: id + modified only."""
    return {"vulns": [{"id": sid, "modified": "2024-05-20T00:00:00Z"}
                      for sid in source_ids]}


class _Stubs:
    """Both hooks stubbed: batched ids and per-id detail lookups."""

    def __init__(self, batch_results, details=None):
        self.batch = batch_results
        self.details = details or {}
        self.batch_calls = 0
        self.detail_calls = 0

    def fetch(self, queries, *, timeout_seconds=15.0):
        self.batch_calls += 1
        return self.batch

    def fetch_one(self, source_id, *, timeout_seconds=15.0):
        self.detail_calls += 1
        return self.details.get(source_id)


@pytest.fixture()
def stub_env(tmp_path, monkeypatch):
    """A live app client with one org, one project/version, three components."""
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/f1.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "f1")
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    version_row = models.ProjectVersion(project_id=project.id, version="0.1.0")
    session.add(version_row)
    session.flush()
    for purl, identity in (("pkg:pypi/requests@2.32.3", "pkg:pypi/requests@2.32.3"),
                           ("pkg:pypi/urllib3@2.2.1", "pkg:pypi/urllib3@2.2.1"),
                           ("pkg:generic/odd@1.0", "pkg:generic/odd@1.0")):
        component = models.Component(org_id=org.id, identity_key=identity, purl=purl,
                                     name=purl.split("/")[-1])
        session.add(component)
        session.flush()
        session.add(models.VersionComponent(project_version_id=version_row.id,
                                            component_id=component.id))
    session.commit()
    from fastapi.testclient import TestClient

    client = TestClient(app)
    return client, key, session


def test_analyze_creates_findings_with_sources(stub_env):
    client, key, session = stub_env
    stubs = _Stubs(
        [_batch_response("GHSA-fake1"), _batch_response("GHSA-fake2"), {"vulns": []}],
        {"GHSA-fake1": _stub("GHSA-fake1"),
         "GHSA-fake2": _stub("GHSA-fake2", cve="CVE-2024-37891", severity="CRITICAL")})
    monkey = pytest.MonkeyPatch()
    monkey.setattr(vulns, "fetch_batch", stubs.fetch)
    monkey.setattr(vulns, "fetch_detail", stubs.fetch_one)
    try:
        response = client.post("/api/v1/analyze", params={"project": "fixture",
                                                          "version": "0.1.0"},
                               headers={"X-API-Key": key})
        assert response.status_code == 200, response.text
        counts = response.json()["counts"]
        assert counts["advisories_found"] == 2
        assert counts["findings_created"] == 2
        assert counts["details_fetched"] == 2
        # Only the two pypi rows were queried; generic is skipped honestly.
        assert counts["components_queried"] == 2
        assert counts["components_skipped_unmapped"] == 1
        listed = client.get("/api/v1/findings", headers={"X-API-Key": key}).json()
        rows = listed["data"]
        assert listed["total"] == 2
        by_source = {row["source_id"]: row for row in rows}
        assert by_source["GHSA-fake2"]["cve_id"] == "CVE-2024-37891"
        assert by_source["GHSA-fake2"]["severity"] == "CRITICAL"
        assert by_source["GHSA-fake2"]["source_url"].startswith("https://osv.dev/")
        # fingerprint carries org+project+component+advisory, verifiable shape
        for row in rows:
            assert len(row["fingerprint"]) == 64
    finally:
        monkey.undo()
        session.close()


def test_reanalysis_refreshes_never_duplicates(stub_env):
    client, key, session = stub_env
    stubs = _Stubs(
        [_batch_response("GHSA-fake1"), {"vulns": []}, {"vulns": []}] * 2,
        {"GHSA-fake1": _stub("GHSA-fake1")})
    monkey = pytest.MonkeyPatch()
    monkey.setattr(vulns, "fetch_batch", stubs.fetch)
    monkey.setattr(vulns, "fetch_detail", stubs.fetch_one)
    try:
        first = client.post("/api/v1/analyze", params={"project": "fixture",
                                                      "version": "0.1.0"},
                            headers={"X-API-Key": key})
        second = client.post("/api/v1/analyze", params={"project": "fixture",
                                                       "version": "0.1.0"},
                             headers={"X-API-Key": key})
        assert first.json()["counts"]["findings_created"] == 1
        # Second run: the catalog already holds the advisory at the same
        # modified timestamp, so no detail fetch and no duplication.
        assert second.json()["counts"]["findings_created"] == 0
        assert second.json()["counts"]["findings_refreshed"] == 1
        assert second.json()["counts"]["details_fetched"] == 0
        assert client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["total"] == 1
    finally:
        monkey.undo()
        session.close()


def test_osv_failure_does_not_wipe_findings(stub_env):
    import urllib.error

    class _Fail:
        def __call__(self, queries, *, timeout_seconds=15.0):
            raise urllib.error.URLError("osv down")

    client, key, session = stub_env
    ok_stub = _Stubs([_batch_response("GHSA-fake1"), {"vulns": []}, {"vulns": []}],
                     {"GHSA-fake1": _stub("GHSA-fake1")})
    monkey = pytest.MonkeyPatch()
    monkey.setattr(vulns, "fetch_batch", ok_stub.fetch)
    monkey.setattr(vulns, "fetch_detail", ok_stub.fetch_one)
    try:
        client.post("/api/v1/analyze", params={"project": "fixture", "version": "0.1.0"},
                    headers={"X-API-Key": key})
    finally:
        monkey.undo()
    monkey = pytest.MonkeyPatch()
    monkey.setattr(vulns, "fetch_batch", _Fail())
    try:
        response = client.post("/api/v1/analyze",
                               params={"project": "fixture", "version": "0.1.0"},
                               headers={"X-API-Key": key})
        body = response.json()
        assert body["status"] == "error"
        assert "osv request failed" in body["counts"]["error"]
        # Existing findings survive the failed analysis.
        assert client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["total"] == 1
    finally:
        monkey.undo()
        session.close()


def test_truncation_is_reported_not_hidden(stub_env):
    client, key, session = stub_env
    truncated_batch = {"vulns": [{"id": "GHSA-fake1", "modified": "2024-05-20T00:00:00Z"}],
                       "next_page_token": "tok"}
    stubs = _Stubs([truncated_batch, {"vulns": []}, {"vulns": []}],
                   {"GHSA-fake1": _stub("GHSA-fake1")})
    monkey = pytest.MonkeyPatch()
    monkey.setattr(vulns, "fetch_batch", stubs.fetch)
    monkey.setattr(vulns, "fetch_detail", stubs.fetch_one)
    try:
        body = client.post("/api/v1/analyze", params={"project": "fixture",
                                                     "version": "0.1.0"},
                           headers={"X-API-Key": key}).json()
        assert body["counts"]["truncated"] is True
        assert body["counts"]["findings_created"] == 1
    finally:
        monkey.undo()
        session.close()
