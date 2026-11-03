"""v0 inventory: groups, ownership, activity, manual findings, evidence.

These tests are the acceptance contract for slice B of the v0 spec. They assert
behaviour the spec calls out explicitly: an asset keeps its identity and its
links when it leaves a group; a manual IDOR has no invented CVE; re-reporting a
manual finding does not duplicate it; another organization sees none of it.
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


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/v0.db")
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
    key = create_key(session, org.id, "v0")
    other_key = create_key(session, other.id, "v0-other")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _asset(test_client, headers, value="api-aurea.bitsentry.xyz"):
    response = test_client.post("/api/v1/assets", json={
        "type": "domain", "value": value, "actor": "tester"}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]["id"]


def _group(test_client, headers, name="Production"):
    response = test_client.post("/api/v1/inventory/groups", json={
        "name": name, "description": "stuff in production", "tags": ["prod"],
        "actor": "tester"}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


def test_asset_ownership_filters_and_archive(client):
    test_client, headers, _other = client
    asset_id = _asset(test_client, headers)
    patched = test_client.patch(f"/api/v1/assets/{asset_id}", json={
        "owner": "ana@bitsentry.xyz", "project": "aurea",
        "classification_status": "confirmed", "actor": "tester"}, headers=headers)
    assert patched.status_code == 200, patched.text
    data = patched.json()["data"]
    assert data["owner"] == "ana@bitsentry.xyz"
    assert data["project"] == "aurea"
    assert data["classification_status"] == "confirmed"

    filtered = test_client.get("/api/v1/assets?classification=confirmed&q=aurea",
                               headers=headers).json()
    assert filtered["total"] == 1
    assert filtered["data"][0]["id"] == asset_id

    assert test_client.post(f"/api/v1/assets/{asset_id}/archive?actor=tester",
                            headers=headers).status_code == 200
    assert test_client.get("/api/v1/assets", headers=headers).json()["total"] == 0
    assert test_client.get("/api/v1/assets?include_archived=true",
                           headers=headers).json()["total"] == 1

    invalid = test_client.patch(f"/api/v1/assets/{asset_id}", json={
        "classification_status": "totally-ours"}, headers=headers)
    assert invalid.status_code == 422


def test_group_membership_is_nm_and_removal_keeps_the_asset(client):
    test_client, headers, _other = client
    asset_id = _asset(test_client, headers)
    prod = _group(test_client, headers, "Production")
    edge = _group(test_client, headers, "Edge")

    added = test_client.post(f"/api/v1/inventory/groups/{prod}/assets", json={
        "asset_ids": [asset_id], "actor": "tester"}, headers=headers)
    assert added.status_code == 200, added.text
    assert added.json()["data"]["member_count"] == 1
    test_client.post(f"/api/v1/inventory/groups/{edge}/assets", json={
        "asset_ids": [asset_id], "actor": "tester"}, headers=headers)

    asset = test_client.get(f"/api/v1/assets?q=aurea", headers=headers).json()["data"][0]
    assert {g["name"] for g in asset["groups"]} == {"Production", "Edge"}

    removed = test_client.delete(
        f"/api/v1/inventory/groups/{prod}/assets/{asset_id}?actor=tester",
        headers=headers)
    assert removed.status_code == 200, removed.text
    assert removed.json()["data"]["member_count"] == 0
    after_removal = test_client.get(f"/api/v1/inventory/groups/{prod}",
                                    headers=headers).json()["data"]
    assert len(after_removal["removed_members"]) == 1

    still_there = test_client.get(f"/api/v1/assets?q=aurea", headers=headers).json()
    assert still_there["total"] == 1
    assert [g["name"] for g in still_there["data"][0]["groups"]] == ["Edge"]

    # Re-adding revives the same edge instead of creating a second one; the
    # removal stays visible in the activity ledger.
    revived = test_client.post(f"/api/v1/inventory/groups/{prod}/assets", json={
        "asset_ids": [asset_id], "actor": "tester"}, headers=headers).json()
    assert revived["added"] == ["api-aurea.bitsentry.xyz"]
    detail = test_client.get(f"/api/v1/inventory/groups/{prod}", headers=headers).json()
    assert detail["data"]["member_count"] == 1
    assert detail["data"]["removed_members"] == []
    actions = {row["action"] for row in test_client.get(
        f"/api/v1/activity?asset_id={asset_id}", headers=headers).json()["data"]}
    assert {"inventory_group.assets_added",
            "inventory_group.asset_removed"} <= actions


def test_deleting_a_group_keeps_assets_and_their_relations(client):
    test_client, headers, _other = client
    asset_id = _asset(test_client, headers)
    group_id = _group(test_client, headers)
    test_client.post(f"/api/v1/inventory/groups/{group_id}/assets", json={
        "asset_ids": [asset_id], "actor": "tester"}, headers=headers)

    deleted = test_client.delete(
        f"/api/v1/inventory/groups/{group_id}?actor=tester", headers=headers)
    assert deleted.status_code == 200, deleted.text
    assert test_client.get("/api/v1/inventory/groups", headers=headers).json()["total"] == 0
    assert test_client.get("/api/v1/assets", headers=headers).json()["total"] == 1


def test_group_isolation_between_organizations(client):
    test_client, headers, other_headers = client
    group_id = _group(test_client, headers)
    foreign = test_client.get(f"/api/v1/inventory/groups/{group_id}",
                              headers=other_headers)
    assert foreign.status_code == 404

    asset_id = _asset(test_client, headers)
    cross = test_client.post(f"/api/v1/inventory/groups/{group_id}/assets", json={
        "asset_ids": [asset_id]}, headers=other_headers)
    assert cross.status_code == 404
    assert _asset(test_client, other_headers, "api.other.example")


def test_needs_attention_explains_what_is_missing(client):
    test_client, headers, _other = client
    asset_id = _asset(test_client, headers)
    queue = test_client.get("/api/v1/assets/needs-attention", headers=headers).json()
    assert queue["total"] == 1
    codes = {reason["code"] for reason in queue["data"][0]["reasons"]}
    assert {"no_owner", "no_project", "ownership_unconfirmed", "no_deployment"} <= codes
    for reason in queue["data"][0]["reasons"]:
        assert reason["action"]

    test_client.patch(f"/api/v1/assets/{asset_id}", json={
        "owner": "ana@bitsentry.xyz", "project": "aurea",
        "classification_status": "confirmed"}, headers=headers)
    remaining = test_client.get("/api/v1/assets/needs-attention",
                               headers=headers).json()
    codes = {reason["code"] for reason in remaining["data"][0]["reasons"]}
    assert "no_owner" not in codes and "no_project" not in codes


def test_activity_feed_reports_the_same_records(client):
    test_client, headers, other_headers = client
    asset_id = _asset(test_client, headers)
    group_id = _group(test_client, headers)
    test_client.post(f"/api/v1/inventory/groups/{group_id}/assets", json={
        "asset_ids": [asset_id], "actor": "tester"}, headers=headers)

    feed = test_client.get(f"/api/v1/activity?asset_id={asset_id}",
                           headers=headers).json()
    actions = {row["action"] for row in feed["data"]}
    assert {"asset.added", "inventory_group.created", "inventory_group.assets_added"} <= actions
    assert all(row["actor"] for row in feed["data"])

    assert test_client.get(f"/api/v1/activity?asset_id={asset_id}",
                           headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/activity", headers=other_headers).json()["total"] == 0


def test_manual_idor_has_no_cve_and_does_not_duplicate(client):
    test_client, headers, _other = client
    payload = {
        "project": "aurea", "kind": "code-weakness", "title": "IDOR on invoice export",
        "severity": "high", "path": "app/api/invoices.py", "line": 42,
        "cwe": "CWE-639", "impact": "any authenticated user reads another tenant's invoices",
        "recommendation": "authorize by tenant before serializing",
        "reproduction": "GET /invoices/123 with another tenant's session",
        "assignee": "ana@bitsentry.xyz", "actor": "tester",
    }
    created = test_client.post("/api/v1/findings", json=payload, headers=headers)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["already_known"] is False
    finding_id = body["data"]["id"]

    detail = test_client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()["data"]
    assert detail["cve_id"] is None
    assert detail["source_id"] is None
    assert detail["cwe"] == "CWE-639"
    assert detail["severity"] == "HIGH"
    assert detail["assignee"] == "ana@bitsentry.xyz"

    listed = test_client.get("/api/v1/findings?q=IDOR&project=aurea",
                             headers=headers).json()
    assert listed["total"] == 1
    assert listed["data"][0]["id"] == finding_id
    assert listed["data"][0]["cve_id"] is None

    again = test_client.post("/api/v1/findings", json=payload, headers=headers)
    assert again.json()["already_known"] is True
    assert again.json()["data"]["id"] == finding_id

    foreign = test_client.get(f"/api/v1/findings/{finding_id}",
                              headers=client[2])
    assert foreign.status_code == 404


def test_assignment_comments_and_evidence(client):
    test_client, headers, other_headers = client
    finding_id = test_client.post("/api/v1/findings", json={
        "project": "aurea", "kind": "misconfiguration", "title": "S3 bucket public",
        "severity": "critical", "actor": "tester"}, headers=headers).json()["data"]["id"]

    assigned = test_client.patch(f"/api/v1/findings/{finding_id}/assignee", json={
        "assignee": "ana@bitsentry.xyz", "actor": "tester"}, headers=headers).json()
    assert assigned["data"]["assignee"] == "ana@bitsentry.xyz"

    comment = test_client.post(f"/api/v1/findings/{finding_id}/comments", json={
        "body": "confirmed on staging too", "author": "tester"}, headers=headers)
    assert comment.status_code == 201, comment.text
    assert test_client.get(f"/api/v1/findings/{finding_id}/comments",
                           headers=headers).json()["total"] == 1

    evidence = test_client.post(f"/api/v1/findings/{finding_id}/attachments", json={
        "name": "request.txt", "content": "GET /invoices/123 -> 200", "added_by": "tester"},
        headers=headers)
    assert evidence.status_code == 201, evidence.text
    meta = evidence.json()["data"]
    assert meta["redaction_state"] == "unreviewed"

    listed = test_client.get(f"/api/v1/findings/{finding_id}/attachments",
                             headers=headers).json()
    assert listed["total"] == 1
    read = test_client.get(
        f"/api/v1/findings/{finding_id}/attachments/{meta['id']}", headers=headers).json()
    assert read["data"]["content"] == "GET /invoices/123 -> 200"

    assert test_client.get(f"/api/v1/findings/{finding_id}/comments",
                           headers=other_headers).status_code == 404
    assert test_client.get(
        f"/api/v1/findings/{finding_id}/attachments/{meta['id']}",
        headers=other_headers).status_code == 404
