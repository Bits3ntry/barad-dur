"""Two screens, one table, read from both ends.

`#vulnerabilities` groups by (signature, component), so one CVE against two
packages is two rows there — correct for the list, useless for the advisory page,
which has to answer "what does this CVE touch here" once. And the component sheet
asks the mirror question: "what does this package carry". These tests pin the two
answers to the same rows, including the asset-only finding that has no component
at all.
"""
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

CVE = "CVE-2021-23337"


@pytest.fixture()
def sheet_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sheets.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "sheets")
    session.commit()

    alpha = models.Project(org_id=org.id, slug="alpha", name="Alpha")
    beta = models.Project(org_id=org.id, slug="beta", name="Beta")
    session.add_all([alpha, beta]); session.flush()

    lodash = models.Component(org_id=org.id, identity_key="pkg:npm/lodash@4.17.20",
                             purl="pkg:npm/lodash@4.17.20", name="lodash",
                             version="4.17.20", license="MIT")
    vite = models.Component(org_id=org.id, identity_key="pkg:npm/vite@5.4.0",
                            purl="pkg:npm/vite@5.4.0", name="vite", version="5.4.0")
    session.add_all([lodash, vite]); session.flush()

    alpha_build = models.ProjectVersion(project_id=alpha.id, version="1.0.0")
    beta_build = models.ProjectVersion(project_id=beta.id, version="2.0.0")
    session.add_all([alpha_build, beta_build]); session.flush()
    session.add_all([
        models.VersionComponent(project_version_id=alpha_build.id,
                                component_id=lodash.id, is_direct=True,
                                manifest_path="package.json"),
        models.VersionComponent(project_version_id=alpha_build.id,
                                component_id=vite.id, is_direct=True),
        # Beta ships lodash only through vite: transitive, with the parent the BOM
        # declared. That pair is what the chain columns read.
        models.VersionComponent(project_version_id=beta_build.id,
                                component_id=vite.id, is_direct=True),
        models.VersionComponent(project_version_id=beta_build.id,
                                component_id=lodash.id, is_direct=False,
                                parent_purl="pkg:npm/vite@5.4.0"),
    ])

    advisory = models.Vulnerability(source_id=CVE, source="sbom", cve_id=CVE,
                                    title="Lodash is vulnerable to command injection "
                                          "through its template function.",
                                    severity="HIGH",
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                                    url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337")
    other = models.Vulnerability(source_id="CVE-2024-0001", source="sbom",
                                 cve_id="CVE-2024-0001", title="Vite serves files",
                                 severity="MEDIUM")
    asset_advisory = models.Vulnerability(source_id="CVE-2024-0002", source="sbom",
                                         cve_id="CVE-2024-0002",
                                         title="WordPress plugin flaw", severity="CRITICAL")
    session.add_all([advisory, other, asset_advisory]); session.flush()

    asset = models.Asset(org_id=org.id, type="domain", value="shop.example.com",
                         source="manual")
    session.add(asset); session.flush()

    detail = json.dumps({"cvss_score": 7.2, "fixed_version": "4.17.21"})
    session.add_all([
        models.Finding(org_id=org.id, project_id=alpha.id, component_id=lodash.id,
                       vulnerability_id=advisory.id, kind="vulnerability",
                       vector="dependency-cve", source="trivy",
                       fingerprint="a-1", title="Command injection", severity="HIGH",
                       status="open", detail=detail,
                       last_seen_version_id=alpha_build.id),
        models.Finding(org_id=org.id, project_id=beta.id, component_id=lodash.id,
                       vulnerability_id=advisory.id, kind="vulnerability",
                       vector="dependency-cve", source="trivy",
                       fingerprint="b-1", title="Command injection", severity="HIGH",
                       status="resolved", detail=detail,
                       last_seen_version_id=beta_build.id),
        models.Finding(org_id=org.id, project_id=alpha.id, component_id=vite.id,
                       vulnerability_id=other.id, kind="vulnerability",
                       vector="dependency-cve", source="trivy",
                       fingerprint="a-2", title="Files served", severity="MEDIUM",
                       status="open", last_seen_version_id=alpha_build.id,
                       # The NVD runtime ingest stores the score as `cvss`, not
                       # `cvss_score`; the page has to read both or it prints
                       # "no CVSS score" on every runtime CVE.
                       detail=json.dumps({"cvss": 5.3})),
        # No component and no project: the asset answers for it.
        models.Finding(org_id=org.id, asset_id=asset.id,
                       vulnerability_id=asset_advisory.id, kind="vulnerability",
                       vector="dependency-cve", source="wpscan",
                       fingerprint="asset-1", title="Plugin flaw", severity="CRITICAL",
                       status="open"),
    ])
    session.add_all([
        models.KevEntry(cve_id=CVE, name="Lodash Command Injection",
                        vendor="Lodash", product="Lodash",
                        description="Lodash command injection.",
                        required_action="Apply updates per vendor instructions.",
                        ransomware="Known", cwes="CWE-78",
                        date_added="2021-03-01", due_date="2021-03-22"),
        models.EpssScore(cve_id=CVE, epss="0.4213", percentile="0.97"),
    ])
    session.commit()

    session.close()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, {"lodash": lodash.id, "vite": vite.id}


def test_the_advisory_page_merges_every_package_that_names_the_cve(sheet_client):
    client, headers, ids = sheet_client
    body = client.get(f"/api/v1/vulnerabilities/advisory/{CVE}", headers=headers).json()
    data = body["data"]
    assert data["cve_id"] == CVE
    # The table is one row per (project, component, build): lodash in two
    # projects is two upgrades, so it is two rows — but one component.
    components = data["affected"]["components"]
    assert len(components) == 2
    assert {row["project"]["slug"] for row in components} == {"alpha", "beta"}
    assert {row["component"]["name"] for row in components} == {"lodash"}
    assert sum(row["findings"] for row in components) == 2
    assert sum(row["open_findings"] for row in components) == 1
    assert all(row["fixed_versions"] == ["4.17.21"] for row in components)
    assert data["affected"]["totals"]["rows"] == 2
    assert data["affected"]["totals"]["components"] == 1
    assert data["affected"]["totals"]["projects"] == 2
    assert data["affected"]["totals"]["builds"] == 2
    # KEV, EPSS and the CVSS the scanner stated all survive the merge.
    assert data["enrichment"]["kev"]["listed"] is True
    assert data["enrichment"]["kev"]["due_date"] == "2021-03-22"
    assert data["enrichment"]["kev"]["required_action"].startswith("Apply updates")
    assert data["cvss"]["score"] == 7.2
    assert data["counters"]["findings"] == 2
    assert data["counters"]["open"] == 1


def test_a_finding_without_a_component_is_an_affected_asset(sheet_client):
    client, headers, _ids = sheet_client
    data = client.get("/api/v1/vulnerabilities/advisory/CVE-2024-0002",
                      headers=headers).json()["data"]
    assert data["affected"]["components"] == []
    assets = data["affected"]["assets"]
    assert len(assets) == 1
    assert assets[0]["asset"]["value"] == "shop.example.com"
    assert assets[0]["severity"] == "CRITICAL"


def test_a_score_stored_under_the_runtime_key_is_still_a_score(sheet_client):
    client, headers, _ids = sheet_client
    data = client.get("/api/v1/vulnerabilities/advisory/CVE-2024-0001",
                      headers=headers).json()["data"]
    assert data["cvss"]["known"] is True
    assert data["cvss"]["score"] == 5.3


def test_an_advisory_nobody_reported_says_so_instead_of_404ing(sheet_client):
    client, headers, _ids = sheet_client
    session = session_factory()()
    session.add(models.KevEntry(cve_id="CVE-2019-0001", name="Never scanned", vendor="X",
                                product="Y", date_added="2019-01-01"))
    session.commit()
    session.close()
    body = client.get("/api/v1/vulnerabilities/advisory/CVE-2019-0001", headers=headers)
    assert body.status_code == 200
    data = body.json()["data"]
    assert data["affected"]["components"] == []
    assert data["coverage"]["estate"].startswith("no finding")
    assert data["coverage"]["note"]


def test_an_unknown_id_is_a_404_not_an_empty_page(sheet_client):
    client, headers, _ids = sheet_client
    assert client.get("/api/v1/vulnerabilities/advisory/CVE-1999-9999",
                      headers=headers).status_code == 404


def test_the_component_sheet_lists_its_advisories_and_where_it_ships(sheet_client):
    client, headers, ids = sheet_client
    data = client.get(f"/api/v1/components/{ids['lodash']}", headers=headers).json()["data"]
    assert data["component"]["name"] == "lodash"
    assert data["component"]["version"] == "4.17.20"
    rows = data["advisories"]
    assert len(rows) == 1
    assert rows[0]["ref"] == CVE
    assert rows[0]["findings"] == 2
    assert rows[0]["kev"] is True
    assert rows[0]["cvss"]["score"] == 7.2
    assert rows[0]["fix"]["versions"] == ["4.17.21"]
    assert rows[0]["projects"] == ["alpha", "beta"]
    # Two builds carry it, one of them transitively.
    assert data["usage"]["totals"]["builds"] == 2
    assert data["usage"]["totals"]["direct"] == 1
    assert {row["project"]["slug"] for row in data["usage"]["projects"]} == {"alpha", "beta"}
    assert data["counters"]["open"] == 1


def test_the_advisory_page_says_how_each_package_got_in(sheet_client):
    """"Affected: lodash" is a fact; "lodash came in through vite" is the decision."""
    client, headers, _ids = sheet_client
    data = client.get(f"/api/v1/vulnerabilities/advisory/{CVE}", headers=headers).json()["data"]
    rows = {row["project"]["slug"]: row for row in data["affected"]["components"]}
    # Alpha declares it in package.json: no parent, and the BOM says so.
    assert rows["alpha"]["direct"] is True
    assert rows["alpha"]["chain"] == []
    # Beta pulls it through vite, and the chain names what to upgrade first.
    assert rows["beta"]["direct"] is False
    assert [hop["name"] for hop in rows["beta"]["chain"]] == ["vite"]
    assert rows["beta"]["chain"][0]["purl"] == "pkg:npm/vite@5.4.0"


def test_the_estate_list_shows_one_row_per_vulnerability(sheet_client):
    """A finding is "this vulnerability, on this component/build" — so the list of
    vulnerabilities prints one row however many subjects carry it."""
    client, headers, _ids = sheet_client
    body = client.get("/api/v1/vulnerabilities", headers=headers).json()
    rows = [row for row in body["data"] if row["cve_id"] == CVE]
    assert len(rows) == 1
    row = rows[0]
    assert row["findings"] == 2
    assert len(row["components"]) == 1
    assert {project["slug"] for project in row["projects"]} == {"alpha", "beta"}
    # The split per package lives on the advisory page: that is where the two
    # upgrades are two lines.
    details = client.get(f"/api/v1/vulnerabilities/advisory/{CVE}",
                         headers=headers).json()["data"]
    assert len(details["affected"]["components"]) == 2
    # The list's own total counts its own rows, not the findings behind them.
    assert body["total"] == len(body["data"])


def test_the_package_sheet_shows_the_chain_that_explains_a_transitive_package(sheet_client):
    client, headers, ids = sheet_client
    data = client.get(f"/api/v1/components/{ids['lodash']}", headers=headers).json()["data"]
    builds = {row["project"]["slug"]: row for group in data["usage"]["projects"]
              for row in group["builds"]}
    assert builds["alpha"]["chain"] == []
    assert [hop["name"] for hop in builds["beta"]["chain"]] == ["vite"]
    # A package the build does not carry has no path to give.
    assert builds["beta"]["direct"] is False


def test_a_component_from_another_organization_is_not_found(sheet_client):
    client, headers, _ids = sheet_client
    assert client.get("/api/v1/components/does-not-exist",
                      headers=headers).status_code == 404
