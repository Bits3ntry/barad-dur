"""Runtime CVEs from NVD CPE data: ranges, confidence, and no invented versions."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, runtime_cves  # noqa: E402
from backend.app.db import session_factory  # noqa: E402


def _cve(cve_id="CVE-2025-59465", product=("nodejs", "node.js"), end="22.15.0",
         severity="HIGH", start="22.0.0"):
    return {
        "id": cve_id,
        "published": "2025-10-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "use-after-free in the http2 stack"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 7.5, "baseSeverity": severity,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:{product[0]}:{product[1]}:*:*:*:*:*:*:*:*",
            "versionStartIncluding": start,
            "versionEndExcluding": end,
        }]}]}],
    }


# ---------------------------------------------------------------- intervals

def test_a_pinned_version_is_a_point():
    interval, confidence = runtime_cves.declared_interval("22.14.0")
    assert confidence == "exact"
    assert runtime_cves.overlaps(interval, runtime_cves.Interval((22, 0, 0), True,
                                                               (22, 15, 0), False))
    assert not runtime_cves.overlaps(interval, runtime_cves.Interval((23, 0, 0), True))


def test_a_declared_range_is_a_window_and_says_so():
    interval, confidence = runtime_cves.declared_interval(">=22.12.0 <23")
    assert confidence == "range"
    affected = runtime_cves.Interval((22, 0, 0), True, (22, 15, 0), False)
    assert runtime_cves.overlaps(interval, affected), "22.12-22.15 cae dentro del rango"
    older = runtime_cves.Interval((20, 0, 0), True, (22, 10, 0), False)
    assert not runtime_cves.overlaps(interval, older), "20.x no se solapa con >=22.12"


def test_an_image_tag_is_the_line_it_names():
    interval, confidence = runtime_cves.declared_interval("22-alpine", tag=True)
    assert confidence == "line"
    assert runtime_cves.overlaps(interval, runtime_cves.Interval((22, 9, 0), True,
                                                               (22, 10, 0), False))
    assert not runtime_cves.overlaps(interval, runtime_cves.Interval((24, 0, 0), True))
    line, kind = runtime_cves.declared_interval("3.11-slim", tag=True)
    assert kind == "line"
    assert runtime_cves.overlaps(line, runtime_cves.Interval((3, 11, 4), True))
    assert not runtime_cves.overlaps(line, runtime_cves.Interval((3, 12, 0), True)), \
        "3.11-slim no es todo python 3"
    exact, kind = runtime_cves.declared_interval("22.14.0-alpine", tag=True)
    assert kind == "exact", "un tag con patch completo sí pinnea"
    assert runtime_cves.declared_interval("latest", tag=True) is None


def test_an_unparseable_declaration_is_no_claim():
    assert runtime_cves.declared_interval("") is None
    assert runtime_cves.declared_interval("latest") is None


def test_interval_bounds_are_respected_at_the_edges():
    exclusive_end = runtime_cves.Interval((22, 0, 0), True, (22, 15, 0), False)
    assert runtime_cves.overlaps(runtime_cves.Interval((22, 15, 0), True, (22, 15, 0), True),
                                 exclusive_end) is False
    inclusive_end = runtime_cves.Interval((22, 0, 0), True, (22, 15, 0), True)
    assert runtime_cves.overlaps(runtime_cves.Interval((22, 15, 0), True, (22, 15, 0), True),
                                 inclusive_end) is True


# ---------------------------------------------------------------- cpe shapes

def test_an_explicit_cpe_version_is_matched_exactly():
    cve = _cve()
    cve["configurations"][0]["nodes"][0]["cpeMatch"][0] = {
        "vulnerable": True, "criteria": "cpe:2.3:a:nodejs:node.js:20.11.0:*:*:*:*:*:*:*"}
    prefix = "cpe:2.3:a:nodejs:node.js:"
    ranges = runtime_cves._cpe_intervals(cve, prefix)
    assert runtime_cves.overlaps(runtime_cves.Interval((20, 11, 0), True, (20, 11, 0), True),
                                 ranges[0])
    assert not runtime_cves.overlaps(runtime_cves.Interval((22, 14, 0), True, (22, 14, 0), True),
                                     ranges[0])


def test_a_wildcard_cpe_covers_everything():
    cve = _cve()
    cve["configurations"][0]["nodes"][0]["cpeMatch"][0] = {
        "vulnerable": True, "criteria": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"}
    ranges = runtime_cves._cpe_intervals(cve, "cpe:2.3:a:nodejs:node.js:")
    assert ranges and ranges[0].low is None and ranges[0].high is None
    assert runtime_cves.overlaps(runtime_cves.Interval((1, 0, 0), True), ranges[0])


def test_another_products_cpe_is_ignored():
    cve = _cve()
    cve["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"] = \
        "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
    assert runtime_cves._cpe_intervals(cve, "cpe:2.3:a:nodejs:node.js:") == []


def test_runtime_detection_from_purls():
    generic = models.Component(org_id="o", identity_key="k", purl="pkg:generic/node",
                               name="node", version=">=22.12.0 <23")
    assert runtime_cves.runtime_of(generic) == ("node", ">=22.12.0 <23")
    image = models.Component(org_id="o", identity_key="k", purl="pkg:docker/node@22-alpine",
                             name="node", version="22-alpine")
    assert runtime_cves.runtime_of(image) == ("node", "22-alpine")
    package = models.Component(org_id="o", identity_key="k", purl="pkg:npm/lodash@4.17.21",
                               name="lodash", version="4.17.21")
    assert runtime_cves.runtime_of(package) is None


# ---------------------------------------------------------------- analysis

@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/runtime.db")
    from backend.app.main import create_app  # noqa: F401 — registers models

    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    project = models.Project(org_id=org.id, name="Aurea", slug="aurea")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="main")
    session.add(version)
    session.flush()
    component = models.Component(org_id=org.id, identity_key="pkg:generic/node",
                                 purl="pkg:generic/node", name="node",
                                 version="22.14.0")
    session.add(component)
    session.flush()
    session.add(models.VersionComponent(project_version_id=version.id,
                                        component_id=component.id))
    session.commit()
    yield {"session": session, "org": org, "project": project, "version": version,
           "component": component}
    session.close()


def test_a_node_cve_lands_on_the_runtime_component(env):
    session, org = env["session"], env["org"]
    counters = runtime_cves.analyze(session, org.id, env["project"], env["version"],
                                    fetch=lambda vendor, product: [_cve()])
    session.commit()
    assert counters["findings_created"] == 1
    finding = session.query(models.Finding).one()
    assert finding.source == "nvd" and finding.vector == "runtime-cve"
    assert finding.severity == "HIGH"
    assert finding.component_id == env["component"].id
    assert "CVE-2025-59465" in finding.title
    assert "pinned version" in (finding.detail or "") or "confidence" in (finding.detail or "")


def test_a_rerun_refreshes_instead_of_duplicating(env):
    session, org = env["session"], env["org"]
    for _ in range(2):
        counters = runtime_cves.analyze(session, org.id, env["project"], env["version"],
                                        fetch=lambda vendor, product: [_cve()])
        session.commit()
    assert counters["findings_created"] == 0
    assert counters["findings_refreshed"] == 1
    assert session.query(models.Finding).count() == 1


def test_a_cve_outside_the_range_is_not_reported(env):
    session, org = env["session"], env["org"]
    counters = runtime_cves.analyze(session, org.id, env["project"], env["version"],
                                    fetch=lambda vendor, product: [_cve(end="22.10.0")])
    session.commit()
    assert counters["findings_created"] == 0
    assert session.query(models.Finding).count() == 0


def test_the_same_cve_from_the_artifact_is_not_a_second_row(env):
    """Trivy/OSV may already have said it: one advisory, one finding."""
    session, org = env["session"], env["org"]
    advisory = models.Vulnerability(source_id="CVE-2025-59465", source="osv",
                                    cve_id="CVE-2025-59465", title="http2 uaf",
                                    severity="HIGH")
    session.add(advisory)
    session.flush()
    session.add(models.Finding(org_id=org.id, project_id=env["project"].id,
                               kind="vulnerability", fingerprint="artifact", source="sbom",
                               title="http2 uaf", severity="HIGH",
                               component_id=env["component"].id,
                               vulnerability_id=advisory.id,
                               last_seen_version_id=env["version"].id,
                               first_seen_at=models.utcnow(), last_seen_at=models.utcnow()))
    session.commit()
    counters = runtime_cves.analyze(session, org.id, env["project"], env["version"],
                                    fetch=lambda vendor, product: [_cve()])
    session.commit()
    assert counters["findings_created"] == 0
    assert session.query(models.Finding).count() == 1


def test_an_unmapped_runtime_is_skipped_and_named(env):
    session, org = env["session"], env["org"]
    extra = models.Component(org_id=org.id, identity_key="pkg:generic/elixir",
                             purl="pkg:generic/elixir", name="elixir", version="1.16.0")
    session.add(extra)
    session.flush()
    session.add(models.VersionComponent(project_version_id=env["version"].id,
                                        component_id=extra.id))
    session.commit()
    counters = runtime_cves.analyze(session, org.id, env["project"], env["version"],
                                    fetch=lambda vendor, product: [])
    assert counters["runtimes"] == 2, "node (mapeado) + elixir (sin CPE)"
    assert counters["runtimes_skipped"] == 1
    assert counters["errors"][0]["runtime"] == "elixir"


def test_a_product_fetch_failure_is_reported_not_crashed(env):
    session, org = env["session"], env["org"]

    def boom(vendor, product):
        raise OSError("nvd unreachable")

    counters = runtime_cves.analyze(session, org.id, env["project"], env["version"], fetch=boom)
    assert counters["findings_created"] == 0
    assert counters["errors"][0]["source"] == "nvd"
