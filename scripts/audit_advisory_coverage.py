#!/usr/bin/env python
"""Are we hiding CVEs? Ask the sources, not the console.

Read-only coverage audit over every *current* build (the newest version of each
project component):

1. packages — every component with a resolvable purl and a version is asked
   again of OSV, and each advisory it returns must exist as a finding for that
   component, either under its own id or under the CVE it aliases (the platform
   dedupes by CVE, so a GHSA row can legitimately answer for a CVE report);
2. runtimes — `pkg:generic/*` and `pkg:docker/*` rows are re-matched against
   NVD's CPE ranges with the same logic the clock uses.

It never writes. What it *cannot* check is reported as a gap of the inventory,
not as a clean result: an unmapped ecosystem or a missing version is "unknown",
and saying so is the whole point.

    python scripts/audit_advisory_coverage.py
    python scripts/audit_advisory_coverage.py --json > coverage.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))


def _database_url() -> str:
    """The live database, read the way the app reads it."""
    if os.environ.get("PLATFORM_DATABASE_URL"):
        return os.environ["PLATFORM_DATABASE_URL"]
    password = ""
    env_file = ROOT / ".env"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            if line.startswith("barad_db_password="):
                password = line.split("=", 1)[1].strip()
    return (f"postgresql+psycopg://barad:{urllib.parse.quote(password)}"
            f"@127.0.0.1:15443/barad_platform")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    parser.add_argument("--show", type=int, default=25, help="how many gaps to print")
    args = parser.parse_args(argv)
    os.environ.setdefault("PLATFORM_DATABASE_URL", _database_url())

    from backend.app import models, runtime_cves, vulns
    from backend.app.db import session_factory

    session = session_factory()()
    report = {"builds": 0, "components": 0, "checked": 0, "osv_advisories": 0,
              "reported": 0, "missing": [], "runtime_expected": 0,
              "unmapped": [], "no_version": [], "errors": []}

    # The current builds: newest version per (project, component).
    versions: dict[tuple, models.ProjectVersion] = {}
    for version in (session.query(models.ProjectVersion)
                    .order_by(models.ProjectVersion.created_at.desc()).all()):
        versions.setdefault((version.project_id, version.component_id), version)
    report["builds"] = len(versions)

    osv_rows = []
    runtime_rows = []
    for _key, version in versions.items():
        project = session.get(models.Project, version.project_id)
        label = f"{project.slug}/{version.version}"
        rows = (session.query(models.VersionComponent, models.Component)
                .join(models.Component,
                      models.VersionComponent.component_id == models.Component.id)
                .filter(models.VersionComponent.project_version_id == version.id).all())
        for _link, component in rows:
            report["components"] += 1
            purl = component.purl or ""
            if purl.startswith(("pkg:generic/", "pkg:docker/")):
                parsed = runtime_cves.runtime_of(component)
                if parsed:
                    runtime_rows.append((label, component, version.id, purl, parsed))
                continue
            parsed_purl = vulns.parse_purl(purl)
            if parsed_purl is None:
                report["unmapped"].append({"build": label, "component": component.name,
                                           "purl": purl})
                continue
            if not component.version:
                report["no_version"].append({"build": label, "component": component.name,
                                             "purl": purl})
                continue
            osv_rows.append((label, component, version.id, parsed_purl))

    # 1. packages, asked again of OSV.
    queries = [{"package": parsed, "version": component.version}
               for _label, component, _vid, parsed in osv_rows]
    results: list = []
    for start in range(0, len(queries), 500):
        chunk = queries[start:start + 500]
        try:
            results.extend(vulns.fetch_batch(chunk))
        except Exception as error:  # noqa: BLE001 — an outage is reported, not hidden
            report["errors"].append(f"osv batch {start}: {type(error).__name__}: {error}")
            results.extend([{} for _ in chunk])
        time.sleep(1)

    def reported_for(component_id: str, version_id: str) -> tuple[set, set]:
        rows = (session.query(models.Finding, models.Vulnerability)
                .join(models.Vulnerability,
                      models.Vulnerability.id == models.Finding.vulnerability_id)
                .filter(models.Finding.component_id == component_id,
                        models.Finding.last_seen_version_id == version_id,
                        models.Finding.kind == "vulnerability").all())
        return ({advisory.source_id for _finding, advisory in rows},
                {advisory.cve_id for _finding, advisory in rows if advisory.cve_id})

    for (label, component, version_id, _parsed), result in zip(osv_rows, results):
        report["checked"] += 1
        stubs = (result or {}).get("vulns") or []
        if not stubs:
            continue
        report["osv_advisories"] += len(stubs)
        have_ids, have_cves = reported_for(component.id, version_id)
        for stub in stubs:
            source_id = stub.get("id")
            if not source_id:
                continue
            if source_id in have_ids:
                report["reported"] += 1
                continue
            advisory = (session.query(models.Vulnerability)
                        .filter_by(source_id=source_id).one_or_none())
            alias_cve = advisory.cve_id if advisory else None
            if alias_cve is None:
                try:
                    detail = vulns.fetch_detail(source_id)
                except Exception:  # noqa: BLE001
                    detail = None
                if detail:
                    alias_cve = next((alias for alias in detail.get("aliases") or []
                                      if isinstance(alias, str) and alias.startswith("CVE-")),
                                     None)
            if alias_cve and alias_cve in have_cves:
                report["reported"] += 1
                continue
            report["missing"].append({
                "build": label, "component": component.name,
                "version": component.version, "purl": component.purl,
                "advisory": source_id, "cve": alias_cve,
                "severity": advisory.severity if advisory else None,
                "in_catalog": advisory is not None})

    # 2. runtimes, re-matched against NVD with the clock's own logic.
    cache: dict = {}
    for label, component, version_id, purl, (name, stated) in runtime_rows:
        product = runtime_cves.PRODUCTS.get(name)
        declared = (runtime_cves.declared_interval(stated, tag=purl.startswith("pkg:docker/"))
                    if product else None)
        if product is None or declared is None:
            report["unmapped"].append({"build": label, "component": name,
                                       "purl": purl, "reason": "no CPE product mapped"})
            continue
        if product not in cache:
            try:
                cache[product] = runtime_cves.fetch_product(*product)
            except Exception as error:  # noqa: BLE001
                report["errors"].append(f"nvd {'/'.join(product)}: "
                                        f"{type(error).__name__}: {error}")
                cache[product] = []
            time.sleep(6)   # NVD allows 5 requests per 30 s without an API key
        interval, _confidence = declared
        prefix = f"cpe:2.3:a:{product[0]}:{product[1]}:"
        expected = [cve["id"] for cve in cache[product]
                    if any(runtime_cves.overlaps(interval, item)
                           for item in runtime_cves._cpe_intervals(cve, prefix))]
        report["runtime_expected"] += len(expected)
        have_ids, have_cves = reported_for(component.id, version_id)
        report["reported"] += len([cve for cve in expected
                                   if cve in have_ids or cve in have_cves])
        for cve in expected:
            if cve in have_ids or cve in have_cves:
                continue
            report["missing"].append({"build": label, "component": name,
                                      "version": stated, "purl": purl,
                                      "advisory": cve, "source": "nvd"})
    session.close()

    if args.json:
        print(json.dumps(report, indent=1))
    else:
        print(json.dumps({key: report[key] for key in
                          ("builds", "components", "checked", "osv_advisories",
                           "reported", "runtime_expected")}, indent=1))
        print(f"missing: {len(report['missing'])}")
        print(f"unmapped (unknown, not clean): {len(report['unmapped'])}")
        print(f"without a version (unknown): {len(report['no_version'])}")
        if report["errors"]:
            print(f"errors: {report['errors']}")
        for item in report["missing"][:args.show]:
            print(" gap:", item)
        for item in report["unmapped"][:args.show]:
            print(" unknown:", item)
    return 0 if not report["missing"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
