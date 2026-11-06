#!/usr/bin/env python
"""Collapse dependency findings that name the same CVE on the same package.

Background: the first OSV sweep created a row per advisory *id*, so a CVE that
Trivy called `CVE-2021-23337` and OSV called `GHSA-35jh-r3h4-6jhm` appeared
twice. The write path now looks the CVE up first, so new sweeps cannot repeat
it; this script repairs what the earlier sweep left behind.

It never deletes. The redundant row is closed with a note naming the survivor,
because a finding may carry occurrences, comments or suppressions and losing
that history is worse than a closed row. Survivor, in order: the row the
artifact produced (it carries the fixed version and the recommendation), then
the oldest.

    python scripts/dedupe_advisory_findings.py             # dry run
    python scripts/dedupe_advisory_findings.py --apply     # write
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))

from backend.app import models  # noqa: E402
from backend.app.db import session_factory  # noqa: E402

OPEN = ("open",)


def groups(session, org_slug: str | None):
    query = (session.query(models.Finding, models.Vulnerability)
             .join(models.Vulnerability, models.Vulnerability.id == models.Finding.vulnerability_id)
             .filter(models.Finding.kind == "vulnerability",
                     models.Finding.status.in_(OPEN),
                     models.Vulnerability.cve_id.isnot(None)))
    if org_slug:
        org = session.query(models.Organization).filter_by(slug=org_slug).one_or_none()
        if org is None:
            raise SystemExit(f"error: no organization with slug {org_slug!r}")
        query = query.filter(models.Finding.org_id == org.id)
    buckets = defaultdict(list)
    for finding, advisory in query.all():
        buckets[(finding.org_id, finding.project_id, finding.component_id,
                 advisory.cve_id)].append((finding, advisory))
    return {key: rows for key, rows in buckets.items() if len(rows) > 1}


def survivor(rows):
    artifact = [row for row in rows if (row[0].source or "") == "sbom"]
    pool = artifact or rows
    return sorted(pool, key=lambda row: (row[0].first_seen_at or models.utcnow()))[0]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="write the changes (default: report only)")
    parser.add_argument("--org", default=None, help="only this organization slug")
    args = parser.parse_args(argv)

    session = session_factory()()
    try:
        found = groups(session, args.org)
        total = sum(len(rows) - 1 for rows in found.values())
        print(json.dumps({"groups": len(found), "redundant": total,
                          "apply": bool(args.apply)}, indent=2))
        for (org_id, project_id, component_id, cve), rows in sorted(found.items(),
                                                                   key=lambda item: item[0][3]):
            keep, keep_advisory = survivor(rows)
            for finding, advisory in rows:
                if finding.id == keep.id:
                    continue
                note = (f"Superseded by finding {keep.id}: same CVE {cve} on the same "
                        f"package, reported as {keep_advisory.source_id}.")
                if args.apply:
                    finding.status = "closed"
                    finding.detail = ((finding.detail or "") + "\n" + note).strip()
                    finding.updated_at = models.utcnow()
                print(json.dumps({"cve": cve, "keep": keep.id, "keep_source": keep.source,
                                  "close": finding.id, "close_source": finding.source,
                                  "applied": bool(args.apply)}))
        if args.apply:
            session.commit()
            print(json.dumps({"closed": total}, indent=2))
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
