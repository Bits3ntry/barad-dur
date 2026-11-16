"""Why a package is in a build: the chain from it up to what the app declares.

"I have a CVE in brotli" is only actionable as "brotli came in through axios", so
every screen that shows one package inside one build answers with the path. The
advisory page, the package sheet and the build graph all read the walk from here
instead of each carrying its own copy of it.

The chain comes from `version_components.parent_purl`, which the SBOM ingest
fills from the BOM's own dependency graph. When the document declares no parent
(pip's flat list, a hand-written inline BOM) the answer is `[]` — absent, not
"this package is top level".
"""
from sqlalchemy.orm import Session

from backend.app import models


def links_of(session: Session, version_id: str) -> dict:
    """`component_id -> VersionComponent` for one build, so a caller walking
    several packages of the same build reads the links once."""
    return {link.component_id: link for link in
            session.query(models.VersionComponent)
            .filter_by(project_version_id=version_id).all()}


def ancestry(session: Session, version_id: str, component,
             links: dict | None = None) -> list[dict]:
    """The parents of one package in one build, nearest first.

    A cycle (possible in a hand-written BOM) stops the walk instead of looping,
    and the depth is capped because a chain longer than that is not a path a
    reader is going to act on.
    """
    if component is None:
        return []
    links = links if links is not None else links_of(session, version_id)
    if not links:
        return []
    by_purl = {}
    for row in (session.query(models.Component)
                .filter(models.Component.id.in_(set(links))).all()):
        if row.purl:
            by_purl[row.purl] = row
    path: list[dict] = []
    seen = {component.id}
    current = component
    while len(path) < 16:
        link = links.get(current.id)
        parent = by_purl.get(link.parent_purl) if link and link.parent_purl else None
        if parent is None or parent.id in seen:
            break
        path.append({"id": parent.id, "name": parent.name, "version": parent.version,
                     "purl": parent.purl})
        seen.add(parent.id)
        current = parent
    return path
