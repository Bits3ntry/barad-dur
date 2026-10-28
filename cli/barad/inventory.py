"""Normalized inventory graph identity and LOCAL snapshot comparison.

The fingerprint covers component identities, dependency edges and the scan target
(including an image reference), never CycloneDX serial numbers, timestamps or
generator metadata. Dependency bom-refs are resolved to stable component identity
(PURL first) so renaming references does not change the graph fingerprint. A
previous record is a local snapshot: it proves what this installation last
scanned, never that a remote system accepted or published anything.
"""
import json

from barad_security.evidence import sha256_bytes

BASIS = "normalized_cyclonedx_graph_v4"


def fingerprint(document, *, target_type, target):
    """Hash the normalized component set, distinct edges and target identity."""
    if not isinstance(document, dict) or not isinstance(document.get("components"), list):
        return None
    components = []
    identity_by_ref = {}
    for component in document["components"]:
        if not isinstance(component, dict):
            continue
        identity = _component_identity(component)
        if identity is None:
            continue
        components.append(identity)
        for key in (component.get("bom-ref"), component.get("purl")):
            if isinstance(key, str) and key:
                identity_by_ref.setdefault(key, identity)
    if not components:
        return None

    # Dependency-Track rewrites the CycloneDX metadata.component bom-ref to
    # its project UUID on export. This root node represents the already-hashed
    # scan target, not another package; canonicalize only this known ref.
    metadata = document.get('metadata')
    root_component = metadata.get('component') if isinstance(metadata, dict) else None
    root_ref = root_component.get('bom-ref') if isinstance(root_component, dict) else None
    if isinstance(root_ref, str) and root_ref:
        identity_by_ref[root_ref] = ('target-root',)

    edges = set()
    for dependency in document.get("dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        source = _resolve(dependency.get("ref"), identity_by_ref)
        if source is None:
            continue
        for reference in dependency.get("dependsOn") or []:
            destination = _resolve(reference, identity_by_ref)
            if destination is not None:
                edges.add((source, destination))

    payload = {
        "basis": BASIS,
        "target": {"type": target_type, "value": str(target)},
        "components": sorted(components),
        "edges": [list(edge) for edge in sorted(edges)],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256_bytes(encoded.encode("utf-8"))


def compare(record, *, target_type, target, current):
    """Return `(comparison, previous_public)` without ever claiming publication."""
    if current is None:
        return "unavailable", None
    if not isinstance(record, dict):
        return "no_previous", None
    same_target = (record.get("target_type") == target_type
                   and record.get("target") == target)
    same_basis = record.get("inventory_basis") == BASIS
    has_fingerprint = bool(record.get("inventory_fingerprint"))
    previous = {
        "source": "local_snapshot",
        "compatible": bool(same_target and same_basis and has_fingerprint),
        "basis": record.get("inventory_basis"),
        "fingerprint": record.get("inventory_fingerprint"),
        "run_id": record.get("run_id"),
        "scanned_at": record.get("recorded_at"),
    }
    if not same_target or not same_basis:
        return "incompatible_previous", previous
    if not has_fingerprint:
        return "unverifiable", previous
    if record["inventory_fingerprint"] == current:
        return "unchanged", previous
    return "changed", previous


def _component_identity(component):
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return ("purl", purl, component.get("version") or "")
    name = component.get("name")
    if isinstance(name, str) and name:
        return ("component", component.get("type") or "", name,
                component.get("version") or "")
    reference = component.get("bom-ref")
    if isinstance(reference, str) and reference:
        return ("ref", reference)
    return None


def _resolve(reference, identity_by_ref):
    if not isinstance(reference, str) or not reference:
        return None
    if reference in identity_by_ref:
        return identity_by_ref[reference]
    # Keep unresolved edges distinct instead of dropping them into a collision.
    return ("ref", reference)
