"""CycloneDX inspection: verify the inventory Trivy produced, never invent one.

The checks answer the questions the manifest must be able to prove: is this a
CycloneDX document, which specification version, how many components, how many
carry a PURL, is there a dependency graph, which generator and timestamp, and does
it (incorrectly) carry vulnerability results. Missing relations are reported as a
quality warning; nothing is added to the document.
"""

SUPPORTED_SPECS = ("1.4", "1.5", "1.6", "1.7")


class SbomValidation:
    def __init__(self):
        self.ok = False
        self.problems = []
        self.warnings = []
        self.summary = {}

    def problem(self, code, detail):
        self.problems.append({"code": code, "detail": detail})

    def warn(self, code, detail):
        self.warnings.append({"code": code, "detail": detail})

    def public(self):
        return {
            "ok": self.ok,
            "problems": list(self.problems),
            "warnings": list(self.warnings),
            "summary": dict(self.summary),
        }


def validate(document):
    """Structural validation of a CycloneDX JSON inventory."""
    result = SbomValidation()
    if not isinstance(document, dict):
        result.problem("sbom_root_not_object", "CycloneDX JSON root must be an object")
        return result

    if document.get("bomFormat") != "CycloneDX":
        result.problem("sbom_bom_format", "bomFormat must be 'CycloneDX'")
    spec_version = document.get("specVersion")
    if not isinstance(spec_version, str):
        result.problem("sbom_spec_version", "specVersion is missing")
    elif spec_version not in SUPPORTED_SPECS:
        result.problem("sbom_spec_version_unsupported",
                       f"specVersion {spec_version} is not one of {', '.join(SUPPORTED_SPECS)}")

    components = document.get("components")
    if not isinstance(components, list) or not components:
        result.problem("sbom_components_missing", "the inventory has no components")
        components = []
    purls = [component for component in components
             if isinstance(component, dict) and isinstance(component.get("purl"), str) and component["purl"]]
    without_purl = len(components) - len(purls)
    dependencies = document.get("dependencies")
    relations = 0
    if isinstance(dependencies, list):
        relations = sum(len(entry.get("dependsOn") or []) for entry in dependencies
                        if isinstance(entry, dict))

    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    tools = metadata.get("tools")
    generator = None
    if isinstance(tools, dict):
        tool_components = tools.get("components") or []
        if tool_components and isinstance(tool_components[0], dict):
            first = tool_components[0]
            generator = f"{first.get('group', '')}/{first.get('name', '')}@{first.get('version', '')}".lstrip("/")
    elif isinstance(tools, list) and tools and isinstance(tools[0], dict):
        generator = f"{tools[0].get('name', '')}@{tools[0].get('version', '')}"
    if not generator:
        result.warn("sbom_generator_unknown", "metadata.tools does not identify the generator")
    if not metadata.get("timestamp"):
        result.warn("sbom_timestamp_missing", "metadata.timestamp is missing")
    if not document.get("serialNumber"):
        result.warn("sbom_serial_missing", "serialNumber is missing")

    if not components:
        pass
    elif not purls:
        result.warn("sbom_no_purls", "no component carries a PURL; Dependency-Track cannot match components")
    elif without_purl:
        result.warn("sbom_partial_purls", f"{without_purl} of {len(components)} components have no PURL")

    if not isinstance(dependencies, list) or not dependencies:
        result.warn("sbom_dependency_graph_missing",
                    "Trivy produced no dependency graph; Dependency-Track will see a flat inventory")

    vulnerabilities = document.get("vulnerabilities")
    if vulnerabilities:
        result.warn("sbom_contains_vulnerabilities",
                    "the inventory carries vulnerability results; the JSON report is the security evidence")

    result.summary = {
        "bom_format": document.get("bomFormat"),
        "spec_version": spec_version,
        "serial_number": document.get("serialNumber"),
        "components": len(components),
        "components_with_purl": len(purls),
        "dependency_entries": len(dependencies) if isinstance(dependencies, list) else 0,
        "dependency_relations": relations,
        "generator": generator,
        "timestamp": metadata.get("timestamp"),
        "has_metadata_component": isinstance(metadata.get("component"), dict),
    }
    result.ok = not result.problems
    return result
