# Barad CLI scan and run

Install: `python3 -m pip install .`; `barad scan .` writes private JSON/CycloneDX and manifest under `.barad/reports/<scan-id>/`.
Optional `.barad.yml` selects filesystem/JAR/image targets. Credentials are environment-only.

## Remote workflow

`barad run .` always scans with the same engine. With enabled integrations, Dependency-Track compares normalized inventory against a remote CycloneDX export before upload, tracks the BOM processing token, and never claims publication from a local snapshot. PR/non-default branch publication is skipped; mutable release versions are rejected. DefectDojo imports sanitized Trivy JSON into a stable Product/Engagement/Test, then reimports with `close_old_findings=false`. Failures keep scan artifacts and return exit 4.

For isolated tests, use `cli/tests/fixtures/representative/.barad.yml` with a dedicated POC project; never use production names or publish PR versions.
The `health` command is reserved for the next work unit.
