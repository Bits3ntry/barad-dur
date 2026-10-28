# Barad CLI scan foundation

Install: `python3 -m pip install .`; run `barad scan .`.
Docker Trivy writes private JSON + CycloneDX and a normalized manifest under `.barad/reports/<scan-id>/`.
Optional `.barad.yml` selects filesystem/JAR/image targets. Credentials are never stored in project YAML.
The `run` and `health` command names are reserved for subsequent work units.
