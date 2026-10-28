"""BARAD-DÛR Security Workflow: one portable Trivy-driven security runner.

The package is deliberately standard-library first (plus PyYAML and jsonschema,
already required by this repository) so the same code runs from a laptop CLI,
from a Git hook, from `act` and from GitHub Actions without a service or a
database.
"""

__version__ = "1.0.0"

MANIFEST_SCHEMA_VERSION = "1.0"
