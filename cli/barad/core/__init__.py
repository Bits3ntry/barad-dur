"""Shared implementation for the Barad CLI and integrations."""

from .trivy import TrivyRunner

__version__ = "0.1.0"
MANIFEST_SCHEMA_VERSION = "1.0"

__all__ = ["MANIFEST_SCHEMA_VERSION", "TrivyRunner", "__version__"]
