"""Error taxonomy: technical failures are never conflated with security findings.

Exit codes are part of the CLI contract:

    0  run completed and every required step succeeded (findings allowed)
    1  technical failure (scanner, evidence or required publication)
    2  usage, configuration or environment error; nothing was scanned
    3  the configured findings gate tripped (only with fail_on_findings: true)
"""

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_FINDINGS = 3


class BaradError(Exception):
    """Base class for every failure the CLI reports as a technical error."""

    exit_code = EXIT_FAILURE
    step = "run"
    kind = "technical_error"

    def __init__(self, message, *, details=None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class UsageError(BaradError):
    exit_code = EXIT_USAGE
    step = "cli"
    kind = "usage_error"


class ConfigError(BaradError):
    exit_code = EXIT_USAGE
    step = "config"
    kind = "configuration_error"


class EnvironmentError_(BaradError):
    exit_code = EXIT_USAGE
    step = "environment"
    kind = "environment_error"


class GitError(BaradError):
    step = "git"
    kind = "git_error"


class ScannerError(BaradError):
    """Trivy did not finish correctly; distinct from "it found problems"."""

    step = "trivy"
    kind = "scanner_error"


class SBOMParseError(BaradError):
    step = "sbom"
    kind = "sbom_error"


class EvidenceError(BaradError):
    step = "evidence"
    kind = "evidence_error"


class PublishError(BaradError):
    """Optional integrations must never hide an analysis result."""

    step = "publish"
    kind = "publication_error"

    def __init__(self, message, *, service="unknown", attempts=None, details=None):
        super().__init__(message, details=details)
        self.service = service
        self.attempts = attempts or []
