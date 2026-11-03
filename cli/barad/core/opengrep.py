"""OpenGrep execution for versioned, local SAST rules.

OpenGrep is intentionally separate from Trivy: it examines source patterns while
Trivy owns SBOM generation, secrets, and configuration mischecks.  The runner
writes its JSON evidence into Barad's protected run directory and never sends
it to a remote integration.

The engine is not assumed to be installed.  `EngineManager` resolves the pinned
release from the packaged lockfile, verifies its SHA-256 and hands back an
absolute path, so the CLI runs the exact OpenGrep build the lockfile names.
"""
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from .engines import ENGINE_NAME, EngineManager
from .errors import ScannerError
from .trivy import _tail, sanitize_command


@dataclass
class OpenGrepOutcome:
    status: str = "pending"
    exit_code: int = None
    duration_ms: int = None
    version: str = None
    artifact: str = None
    parameters: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    error: dict = None
    command: list = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""

    @property
    def successful(self):
        return self.status == "success"


class OpenGrepRunner:
    """Run the pinned OpenGrep engine using a checked-in rule bundle."""

    def __init__(self, config, logger, *, repo_root=None, engines=None):
        self.config = config
        self.logger = logger
        self.repo_root = Path(repo_root or config.repo_root).resolve()
        self.engines = engines or EngineManager(
            logger=logger, environ=getattr(config, "environ", None)
        )
        self.rules = config.get("opengrep.rules")
        self.timeout = int(config.get("opengrep.timeout_seconds", 600))
        self.exclude_paths = list(config.get("opengrep.exclude_paths", []))
        self._executable = None
        self._version = None

    def engine(self):
        """Pinned engine identity recorded as evidence (version, platform, digest)."""
        return self.engines.engine(ENGINE_NAME).public()

    def executable(self):
        """Absolute path of the verified engine; resolved once per runner."""
        if self._executable is None:
            self._executable = self.engines.resolve(ENGINE_NAME)
        return self._executable

    def scan_target(self):
        return self.repo_root

    def rule_path(self):
        if self.rules:
            return self.config.path(self.rules)
        return Path(resources.files("barad").joinpath("rules", "opengrep-baseline.yml"))

    def preflight(self):
        # A resolution failure (unsupported host, failed download or digest
        # mismatch) surfaces as an EngineError, which is a ScannerError.
        self.executable()
        rules = self.rule_path()
        if not rules.is_file():
            raise ScannerError(f"opengrep rule file not found: {rules}")

    def version(self):
        if self._version:
            return self._version
        try:
            executable = self.executable()
        except ScannerError:
            return None
        try:
            result = subprocess.run([str(executable), "--version"], capture_output=True,
                                    text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", result.stdout or "")
        self._version = match.group(1) if match else None
        return self._version

    def _command(self, output_path):
        # OpenGrep 1.33.1 full-CLI argv: no `--no-progress-bar` (semgrep-only);
        # `--disable-version-check` keeps the credential-free scan boundary
        # (an update check would be an unexplained outbound call).
        argv = [
            str(self.executable()), "scan", "--json-output", str(output_path),
            "--disable-version-check", "--config", str(self.rule_path()),
        ]
        for path in self.exclude_paths:
            argv += ["--exclude", path]
        argv.append(str(self.scan_target()))
        return argv

    def scan_json(self, output_path):
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        argv = self._command(output_path)
        try:
            result = subprocess.run(argv, cwd=self.repo_root, capture_output=True,
                                    text=True, timeout=self.timeout)
            exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise ScannerError(
                f"OpenGrep exceeded its {self.timeout}s budget",
                details={"command": sanitize_command(argv, self.repo_root)},
            ) from None
        except OSError as error:
            raise ScannerError(f"cannot execute OpenGrep: {error.strerror or error}") from None

        outcome = OpenGrepOutcome(
            status="failed",
            exit_code=exit_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            version=self.version(),
            artifact=output_path.name,
            command=sanitize_command(argv, self.repo_root),
            parameters={
                "engine": self.engine(),
                "rules": _display_rule_path(self.rule_path(), self.repo_root),
                "format": "json",
                "exit_code_policy": "findings do not fail the run",
                "exclude_paths": list(self.exclude_paths),
                "timeout_seconds": self.timeout,
            },
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
        )
        if exit_code != 0:
            outcome.error = {
                "code": "opengrep_nonzero_exit",
                "detail": f"OpenGrep exited with {exit_code}",
                "stderr_tail": outcome.stderr_tail,
            }
            if self.logger:
                self.logger.error("opengrep", "scan_failed", {"exit_code": exit_code})
            return outcome
        try:
            document = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            outcome.error = {"code": "opengrep_report_unreadable", "detail": str(error)}
            return outcome
        if not isinstance(document, dict) or not isinstance(document.get("results"), list):
            outcome.error = {
                "code": "opengrep_report_malformed",
                "detail": "the JSON report has no results array",
            }
            return outcome
        errors = document.get("errors", [])
        if not isinstance(errors, list):
            outcome.error = {
                "code": "opengrep_report_malformed",
                "detail": "the JSON report errors field is not an array",
            }
            return outcome

        outcome.status = "success"
        outcome.version = str(document.get("version") or outcome.version or "unknown")
        outcome.counts = count_findings(document)
        if self.logger:
            self.logger.info("opengrep", "scan_completed", {
                "counts": outcome.counts, "duration_ms": outcome.duration_ms,
            })
        return outcome


def count_findings(document):
    counts = {"total": 0, "error": 0, "warning": 0, "info": 0}
    for finding in document.get("results") or []:
        if not isinstance(finding, dict):
            continue
        extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
        severity = str(extra.get("severity") or "INFO").lower()
        if severity not in ("error", "warning", "info"):
            severity = "info"
        counts[severity] += 1
        counts["total"] += 1
    return counts


def _display_rule_path(path, repo_root):
    path = Path(path).resolve()
    try:
        return path.relative_to(Path(repo_root).resolve()).as_posix()
    except ValueError:
        return "bundled:opengrep-baseline.yml"
