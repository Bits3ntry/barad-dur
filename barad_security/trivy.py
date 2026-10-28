"""Trivy execution: one JSON report on every run, an SBOM only when decided.

The runner never builds a shell string. Every configurable value has already been
validated against an allowlist by the schema, and arguments are passed as a list,
so a repository can never inject a command.

Two invocation modes exist because the same logic must work where Trivy is
installed and where only its container image is available:

* `local`  — the `trivy` binary from PATH (or `trivy.executable`);
* `docker` — the pinned `trivy.image`, with the scan target mounted read-only and
  the evidence directory mounted read-write (Trivy cannot write into a read-only
  mount, which is why they are separate).

A non-zero exit is a technical failure. Findings are not: `--exit-code 0` is always
passed and the counts come from the parsed report.
"""
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ScannerError

SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SUPPORTED_CYCLONEDX_SPECS = ("1.4", "1.5", "1.6", "1.7")
_OUTPUT_TAIL = 4000


@dataclass
class TrivyOutcome:
    status: str = "pending"
    exit_code: int = None
    duration_ms: int = None
    version: str = None
    target: str = None
    artifact: str = None
    parameters: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    error: dict = None
    warnings: list = field(default_factory=list)
    report_id: str = None
    created_at: str = None
    command: list = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""

    @property
    def successful(self):
        return self.status == "success"

    def public(self):
        payload = {
            "status": self.status,
            "duration_ms": self.duration_ms,
            "artifact": self.artifact,
            "target": self.target,
            "version": self.version,
            "parameters": dict(self.parameters),
            "counts": dict(self.counts),
            "command": list(self.command),
            "warnings": list(self.warnings),
        }
        if self.exit_code is not None:
            payload["exit_code"] = self.exit_code
        if self.report_id:
            payload["report_id"] = self.report_id
        if self.created_at:
            payload["created_at"] = self.created_at
        if self.error:
            payload["error"] = dict(self.error)
        return payload


def sanitize_command(argv, repo_root):
    root = str(repo_root)
    return [part.replace(root + os.sep, "./").replace(root, ".") for part in argv]


def _tail(text, limit=_OUTPUT_TAIL):
    if not text:
        return ""
    cleaned = re.sub(r"[ \t]*\r", "\n", text)
    cleaned = "\n".join(line for line in cleaned.splitlines() if line.strip())
    return cleaned[-limit:]


class TrivyRunner:
    def __init__(self, config, logger, *, repo_root=None):
        self.config = config
        self.logger = logger
        self.repo_root = Path(repo_root or config.repo_root).resolve()
        self.runner = config.get("trivy.runner", "local")
        self.executable = config.get("trivy.executable", "trivy")
        self.image = config.get("trivy.image", "aquasec/trivy:0.76.1")
        self.scanners = list(config.get("trivy.scanners", ["vuln"]))
        self.severity = list(config.get("trivy.severity", list(SEVERITIES)))
        self.timeout = int(config.get("trivy.timeout_seconds", 900))
        self.cache_enabled = bool(config.get("trivy.cache_enabled", True))
        self.cache_dir = config.get("trivy.cache_dir", ".barad-dur/cache/trivy")
        self.scan_type = config.get("trivy.scan_type", "fs")
        self._version = None

    # -- target resolution -------------------------------------------------
    def scan_target(self):
        if self.scan_type == "image":
            return self.config.get("trivy.target")
        configured = self.config.get("trivy.target")
        if configured:
            return configured
        return self.config.get("project.path", ".") or "."

    def scan_root(self):
        """Host directory mounted read-only into the Trivy container (fs only)."""
        return self.config.path(self.scan_target())

    def cache_path(self):
        return self.config.path(self.cache_dir)

    def _common_flags(self, *, format_name, include_scanners=True):
        flags = ["--format", format_name, "--no-progress", "--timeout", f"{self.timeout}s"]
        if include_scanners:
            flags += ["--scanners", ",".join(self.scanners)]
            if "vuln" in self.scanners:
                flags += ["--severity", ",".join(self.severity)]
        return flags

    def _local_command(self, *, format_name, output_path, include_scanners=True):
        flags = self._common_flags(format_name=format_name, include_scanners=include_scanners)
        if self.scan_type == "image":
            argv = [self.executable, "image", *flags, "--image-src", "remote",
                    "--exit-code", "0", "--output", str(output_path), self.scan_target()]
            cwd = self.repo_root
        else:
            argv = [self.executable, "fs", *flags, "--exit-code", "0",
                    "--output", str(output_path), self.scan_target()]
            cwd = self.repo_root
        if self.cache_enabled:
            argv[1:1] = ["--cache-dir", str(self.cache_path())]
        return argv, cwd, None

    def _docker_command(self, *, format_name, output_path, include_scanners=True):
        """Build `docker run` so every Trivy flag lands AFTER the image reference.

        Docker parses everything before the image as its own options; putting a
        Trivy flag there fails with "unknown flag". Mounts therefore come first,
        then the image, then the Trivy subcommand and its flags.
        """
        if shutil.which("docker") is None:
            raise ScannerError("trivy.runner is 'docker' but the docker CLI is not available")
        flags = self._common_flags(format_name=format_name, include_scanners=include_scanners)
        output_dir = output_path.parent.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        container_output = f"/out/{output_path.name}"
        docker_options = ["docker", "run", "--rm"]
        if self.scan_type == "image":
            mount_target = None
            docker_options += ["-v", f"{output_dir}:/out"]
            trivy_arguments = [
                "image", *flags, "--image-src", "remote", "--exit-code", "0",
                "--output", container_output, self.scan_target(),
            ]
        else:
            mount_target = self.scan_root()
            if not mount_target.is_dir():
                raise ScannerError(f"scan target is not a directory: {self.scan_target()}")
            # The scan target is read-only; the evidence directory is writable.
            docker_options += ["-v", f"{mount_target}:/scan:ro", "-v", f"{output_dir}:/out"]
            trivy_arguments = [
                "fs", *flags, "--exit-code", "0", "--output", container_output, "/scan",
            ]
        if self.cache_enabled:
            cache = self.cache_path()
            cache.mkdir(parents=True, exist_ok=True)
            docker_options += ["-v", f"{cache}:/root/.cache/trivy"]
        return [*docker_options, self.image, *trivy_arguments], self.repo_root, mount_target

    def _command(self, *, format_name, output_path, include_scanners=True):
        if self.runner == "docker":
            return self._docker_command(format_name=format_name, output_path=output_path,
                                        include_scanners=include_scanners)
        return self._local_command(format_name=format_name, output_path=output_path,
                                   include_scanners=include_scanners)

    # -- version -----------------------------------------------------------
    def version(self):
        if self._version:
            return self._version
        if self.runner == "docker":
            argv = ["docker", "run", "--rm", self.image, "--version"]
        else:
            argv = [self.executable, "--version"]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        match = re.search(r"Version:\s*(\S+)", result.stdout or "")
        self._version = match.group(1) if match else None
        return self._version

    def preflight(self):
        """Fail early, with a technical error, when Trivy cannot be invoked at all."""
        if self.runner == "docker":
            if shutil.which("docker") is None:
                raise ScannerError("trivy.runner is 'docker' but the docker CLI is not available")
            return
        executable = self.executable
        if os.sep in executable:
            if not Path(executable).exists() and not Path(self.repo_root / executable).exists():
                raise ScannerError(f"trivy executable not found: {executable}")
            return
        if shutil.which(executable) is None:
            raise ScannerError(
                f"trivy executable not found: {executable}; install Trivy or set trivy.runner: docker"
            )

    # -- execution ---------------------------------------------------------
    def _execute(self, *, format_name, output_path, include_scanners=True):
        argv, cwd, mount_target = self._command(format_name=format_name, output_path=output_path,
                                                include_scanners=include_scanners)
        previous_dir = os.getcwd()
        os.chdir(cwd)
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout + 30)
            exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise ScannerError(
                f"Trivy exceeded its {self.timeout}s budget",
                details={"command": sanitize_command(argv, self.repo_root)},
            ) from None
        except OSError as error:
            raise ScannerError(f"cannot execute Trivy: {error.strerror or error}") from None
        finally:
            os.chdir(previous_dir)
        return argv, mount_target, exit_code, stdout, stderr

    def scan_json(self, output_path=None):
        output_path = Path(output_path) if output_path else None
        if output_path is None:
            raise ScannerError("scan_json requires an output path")
        started = time.monotonic()
        argv, mount_target, exit_code, stdout, stderr = self._execute(
            format_name="json", output_path=output_path, include_scanners=True
        )
        duration = int((time.monotonic() - started) * 1000)
        outcome = TrivyOutcome(
            status="failed",
            exit_code=exit_code,
            duration_ms=duration,
            version=self.version(),
            target=self.scan_target(),
            artifact=output_path.name,
            command=sanitize_command(argv, self.repo_root),
            parameters={
                "runner": self.runner,
                "image": self.image if self.runner == "docker" else None,
                "scan_type": self.scan_type,
                "target": self.scan_target(),
                "mount_target": str(mount_target) if mount_target else None,
                "scanners": list(self.scanners),
                "severity": list(self.severity),
                "format": "json",
                "exit_code_policy": "0 (findings never fail the run)",
                "cache_enabled": self.cache_enabled,
                "timeout_seconds": self.timeout,
            },
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
        )
        if exit_code != 0:
            outcome.error = {
                "code": "trivy_nonzero_exit",
                "detail": f"Trivy exited with {exit_code}",
                "stderr_tail": outcome.stderr_tail,
            }
            if self.logger:
                self.logger.error("trivy", "scan_failed", {"exit_code": exit_code,
                                                          "stderr_tail": outcome.stderr_tail})
            return outcome
        try:
            document = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            outcome.error = {"code": "trivy_report_unreadable", "detail": str(error)}
            if self.logger:
                self.logger.error("trivy", "report_unreadable", {"detail": str(error)})
            return outcome
        if not isinstance(document, dict) or "Results" not in document:
            outcome.error = {"code": "trivy_report_malformed",
                             "detail": "the JSON report has no Results array"}
            if self.logger:
                self.logger.error("trivy", "report_malformed", {})
            return outcome

        outcome.status = "success"
        outcome.report_id = document.get("ReportID")
        outcome.created_at = document.get("CreatedAt")
        version = document.get("Trivy") if isinstance(document.get("Trivy"), dict) else {}
        outcome.version = version.get("Version") or outcome.version
        outcome.counts = count_findings(document)
        if outcome.counts["results"] == 0:
            outcome.warnings.append("trivy_reported_no_targets")
        if self.logger:
            self.logger.info("trivy", "scan_completed", {"counts": outcome.counts,
                                                         "duration_ms": duration})
        return outcome

    def generate_sbom(self, output_path):
        output_path = Path(output_path)
        started = time.monotonic()
        argv, mount_target, exit_code, stdout, stderr = self._execute(
            format_name="cyclonedx", output_path=output_path, include_scanners=False
        )
        duration = int((time.monotonic() - started) * 1000)
        outcome = TrivyOutcome(
            status="failed",
            exit_code=exit_code,
            duration_ms=duration,
            version=self.version(),
            target=self.scan_target(),
            artifact=output_path.name,
            command=sanitize_command(argv, self.repo_root),
            parameters={
                "runner": self.runner,
                "image": self.image if self.runner == "docker" else None,
                "format": "cyclonedx",
                "scanners": "none (CycloneDX inventory only)",
                "mount_target": str(mount_target) if mount_target else None,
            },
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
        )
        if exit_code != 0:
            outcome.error = {
                "code": "trivy_sbom_nonzero_exit",
                "detail": f"Trivy exited with {exit_code}",
                "stderr_tail": outcome.stderr_tail,
            }
            if self.logger:
                self.logger.error("sbom", "generation_failed", {"exit_code": exit_code,
                                                               "stderr_tail": outcome.stderr_tail})
            return outcome
        if not output_path.is_file() or output_path.stat().st_size == 0:
            outcome.error = {"code": "trivy_sbom_missing", "detail": "no SBOM file was written"}
            if self.logger:
                self.logger.error("sbom", "generation_missing", {})
            return outcome
        outcome.status = "success"
        if self.logger:
            self.logger.info("sbom", "generated", {"artifact": output_path.name,
                                                   "duration_ms": duration})
        return outcome


def count_findings(document):
    counts = {severity.lower(): 0 for severity in SEVERITIES}
    counts.update({"total": 0, "secrets": 0, "misconfigurations": 0, "results": 0})
    results = document.get("Results") or []
    counts["results"] = len(results)
    for result in results:
        if not isinstance(result, dict):
            continue
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = str(vulnerability.get("Severity", "UNKNOWN")).upper()
            key = severity.lower()
            if key not in counts:
                key = "unknown"
            counts[key] += 1
            counts["total"] += 1
        counts["secrets"] += len(result.get("Secrets") or [])
        for misconfiguration in result.get("Misconfigurations") or []:
            if str(misconfiguration.get("Status", "FAIL")).upper() == "PASS":
                continue
            counts["misconfigurations"] += 1
    return counts
