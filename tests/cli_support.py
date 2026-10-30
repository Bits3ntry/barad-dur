"""Shared helpers for barad CLI contract tests (stdlib unittest only).

The CLI root is placed on sys.path so tests run from a checkout without an
install, exactly like `python -m unittest discover -s tests`.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = REPO_ROOT / "cli"
if str(CLI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLI_ROOT))


def cyclonedx(version="1.2.3", serial="urn:uuid:1", timestamp="2024-01-01T00:00:00Z",
              bom_ref=None, dependencies=None):
    component = {
        "type": "library",
        "name": "demo",
        "version": version,
        "purl": f"pkg:pypi/demo@{version}",
    }
    if bom_ref:
        component["bom-ref"] = bom_ref
    if dependencies is None:
        dependencies = [{"ref": component.get("bom-ref", component["purl"]), "dependsOn": []}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"name": "trivy", "version": "0.76.1"}]},
        },
        "components": [component],
        "dependencies": dependencies,
    }


def graph_sbom(*, edge=True, app_ref="ref-app", lib_ref="ref-lib",
               serial="urn:uuid:graph", timestamp="2024-01-01T00:00:00Z"):
    """Two components whose dependency edge can be toggled or re-referenced."""
    components = [
        {"type": "application", "name": "app", "version": "1.0",
         "purl": "pkg:generic/app@1.0", "bom-ref": app_ref},
        {"type": "library", "name": "lib", "version": "2.0",
         "purl": "pkg:generic/lib@2.0", "bom-ref": lib_ref},
    ]
    dependencies = [{"ref": app_ref, "dependsOn": [lib_ref] if edge else []}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"name": "trivy", "version": "0.76.1"}]},
        },
        "components": components,
        "dependencies": dependencies,
    }


def fixed_purl_sbom(version, serial="urn:uuid:fixed", timestamp="2024-01-01T00:00:00Z"):
    """One PURL that does not encode its version, so only component.version varies."""
    component = {
        "type": "library",
        "name": "demo",
        "version": version,
        "purl": "pkg:pypi/demo",
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"name": "trivy", "version": "0.76.1"}]},
        },
        "components": [component],
        "dependencies": [{"ref": "pkg:pypi/demo", "dependsOn": []}],
    }


def trivy_document():
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.76.1"},
        "Results": [
            {
                "Target": "pyproject.toml",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1", "Severity": "HIGH"}],
                "Secrets": [{"RuleID": "secret-1", "Match": "do-not-publish"}],
            }
        ],
    }


class FakeEngineManager:
    """Deterministic stand-in for barad.core.engines.EngineManager.

    `resolve` hands back an absolute path inside a private temporary directory, so
    a scan test proves the runner invokes a resolved engine and never a PATH
    lookup, without downloading anything.
    """

    instances = []
    resolve_calls = 0
    spec = {
        "version": "1.33.1",
        "platform": "linux-x86_64",
        "asset": "opengrep_manylinux_x86",
        "sha256": "0" * 64,
        "url": "https://github.com/opengrep/opengrep/releases/download/v1.33.1/"
               "opengrep_manylinux_x86",
    }

    def __init__(self, **kwargs):
        self.logger = kwargs.get("logger")
        self.environ = kwargs.get("environ") or {}
        self.cache_dir = Path(tempfile.mkdtemp(prefix="barad-fake-engines-"))
        self.path = self.cache_dir / "opengrep"
        self.path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.path.chmod(0o755)
        FakeEngineManager.instances.append(self)

    def resolve(self, name="opengrep"):
        FakeEngineManager.resolve_calls += 1
        return self.path.resolve()

    def engine(self, name="opengrep"):
        from barad.core.engines import EngineSpec

        return EngineSpec(name=name, **FakeEngineManager.spec)


class FakeOpenGrep:
    """Deterministic stand-in for barad.core.opengrep.OpenGrepRunner."""

    instances = []
    scan_calls = 0

    def __init__(self, config, logger, *, repo_root=None):
        self.config = config
        self.logger = logger
        self.repo_root = Path(repo_root)
        FakeOpenGrep.instances.append(self)

    def preflight(self):
        return None

    def scan_json(self, path):
        from barad.core.opengrep import OpenGrepOutcome

        FakeOpenGrep.scan_calls += 1
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "version": "1.33.1",
            "results": [{"check_id": "barad.python.subprocess-shell-true",
                         "extra": {"severity": "ERROR"}}],
            "errors": [],
        }), encoding="utf-8")
        return OpenGrepOutcome(
            status="success", exit_code=0, version="1.33.1", artifact=path.name,
            counts={"total": 1, "error": 1, "warning": 0, "info": 0},
        )


class FakeTrivy:
    """Deterministic stand-in for barad.core.TrivyRunner."""

    sbom = cyclonedx()
    fail_scan = False
    fail_sbom = False
    preflight_error = None
    instances = []
    scan_calls = 0
    sbom_calls = 0

    def __init__(self, config, logger, *, repo_root=None):
        self.config = config
        self.logger = logger
        self.repo_root = Path(repo_root)
        self.scan_type = config.get("trivy.scan_type")
        FakeTrivy.instances.append(self)

    def version(self):
        return "0.76.1"

    def scan_target(self):
        return self.config.get("trivy.target") or "."

    def preflight(self):
        if FakeTrivy.preflight_error:
            raise FakeTrivy.preflight_error

    def scan_json(self, path):
        from barad.core.trivy import TrivyOutcome

        FakeTrivy.scan_calls += 1
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(trivy_document()), encoding="utf-8")
        if FakeTrivy.fail_scan:
            return TrivyOutcome(
                status="failed",
                exit_code=1,
                version="0.76.1",
                artifact=path.name,
                error={"code": "trivy_nonzero_exit", "detail": "Trivy exited with 1"},
            )
        return TrivyOutcome(
            status="success",
            exit_code=0,
            version="0.76.1",
            artifact=path.name,
            counts={"total": 1, "high": 1, "secrets": 1, "misconfigurations": 0, "results": 1},
        )

    def generate_sbom(self, path):
        from barad.core.trivy import TrivyOutcome

        FakeTrivy.sbom_calls += 1
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(FakeTrivy.sbom), encoding="utf-8")
        if FakeTrivy.fail_sbom:
            return TrivyOutcome(
                status="failed",
                exit_code=1,
                version="0.76.1",
                artifact=path.name,
                error={"code": "trivy_sbom_nonzero_exit", "detail": "Trivy exited with 1"},
            )
        return TrivyOutcome(
            status="success", exit_code=0, version="0.76.1", artifact=path.name
        )


def reset_fake():
    FakeTrivy.sbom = cyclonedx()
    FakeTrivy.fail_scan = False
    FakeTrivy.fail_sbom = False
    FakeTrivy.preflight_error = None
    FakeEngineManager.instances = []
    FakeEngineManager.resolve_calls = 0
    FakeOpenGrep.instances = []
    FakeOpenGrep.scan_calls = 0
    FakeTrivy.instances = []
    FakeTrivy.scan_calls = 0
    FakeTrivy.sbom_calls = 0


def invoke(argv, cwd=None):
    from barad.cli import main

    out, err = io.StringIO(), io.StringIO()
    previous = Path.cwd()
    if cwd is not None:
        os.chdir(cwd)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(list(argv))
            except SystemExit as exit_exc:
                code = exit_exc.code if isinstance(exit_exc.code, int) else 1
    finally:
        os.chdir(previous)
    return code, out.getvalue(), err.getvalue()


class CliTestCase(unittest.TestCase):
    def setUp(self):
        reset_fake()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.default_output = self.root / ".barad" / "reports"
        self.state_path = self.root / ".barad" / "state" / "local-inventory.json"

    def scan(self, *argv, cwd=None, output=None):
        with mock.patch("barad.scan.TrivyRunner", FakeTrivy), \
             mock.patch("barad.scan.OpenGrepRunner", FakeOpenGrep):
            code, out, err = invoke(["scan", *argv], cwd=cwd)
        manifest = None
        run_dir = None
        if out.lstrip().startswith("{"):
            manifest = json.loads(out)
            run_dir = self.root / manifest["run"]["directory"]
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        else:
            for line in out.splitlines():
                if line.strip().startswith("evidence: "):
                    run_dir = Path(line.split("evidence: ", 1)[1].strip())
                    manifest = json.loads(
                        (run_dir / "manifest.json").read_text(encoding="utf-8")
                    )
                    break
        return code, out, err, manifest, run_dir

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_config(self, text):
        return self.write(".barad.yml", text)
