"""`.barad.yml`: secure defaults mapped onto `barad_security` validation.

The CLI owns only a small, documented project file. It is translated into the
existing `barad_security` configuration document, so the runner keeps one schema,
one semantic checker and one environment-expansion policy. Credentials are never
values in `.barad.yml`: integrations name the environment variable (`token_env`)
that holds them, and an environment value overrides a non-secret `endpoint`
declared in the file.
"""
import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from barad_security.config import build_config
from barad_security.errors import ConfigError

CONFIG_FILENAME = ".barad.yml"
INTEGRATIONS = ("dependency_track", "defectdojo")

DEFAULT_EXCLUDES = [".git", ".venv", "node_modules", ".barad", ".barad-dur", "dist",
                    "build", ".secrets"]

DEFAULTS = {
    "version": 1,
    "project": {"name": "auto", "version": {"source": "auto"}},
    "scan": {
        "target_type": "fs",
        "target": None,
        "runner": "docker",
        "executable": "trivy",
        "image": "aquasec/trivy:0.76.1",
        "scanners": ["vuln", "secret", "misconfig"],
        "severity": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "timeout_seconds": 900,
        "exclude_paths": list(DEFAULT_EXCLUDES),
    },
    "output": {"directory": ".barad/reports"},
    "integrations": {
        "dependency_track": {
            "enabled": False, "endpoint_env": "DTRACK_URL", "token_env": "DTRACK_API_KEY",
            "auto_create": False, "wait_timeout_seconds": 30,
        },
        "defectdojo": {
            "enabled": False, "endpoint_env": "DOJO_URL", "token_env": "DOJO_TOKEN",
            "auto_create_context": False, "reimport": True,
        },
    },
}

_TOP_LEVEL = {"version", "project", "scan", "output", "integrations"}
_PROJECT_KEYS = {"name", "version"}
_VERSION_KEYS = {"source", "path", "key", "value", "env"}
_SCAN_KEYS = {"target_type", "target", "runner", "executable", "image", "scanners",
              "severity", "timeout_seconds", "exclude_paths"}
_OUTPUT_KEYS = {"directory"}
_BLOCK_KEYS = {"enabled", "endpoint", "endpoint_env", "token_env", "required",
               "auto_create", "wait_timeout_seconds", "auto_create_context", "reimport",
               "product_name", "product_type_name", "engagement_name", "test_title_prefix", "timeout_seconds",
               "max_attempts"}
_SECRET_KEYS = {"token", "password", "secret", "api_key", "apikey", "access_key"}


@dataclass
class Settings:
    document: dict
    security: object
    source: Path = None
    root: Path = None
    environ: dict = field(default_factory=dict)
    ecosystems: list = field(default_factory=list)

    def block(self, name):
        return self.document["integrations"][name]

    def endpoint(self, name):
        """Environment first: a deployment overrides the checked-in endpoint."""
        settings = self.block(name)
        return self.environ.get(settings.get("endpoint_env") or "") or settings.get("endpoint")

    def connection(self, name):
        settings = self.block(name)
        return {
            "endpoint": self.endpoint(name),
            "endpoint_configured": bool(self.endpoint(name)),
            "token_configured": bool(self.environ.get(settings.get("token_env") or "")),
        }

    def secret_values(self):
        values = []
        for name in INTEGRATIONS:
            settings = self.block(name)
            for key in ("token_env", "endpoint_env"):
                value = self.environ.get(settings.get(key) or "")
                if value:
                    values.append(value)
        return values

    def public(self):
        """Configuration safe to persist: variable names, never their values."""
        return copy.deepcopy(self.document)


def read_project_config(path):
    """Parse and shape-check `.barad.yml`; returns `(document, source)`."""
    if path is None:
        return {}, None
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error.strerror}") from None
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ConfigError(f"{path.name} is not valid YAML: {error}") from None
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise ConfigError("configuration root must be a mapping")
    _check_keys(document)
    _check_types(document)
    return document, path.resolve()


def load_settings(document, *, source, root, project_name, ecosystems=(),
                  environ=None, output_override=None, target_override=None):
    """Merge defaults, resolve identity and build the validated runner config."""
    document = document or {}
    _check_keys(document)
    _check_types(document)
    merged = _merge(DEFAULTS, document)
    root = Path(root).resolve()
    environment = dict(environ if environ is not None else os.environ)

    configured_name = merged["project"].get("name")
    if not configured_name or str(configured_name).strip().lower() == "auto":
        configured_name = project_name
    merged["project"]["name"] = configured_name
    output_directory = output_override or merged["output"]["directory"]
    _check_relative(output_directory, "output.directory")
    _check_state_separation(output_directory)
    merged["output"]["directory"] = Path(output_directory).as_posix()

    version = merged["project"].get("version") or {"source": "auto"}
    target_type = merged["scan"]["target_type"]
    security_document = {
        "version": 1,
        "project": {"name": configured_name, "service": configured_name, "path": ".",
                    "version": version},
        "trivy": {
            "enabled": True,
            "always_run": True,
            "runner": merged["scan"]["runner"],
            "executable": merged["scan"]["executable"],
            "image": merged["scan"]["image"],
            "cache_enabled": True,
            "cache_dir": ".barad-dur/cache/trivy",
            "scan_type": target_type,
            "scanners": list(merged["scan"]["scanners"]),
            "severity": list(merged["scan"]["severity"]),
            "exclude_paths": list(merged["scan"]["exclude_paths"]),
            "report_format": "json",
            "timeout_seconds": merged["scan"]["timeout_seconds"],
        },
        "sbom": {"enabled": True, "generator": "trivy", "format": "cyclonedx"},
        "artifacts": {
            "directory": Path(output_directory).as_posix(),
            "preserve_reports": True,
            "preserve_logs": True,
            "create_manifest": True,
            "checksums": "sha256",
        },
        "integrations": {},
    }
    if ecosystems:
        security_document["project"]["ecosystem"] = list(ecosystems)[0]
    if target_type == "image" or target_override:
        security_document["trivy"]["target"] = target_override or merged["scan"].get("target")
    for name in INTEGRATIONS:
        settings = merged["integrations"][name]
        security_document["integrations"][name] = {
            "enabled": bool(settings.get("enabled", False)),
            "required": bool(settings.get("required", False)),
            "endpoint_env": settings["endpoint_env"],
            "token_env": settings["token_env"],
        }
    _check_endpoint(merged["integrations"])
    security = build_config(security_document, source=source, repo_root=root,
                            environ=environment)
    return Settings(document=merged, security=security, source=source, root=root,
                    environ=environment, ecosystems=list(ecosystems))


def _merge(base, override):
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if value is None and isinstance(merged.get(key), dict):
            continue  # null optional mapping means use its documented defaults
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _check_keys(document):
    for key in document:
        if key not in _TOP_LEVEL:
            raise ConfigError(f"unknown configuration key: {key}")
    if document.get("version", 1) != 1:
        raise ConfigError("invalid configuration: version must be 1")
    project = _mapping(document, "project")
    for key in project:
        if key not in _PROJECT_KEYS:
            raise ConfigError(f"unknown configuration key: project.{key}")
    for key in _mapping(project, "version", parent="project"):
        if key not in _VERSION_KEYS:
            raise ConfigError(f"unknown configuration key: project.version.{key}")
    for key in _mapping(document, "scan"):
        if key not in _SCAN_KEYS:
            raise ConfigError(f"unknown configuration key: scan.{key}")
    for key in _mapping(document, "output"):
        if key not in _OUTPUT_KEYS:
            raise ConfigError(f"unknown configuration key: output.{key}")
    integrations = _mapping(document, "integrations")
    for name in integrations:
        if name not in INTEGRATIONS:
            raise ConfigError(f"unknown configuration key: integrations.{name}")
        block = _mapping(integrations, name, parent="integrations")
        for key in block:
            if key.lower() in _SECRET_KEYS:
                raise ConfigError(
                    f"refusing secret value at integrations.{name}.{key}; "
                    "declare an environment variable name with token_env instead"
                )
            if key not in _BLOCK_KEYS:
                raise ConfigError(f"unknown configuration key: integrations.{name}.{key}")


def _check_types(document):
    project = _mapping(document, "project")
    if "name" in project and not isinstance(project["name"], str):
        raise ConfigError("invalid configuration: project.name must be a string")
    scan = _mapping(document, "scan")
    if "target_type" in scan and scan["target_type"] not in ("fs", "image"):
        raise ConfigError("invalid configuration: scan.target_type must be 'fs' or 'image'")
    if "target" in scan and scan["target"] is not None and not isinstance(scan["target"], str):
        raise ConfigError("invalid configuration: scan.target must be a string")
    if "runner" in scan and scan["runner"] not in ("docker", "local"):
        raise ConfigError("invalid configuration: scan.runner must be 'docker' or 'local'")
    for key in ("image", "executable"):
        if key in scan and not isinstance(scan[key], str):
            raise ConfigError(f"invalid configuration: scan.{key} must be a string")
    for key in ("scanners", "severity", "exclude_paths"):
        value = scan.get(key)
        required = key != "exclude_paths"
        if value is not None and (not isinstance(value, list)
                                  or (required and not value)
                                  or not all(isinstance(item, str) and item for item in value)):
            raise ConfigError(
                f"invalid configuration: scan.{key} must be a list of non-empty strings"
            )
    timeout = scan.get("timeout_seconds")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int)):
        raise ConfigError("invalid configuration: scan.timeout_seconds must be an integer")
    output = _mapping(document, "output")
    if "directory" in output and not isinstance(output["directory"], str):
        raise ConfigError("invalid configuration: output.directory must be a string")
    for name, block in _mapping(document, "integrations").items():
        for key in ("enabled", "required", "auto_create", "auto_create_context", "reimport"):
            if key in block and not isinstance(block[key], bool):
                raise ConfigError(
                    f"invalid configuration: integrations.{name}.{key} must be a boolean"
                )
        for key in ("endpoint_env", "token_env"):
            if key in block and not isinstance(block[key], str):
                raise ConfigError(
                    f"invalid configuration: integrations.{name}.{key} must be a string"
                )
        if "endpoint" in block and block["endpoint"] is not None and not isinstance(
                block["endpoint"], str):
            raise ConfigError(
                f"invalid configuration: integrations.{name}.endpoint must be a string"
            )
        for key in ("wait_timeout_seconds", "timeout_seconds", "max_attempts"):
            if key in block and (isinstance(block[key], bool) or not isinstance(block[key], int)
                                 or block[key] < 1 or block[key] > (10 if key == "max_attempts" else 600)):
                raise ConfigError(f"invalid configuration: integrations.{name}.{key} must be a positive bounded integer")
        for key in ("product_name", "product_type_name", "engagement_name", "test_title_prefix"):
            if key in block and not isinstance(block[key], str):
                raise ConfigError(f"invalid configuration: integrations.{name}.{key} must be a string")


def _mapping(document, key, *, parent=None):
    value = document.get(key)
    if value is None:
        return {}
    location = f"{parent}.{key}" if parent else key
    if not isinstance(value, dict):
        raise ConfigError(f"invalid configuration: {location} must be a mapping")
    return value


def _check_relative(value, label):
    if not isinstance(value, str) or not value:
        raise ConfigError(f"invalid configuration: {label} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"invalid configuration: {label} must stay inside the project root")


def _check_state_separation(output_directory):
    output = Path(output_directory)
    state = Path(".barad") / "state"
    if output == state or state in output.parents:
        raise ConfigError(
            "invalid configuration: output.directory must not overlap the state "
            f"directory: {state.as_posix()}"
        )


def _check_endpoint(integrations):
    for name in INTEGRATIONS:
        value = integrations[name].get("endpoint")
        if value is None:
            continue
        parsed = urlsplit(str(value))
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ConfigError(
                f"invalid configuration: integrations.{name}.endpoint must be a plain "
                "http(s) URL without credentials, query or fragment"
            )
