"""Load, expand, merge and validate `barad-security.yml`.

The YAML file is an internal contract for this runner, not a Trivy native
configuration. Validation happens in three layers so failures are always
actionable:

1. JSON Schema (structure, enumerations, path and glob syntax) with the exact
   document path of every violation;
2. semantic rules (Trivy always runs, SBOM comes only from Trivy, no absolute or
   escaping paths, source-specific version resolution);
3. environment expansion `${VAR}` / `${VAR:-default}` so a repository can point
   at an endpoint without hard-coding it, while credentials stay in environment
   variables whose *names* are what the file declares.
"""
import copy
import hashlib
import json
import os
import re
from pathlib import Path

import jsonschema
import yaml

from .errors import ConfigError

SCHEMA_PATH = Path(__file__).resolve().with_name("schema") / "config.schema.json"

CONFIG_FILENAMES = ("barad-security.yml", "barad-security.yaml")

DEFAULT_INCLUDE_PATTERNS = [
    "**/package.json",
    "**/package-lock.json",
    "**/npm-shrinkwrap.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/pyproject.toml",
    "**/poetry.lock",
    "**/uv.lock",
    "**/requirements*.txt",
    "**/Dockerfile*",
    "**/.nvmrc",
    "**/.python-version",
]

# Dependency manifests: a change here can change the scanned package inventory.
DEFAULT_DEPENDENCY_PATTERNS = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "requirements*.txt",
    "requirements/*.txt",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "packages.config",
    "Directory.Packages.props",
    "Cargo.toml",
    "Cargo.lock",
]

# Build context: a change here can change what the artifact is built from.
DEFAULT_BUILD_PATTERNS = [
    "Dockerfile",
    "Dockerfile.*",
    "*.dockerfile",
    ".nvmrc",
    ".python-version",
    ".tool-versions",
    ".dockerignore",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose.yml",
    "compose.yaml",
]

DEFAULTS = {
    "project": {"path": "."},
    "execution": {
        "local_enabled": True,
        "github_enabled": True,
        "fail_on_findings": False,
        "fail_on_scanner_error": True,
        "log_level": "INFO",
    },
    "detection": {"base_ref": None},
    "trivy": {
        "enabled": True,
        "always_run": True,
        "runner": "local",
        "executable": "trivy",
        "image": "aquasec/trivy:0.76.1",
        "cache_enabled": True,
        "cache_dir": ".barad-dur/cache/trivy",
        "scan_type": "fs",
        "scanners": ["vuln", "secret", "misconfig"],
        "severity": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "report_format": "json",
        "timeout_seconds": 900,
    },
    "sbom": {
        "enabled": True,
        "generator": "trivy",
        "format": "cyclonedx",
        "generate_on": {
            "dependency_changes": True,
            "version_changes": True,
            "build_changes": True,
            "release": True,
        },
        "include_patterns": list(DEFAULT_INCLUDE_PATTERNS),
    },
    "artifacts": {
        "directory": ".barad-dur/security",
        "preserve_reports": True,
        "preserve_logs": True,
        "create_manifest": True,
        "checksums": "sha256",
    },
    "integrations": {
        "barad_dur": {
            "enabled": False,
            "required": False,
            "endpoint_env": "BARAD_DUR_URL",
            "token_env": "BARAD_DUR_TOKEN",
            "timeout_seconds": 20,
            "max_attempts": 3,
        },
        "dependency_track": {
            "enabled": False,
            "required": False,
            "endpoint_env": "DTRACK_URL",
            "token_env": "DTRACK_API_KEY",
            "publish_on_release": True,
            "update_development_project": False,
            "development_version": "main",
            "auto_create": True,
            "latest_policy": "never",
            "allow_release_overwrite": False,
            "wait_for_analysis": False,
            "wait_timeout_seconds": 300,
            "timeout_seconds": 30,
            "max_attempts": 3,
        },
        "defectdojo": {
            "enabled": False,
            "required": False,
            "endpoint_env": "DOJO_URL",
            "token_env": "DOJO_TOKEN",
            "publish_trivy_reports": False,
            "publish_on_pull_request": False,
            "reimport": True,
            "test_title_prefix": "",
            "minimum_severity": "Info",
            "auto_create_context": True,
            "timeout_seconds": 30,
            "max_attempts": 2,
        },
    },
    "notifications": {"direct_slack": False},
}

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

# A variable whose name ends in one of these words is treated as a credential.
# Expansion of such a variable is refused: a repository file must never be able
# to copy a runtime secret into a manifest, an outbound payload or a log line.
_CREDENTIAL_NAME = re.compile(r"(?i)(?:^|_)(?:token|secret|password|passwd|api_?key|access_key)$")

_INTEGRATION_ENV_KEYS = ("endpoint_env", "token_env")


def _declared_env_names(document):
    """Every environment variable the configuration names as an integration input."""
    names = set()
    for block in ("barad_dur", "dependency_track", "defectdojo"):
        settings = (document or {}).get("integrations", {}).get(block) if isinstance(document, dict) else None
        if not isinstance(settings, dict):
            defaults = DEFAULTS["integrations"].get(block, {})
            settings = defaults
        for key in _INTEGRATION_ENV_KEYS:
            value = settings.get(key)
            if isinstance(value, str) and value and _ENV_PATTERN.search(value) is None:
                names.add(value)
    return names


def _blocked_expansion_names(document, environ):
    blocked = _declared_env_names(document) | _declared_env_names(DEFAULTS)
    blocked |= {name for name in (environ or {}) if _CREDENTIAL_NAME.search(name)}
    return blocked


def _deep_merge(base, override):
    if not isinstance(base, dict) or not isinstance(override, dict):
        return copy.deepcopy(override)
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _expand(node, environ, errors, path=(), *, blocked=(), refused=None):
    refused = refused if refused is not None else []
    if isinstance(node, str):
        def replace(match):
            name, default = match.group(1), match.group(2)
            if name in blocked:
                refused.append((".".join(path) or "<root>", name))
                return match.group(0)
            value = environ.get(name)
            if value is None:
                if default is not None:
                    return default
                location = ".".join(path) or "<root>"
                errors.append(f"{location} ({name})")
                return match.group(0)
            return value

        expanded = _ENV_PATTERN.sub(replace, node)
        # A value that is exactly one reference keeps its YAML type, so
        # `enabled: ${DTRACK_ENABLED:-false}` is a boolean, not the string "false".
        if _ENV_PATTERN.fullmatch(node) and expanded != node:
            lowered = expanded.strip().lower()
            if lowered in ("true", "false"):
                return lowered == "true"
            if lowered in ("null", "~", ""):
                return None
            if re.fullmatch(r"-?\d+", expanded.strip()):
                return int(expanded.strip())
        return expanded
    if isinstance(node, dict):
        return {key: _expand(value, environ, errors, path + (str(key),), blocked=blocked, refused=refused)
                for key, value in node.items()}
    if isinstance(node, list):
        return [_expand(value, environ, errors, path + (str(index),), blocked=blocked, refused=refused)
                for index, value in enumerate(node)]
    return node


def _format_schema_error(error):
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    message = error.message
    if error.validator == "additionalProperties" and isinstance(error.instance, dict):
        known = set(error.schema.get("properties", {}))
        unknown = [key for key in error.instance if key not in known]
        if unknown:
            message = f"unknown key(s): {', '.join(sorted(unknown))}"
    elif error.validator == "enum":
        message = f"value {error.instance!r} is not one of {', '.join(map(str, error.validator_value))}"
    elif error.validator == "pattern":
        message = f"value {error.instance!r} does not match {error.validator_value}"
    return f"{location}: {message}"


class Config:
    """Validated, expanded configuration bound to one repository root."""

    def __init__(self, data, *, source=None, repo_root=None, environ=None):
        self.data = data
        self.source = Path(source) if source else None
        self.repo_root = Path(repo_root).resolve() if repo_root else Path.cwd().resolve()
        self.environ = dict(environ if environ is not None else os.environ)

    # -- access -----------------------------------------------------------
    def get(self, path, default=None):
        node = self.data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def env(self, name, default=None):
        return self.environ.get(name, default)

    def env_value(self, config_path):
        """Read the value of the environment variable named at `config_path`."""
        name = self.get(config_path)
        if not name:
            return None, None
        return name, self.environ.get(name)

    def path(self, relative):
        """Resolve a repository-relative path, refusing to escape the repository."""
        candidate = (self.repo_root / relative).resolve()
        if candidate != self.repo_root and self.repo_root not in candidate.parents:
            raise ConfigError(f"path escapes the repository root: {relative}")
        return candidate

    def project_root(self):
        return self.path(self.get("project.path", "."))

    def artifacts_root(self):
        return self.path(self.get("artifacts.directory", ".barad-dur/security"))

    def dependency_patterns(self):
        """Manifests and lockfiles only; build files are classified separately."""
        patterns = list(DEFAULT_DEPENDENCY_PATTERNS)
        for pattern in self.get("detection.dependency_patterns", []) or []:
            if pattern not in patterns:
                patterns.append(pattern)
        return patterns

    def include_patterns(self):
        """Files worth an inventory check even when no built-in pattern matches."""
        return list(self.get("sbom.include_patterns", []) or [])

    def build_patterns(self):
        patterns = list(DEFAULT_BUILD_PATTERNS)
        for pattern in self.get("detection.build_patterns", []) or []:
            if pattern not in patterns:
                patterns.append(pattern)
        return patterns

    def public(self):
        """Configuration safe to persist: environment *names*, never values."""
        document = copy.deepcopy(self.data)
        document.pop("_meta", None)
        return document

    def fingerprint(self):
        payload = json.dumps(self.data, sort_keys=True, ensure_ascii=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def version_sources(self):
        return self.get("project.version", {}) or {}


def find_config_file(repo_root, explicit=None):
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = Path(repo_root) / path
        if not path.is_file():
            raise ConfigError(f"configuration file not found: {path}")
        return path.resolve()
    for name in CONFIG_FILENAMES:
        candidate = Path(repo_root) / name
        if candidate.is_file():
            return candidate.resolve()
    raise ConfigError(
        "no barad-security.yml found in "
        f"{Path(repo_root).resolve()}; pass --config or copy config/barad-security.example.yml"
    )


def load_config(config_path=None, *, repo_root=None, environ=None):
    root = Path(repo_root or Path.cwd()).resolve()
    path = find_config_file(root, config_path)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error.strerror}") from None
    try:
        document = yaml.safe_load(raw_text)
    except yaml.YAMLError as error:
        raise ConfigError(f"{path.name} is not valid YAML: {error}") from None
    return build_config(document, source=path, repo_root=root, environ=environ)


def build_config(document, *, source=None, repo_root=None, environ=None, strict=True):
    """Expand, merge with defaults and validate a parsed document."""
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise ConfigError("configuration root must be a mapping")

    environment = dict(environ if environ is not None else os.environ)
    blocked = _blocked_expansion_names(document, environment)
    expansion_errors = []
    refused = []
    expanded = _expand(document, environment, expansion_errors, blocked=blocked, refused=refused)
    if refused:
        places = ", ".join(f"{location} ({name})" for location, name in sorted(set(refused)))
        raise ConfigError(
            "refusing to expand credential environment variable(s): "
            f"{places}. Integrations read their token from the environment at run time; "
            "a configuration file may only reference the variable name."
        )
    if expansion_errors:
        missing = ", ".join(sorted(set(expansion_errors)))
        raise ConfigError(f"undefined environment variable referenced at: {missing}")

    merged = _deep_merge(DEFAULTS, expanded)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(merged), key=lambda error: list(error.absolute_path))
    if errors:
        lines = [_format_schema_error(error) for error in errors[:12]]
        raise ConfigError("invalid configuration: " + " | ".join(lines))

    config = Config(merged, source=source, repo_root=repo_root, environ=environ)
    if strict:
        _check_semantics(config)
    return config


def _check_semantics(config):
    project_name = config.get("project.name")
    project_service = config.get("project.service")
    for label, value in (("project.name", project_name), ("project.service", project_service)):
        if value != value.strip():
            raise ConfigError(f"invalid configuration: {label} must not have leading or trailing whitespace")

    if not config.get("trivy.enabled", True):
        raise ConfigError(
            "invalid configuration: trivy.enabled must be true; the workflow requires a Trivy JSON report on every run"
        )
    if not config.get("trivy.always_run", True):
        raise ConfigError(
            "invalid configuration: trivy.always_run must be true; Trivy runs on every execution"
        )
    if config.get("sbom.generator") != "trivy":
        raise ConfigError("invalid configuration: sbom.generator must be 'trivy' (no other generator is integrated)")
    if config.get("sbom.format") != "cyclonedx":
        raise ConfigError("invalid configuration: sbom.format must be 'cyclonedx'")
    if config.get("trivy.report_format") != "json":
        raise ConfigError("invalid configuration: trivy.report_format must be 'json' for the evidence contract")
    if config.get("notifications.direct_slack"):
        raise ConfigError(
            "invalid configuration: notifications.direct_slack is not implemented in this POC; "
            "publish evidence to BARAD-DÛR and notify from there"
        )

    scan_type = config.get("trivy.scan_type")
    if scan_type == "image" and not config.get("trivy.target"):
        raise ConfigError("invalid configuration: trivy.target (image reference) is required when trivy.scan_type is 'image'")
    if scan_type == "fs":
        project_root = config.project_root()
        if not project_root.is_dir():
            raise ConfigError(f"invalid configuration: project.path does not exist or is not a directory: {config.get('project.path')}")
        target = config.get("trivy.target")
        if target:
            resolved = config.path(target)
            if not resolved.exists():
                raise ConfigError(f"invalid configuration: trivy.target does not exist: {target}")

    for related in config.get("project.related_paths", []) or []:
        if not config.path(related).exists():
            raise ConfigError(f"invalid configuration: project.related_paths entry does not exist: {related}")

    artifacts_directory = config.get("artifacts.directory")
    if Path(artifacts_directory).is_absolute():
        raise ConfigError("invalid configuration: artifacts.directory must be repository-relative")

    _check_version_source(config)

    dt = config.get("integrations.dependency_track", {}) or {}
    if dt.get("enabled") and dt.get("publish_on_release") and not config.get("sbom.enabled", True):
        raise ConfigError(
            "invalid configuration: dependency_track.publish_on_release requires sbom.enabled"
        )
    for block in ("dependency_track", "defectdojo", "barad_dur"):
        settings = config.get(f"integrations.{block}", {}) or {}
        if settings.get("enabled") and not settings.get("endpoint_env"):
            raise ConfigError(f"invalid configuration: integrations.{block}.endpoint_env is required when enabled")
        if settings.get("enabled") and settings.get("required") and not settings.get("token_env"):
            raise ConfigError(
                f"invalid configuration: integrations.{block}.token_env is required when the integration is enabled and required"
            )


def _check_version_source(config):
    version = config.version_sources()
    source = version.get("source", "auto")
    if source == "literal" and not version.get("value"):
        raise ConfigError("invalid configuration: project.version.source 'literal' requires project.version.value")
    if source == "env" and not version.get("env"):
        raise ConfigError("invalid configuration: project.version.source 'env' requires project.version.env")
    if source == "file" and not version.get("path"):
        raise ConfigError("invalid configuration: project.version.source 'file' requires project.version.path")
