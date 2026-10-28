"""Resolve the application version from code, without inventing one.

Supported sources (see `project.version.source`): `auto`, `package-json`,
`pyproject`, `file`, `literal`, `env`, `git-tag`. `auto` tries package.json, then
pyproject.toml, then the nearest Git tag and finally reports that the version is
unresolved instead of guessing.
"""
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 and older
    tomllib = None

_MUTABLE = {"latest", "main", "master", "head", "develop", "development", "snapshot"}


@dataclass
class VersionInfo:
    value: str = None
    source: str = "unresolved"
    path: str = None
    problems: list = field(default_factory=list)

    @property
    def resolved(self):
        return bool(self.value)

    def public(self):
        return {
            "value": self.value,
            "source": self.source,
            "path": self.path,
            "resolved": self.resolved,
            "problems": list(self.problems),
        }


def is_mutable_version(value):
    return str(value or "").strip().lower() in _MUTABLE


def _read_package_json(text):
    document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError("package.json root must be an object")
    version = document.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("package.json has no string version field")
    return version.strip()


def _read_pyproject(text):
    if tomllib is None:
        matches = re.findall(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if not matches:
            raise ValueError("pyproject.toml has no version field")
        return matches[0].strip()
    document = tomllib.loads(text)
    project = document.get("project") if isinstance(document.get("project"), dict) else {}
    version = project.get("version")
    if not isinstance(version, str):
        tool = document.get("tool") if isinstance(document.get("tool"), dict) else {}
        poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
        version = poetry.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("pyproject.toml has no project.version")
    return version.strip()


def _read_flat_file(text, key=None):
    if key:
        document = json.loads(text)
        node = document
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                raise ValueError(f"key {key} not found")
            node = node[part]
        return str(node).strip()
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if not first:
        raise ValueError("version file is empty")
    return first


def _read_text(path):
    return Path(path).read_text(encoding="utf-8")


def resolve_version(config, *, environ=None):
    """Read the declared application version from the working tree."""
    env = environ if environ is not None else os.environ
    version_config = config.version_sources() or {}
    declared = version_config.get("source", "auto")
    project_root = config.project_root()
    candidates = [declared] if declared != "auto" else ["package-json", "pyproject", "git-tag"]

    problems = []
    for source in candidates:
        try:
            if source == "package-json":
                path = config.path(version_config.get("path") or str(Path(config.get("project.path", ".")) / "package.json"))
                value = _read_package_json(_read_text(path))
            elif source == "pyproject":
                path = config.path(version_config.get("path") or str(Path(config.get("project.path", ".")) / "pyproject.toml"))
                value = _read_pyproject(_read_text(path))
            elif source == "file":
                path = config.path(version_config.get("path"))
                value = _read_flat_file(_read_text(path), version_config.get("key"))
            elif source == "literal":
                value = version_config.get("value", "").strip()
                path = None
            elif source == "env":
                value = (env.get(version_config.get("env", "")) or "").strip()
                path = None
            elif source == "git-tag":
                value, path = _git_tag_version(project_root), None
            else:  # pragma: no cover - schema rejects this
                problems.append({"code": "unsupported_version_source", "detail": source})
                continue
        except (OSError, ValueError, json.JSONDecodeError) as error:
            problems.append({"code": "version_unreadable", "source": source, "detail": str(error).splitlines()[0]})
            continue
        if value:
            relative = None
            if path is not None:
                try:
                    relative = str(Path(path).resolve().relative_to(config.repo_root))
                except ValueError:
                    relative = str(path)
            return VersionInfo(value=value, source=source, path=relative, problems=problems)
        problems.append({"code": "version_empty", "source": source})
    return VersionInfo(value=None, source="unresolved", path=None, problems=problems)


def _git_tag_version(project_root):
    result = subprocess.run(
        ["git", "-C", str(project_root), "describe", "--tags", "--abbrev=0"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError("no reachable Git tag")
    return result.stdout.strip().lstrip("v")


def resolve_version_at_commit(config, commit, *, environ=None, git_offset=""):
    """Read the same version declaration as it existed at `commit`.

    `git_offset` is the path from the Git top level to the configured repository
    root; Git wants paths from the top level, the configuration speaks from its
    own root.
    """
    if not commit:
        return VersionInfo(value=None, source="unresolved", problems=[{"code": "base_reference_unavailable"}])
    env = environ if environ is not None else os.environ
    version_config = config.version_sources() or {}
    current = resolve_version(config, environ=env)
    source = version_config.get("source", "auto")
    if source in ("literal", "env", "git-tag"):
        return VersionInfo(value=None, source=source,
                           problems=[{"code": "version_comparison_not_applicable", "source": source}])
    if source == "auto" and not current.path:
        return VersionInfo(value=None, source="unresolved",
                           problems=[{"code": "version_comparison_not_applicable", "source": "auto"}])
    path = current.path or version_config.get("path")
    if not path:
        return VersionInfo(value=None, source="unresolved", problems=[{"code": "version_path_unknown"}])
    git_path = f"{git_offset}/{path}" if git_offset else path
    result = subprocess.run(
        ["git", "-C", str(config.repo_root), "show", f"{commit}:{git_path}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return VersionInfo(value=None, source=source, path=path,
                           problems=[{"code": "version_file_absent_at_base", "path": path}])
    try:
        if path.endswith("package.json"):
            value = _read_package_json(result.stdout)
        elif path.endswith("pyproject.toml"):
            value = _read_pyproject(result.stdout)
        else:
            value = _read_flat_file(result.stdout, version_config.get("key"))
    except (ValueError, json.JSONDecodeError) as error:
        return VersionInfo(value=None, source=source, path=path,
                           problems=[{"code": "version_unreadable_at_base", "detail": str(error)}])
    return VersionInfo(value=value, source=source, path=path)
