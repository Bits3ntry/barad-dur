"""Change detection: what actually changed between a base reference and now.

The detector never assumes that ordinary code means a new dependency graph. It
classifies every relevant path as dependency, build-context, version-declaration
or code, scopes the comparison to this service (monorepos), and compares the
declared application version at the base commit against the working tree.
"""
import fnmatch
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .versioning import resolve_version, resolve_version_at_commit

STATUS_LABELS = {
    "A": "added",
    "M": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "copied",
    "T": "type_changed",
    "U": "unmerged",
    "?": "untracked",
}


def matches_any(path, patterns):
    """Return the pattern that matched, or None.

    Patterns are evaluated three ways, because a repository may write `uv.lock`,
    `**/uv.lock` or `requirements/*.txt`: exact fnmatch, the same without a
    leading `**/`, and basename matching for slash-free patterns.
    """
    if not path:
        return None
    for pattern in patterns or ():
        if fnmatch.fnmatchcase(path, pattern):
            return pattern
        if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
            return pattern
        if "/" not in pattern and fnmatch.fnmatchcase(Path(path).name, pattern):
            return pattern
    return None


@dataclass
class Change:
    status: str
    path: str
    old_path: str = None
    category: str = "code"
    pattern: str = None

    def public(self):
        payload = {"status": STATUS_LABELS.get(self.status, self.status.lower()),
                   "path": self.path, "category": self.category}
        if self.old_path:
            payload["old_path"] = self.old_path
        if self.pattern:
            payload["matched_pattern"] = self.pattern
        return payload


@dataclass
class ChangeReport:
    base_sha: str = None
    head_sha: str = None
    base_available: bool = False
    base_resolution: str = "unavailable"
    changes: list = field(default_factory=list)
    ignored: list = field(default_factory=list)
    dependency_changed: bool = False
    build_context_changed: bool = False
    version_file_changed: bool = False
    code_changed: bool = False
    version_changed: bool = False
    previous_version: str = None
    current_version: str = None
    version_comparison: str = "not_comparable"
    problems: list = field(default_factory=list)

    @property
    def files_changed(self):
        return sorted({change.path for change in self.changes})

    def public(self):
        return {
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "base_available": self.base_available,
            "base_resolution": self.base_resolution,
            "dependency_changed": self.dependency_changed,
            "version_changed": self.version_changed,
            "build_context_changed": self.build_context_changed,
            "code_changed": self.code_changed,
            "files_changed": self.files_changed,
            "files_ignored": len(self.ignored),
            "previous_version": self.previous_version,
            "current_version": self.current_version,
            "version_comparison": self.version_comparison,
            "problems": list(self.problems),
        }


def _git(repo, args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def parse_name_status(output):
    """Parse `git diff --name-status -z`: `R100\0old\0new\0`, `M\0path\0`."""
    parts = [part for part in output.split("\0")]
    if parts and parts[-1] == "":
        parts.pop()
    changes = []
    index = 0
    while index < len(parts):
        status = parts[index]
        index += 1
        if not status:
            continue
        letter = status[0]
        if letter in ("R", "C"):
            if index + 1 >= len(parts):
                break
            old_path, new_path = parts[index], parts[index + 1]
            index += 2
            changes.append((letter, new_path, old_path))
        else:
            if index >= len(parts):
                break
            changes.append((letter, parts[index], None))
            index += 1
    return changes


def parse_porcelain(output):
    """Parse `git status --porcelain -z`: renames carry the *new* path first."""
    parts = [part for part in output.split("\0")]
    if parts and parts[-1] == "":
        parts.pop()
    changes = []
    index = 0
    while index < len(parts):
        entry = parts[index]
        index += 1
        if len(entry) < 4:
            continue
        code = entry[:2]
        letter = code.strip()[0] if code.strip() else "M"
        path = entry[3:]
        old_path = None
        if "R" in code or "C" in code:
            if index < len(parts):
                old_path = parts[index]
                index += 1
        if letter == "?":
            letter = "A"
        changes.append((letter, path, old_path))
    return changes


def _scope_prefixes(config):
    prefixes = []
    project_path = str(config.get("project.path", ".") or ".")
    prefixes.append("" if project_path in (".", "./") else project_path.strip("/") + "/")
    for related in config.get("project.related_paths", []) or []:
        prefixes.append(related.strip("/") + "/")
    return prefixes


def _is_relevant(path, prefixes):
    if not prefixes:
        return True
    return any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in prefixes)


def detect_changes(config, context, version_info=None):
    """Compare the working tree (and, for a base SHA, all commits) with the base."""
    report = ChangeReport(
        base_sha=context.base_sha,
        head_sha=context.head_sha,
        base_available=bool(context.base_sha),
        base_resolution=context.base_resolution,
    )
    if not context.available:
        report.problems.extend(context.problems)
        _compare_versions(config, report, version_info, base_sha=None)
        return report

    repo = context.repository_root
    entries = []
    if context.base_sha:
        try:
            entries.extend(parse_name_status(_git(repo, ["diff", "--name-status", "-z", "-M",
                                                         context.base_sha, context.head_sha or "HEAD"])))
        except RuntimeError as error:
            report.problems.append({"code": "diff_failed", "detail": str(error)})
            report.base_available = False
    if context.event in ("local", "dispatch"):
        try:
            tracked = parse_porcelain(_git(repo, ["status", "--porcelain", "-z"]))
        except RuntimeError as error:
            report.problems.append({"code": "status_failed", "detail": str(error)})
            tracked = []
        seen = {(entry[1], entry[2]) for entry in entries}
        for entry in tracked:
            if (entry[1], entry[2]) not in seen:
                entries.append(entry)

    dependency_patterns = config.dependency_patterns()
    build_patterns = config.build_patterns()
    include_patterns = config.include_patterns()
    prefixes = _scope_prefixes(config)
    version_path = (version_info.path if version_info and version_info.path else None)
    if not version_path:
        declared = config.version_sources().get("path")
        if declared:
            version_path = declared

    for status, path, old_path in entries:
        if not _is_relevant(path, prefixes) and not (old_path and _is_relevant(old_path, prefixes)):
            report.ignored.append(path)
            continue
        dependency = matches_any(path, dependency_patterns) or matches_any(old_path, dependency_patterns)
        build = matches_any(path, build_patterns) or matches_any(old_path, build_patterns)
        included = matches_any(path, include_patterns) or matches_any(old_path, include_patterns)
        if version_path and (path == version_path or old_path == version_path):
            category, pattern, is_version = "version", None, True
        elif build:
            # Build context wins over include_patterns: a Dockerfile is not a lockfile.
            category, pattern, is_version = "build", build, False
        elif dependency or included:
            category, pattern, is_version = "dependency", dependency or included, False
        else:
            category, pattern, is_version = "code", None, False
        report.changes.append(Change(status=status, path=path, old_path=old_path,
                                     category=category, pattern=pattern))
        report.dependency_changed |= category == "dependency"
        report.build_context_changed |= category == "build"
        report.version_file_changed |= is_version
        report.code_changed |= category == "code"

    _compare_versions(config, report, version_info, base_sha=context.base_sha if report.base_available else None)
    return report


def _compare_versions(config, report, version_info, base_sha):
    current = version_info or resolve_version(config)
    report.current_version = current.value
    if not current.value:
        report.version_comparison = "current_unresolved"
        report.problems.extend(current.problems)
        return
    if not base_sha:
        report.version_comparison = "base_reference_unavailable"
        return
    previous = resolve_version_at_commit(config, base_sha)
    report.previous_version = previous.value
    if not previous.value:
        report.version_comparison = "previous_unresolved"
        report.problems.extend(previous.problems)
        return
    report.version_comparison = "compared"
    report.version_changed = previous.value != current.value
