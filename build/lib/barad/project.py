"""Automatic project identity and filesystem ecosystem detection.

Identity is derived, never guessed from a network call: the Git top level name
when the target is inside a repository, otherwise the target directory name. A
`.barad.yml` value wins when it is not `auto`. Ecosystem detection is a bounded
walk for well-known manifest names; it never reads their contents.
"""
import fnmatch
import os
import re
from pathlib import Path

ECOSYSTEM_MARKERS = (
    ("node", ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")),
    ("python", ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg",
                "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock")),
    ("go", ("go.mod", "go.sum")),
    ("java", ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile")),
    ("dotnet", ("global.json",)),
    ("ruby", ("Gemfile", "Gemfile.lock")),
    ("php", ("composer.json", "composer.lock")),
    ("rust", ("Cargo.toml", "Cargo.lock")),
    ("container", ("Dockerfile", "Containerfile")),
)

ECOSYSTEM_GLOBS = {
    "dotnet": ("*.csproj", "*.fsproj", "*.sln"),
    "container": ("Dockerfile.*", "*.dockerfile"),
}

_SKIP_DIRECTORIES = {
    ".git", ".venv", "venv", "node_modules", ".barad-dur", "dist", "build",
    "target", "vendor", "__pycache__", ".secrets",
}
_IDENTITY_INVALID = re.compile(r"[^A-Za-z0-9 ._:/+@-]")
_IDENTITY_LEADING = re.compile(r"^[^A-Za-z0-9]+")


def sanitize_name(raw):
    """Coerce a directory name into the configuration identity contract."""
    cleaned = _IDENTITY_INVALID.sub("-", str(raw or "").strip())
    cleaned = re.sub(r"[- ]{2,}", "-", cleaned).strip(" -")[:100]
    cleaned = _IDENTITY_LEADING.sub("", cleaned)
    return cleaned or "project"


def derive_name(configured, git_root, root):
    """Return `(name, name_source)` for an explicit, Git or directory identity."""
    if isinstance(configured, str) and configured.strip() and configured.strip().lower() != "auto":
        return configured.strip(), "config"
    if git_root is not None:
        return sanitize_name(Path(git_root).name), "git"
    return sanitize_name(Path(root).name), "directory"


def detect_ecosystems(root, *, max_depth=4, max_entries=2000):
    """Return detected ecosystems in a stable, documented order."""
    root = Path(root)
    found = set()
    seen = 0
    for current, directories, files in os.walk(root):
        depth = len(Path(current).relative_to(root).parts)
        if depth >= max_depth:
            directories[:] = []
        directories[:] = [name for name in directories
                          if name not in _SKIP_DIRECTORIES and not name.startswith(".")]
        seen += len(files)
        if seen > max_entries:
            break
        names = set(files)
        for ecosystem, markers in ECOSYSTEM_MARKERS:
            if ecosystem in found:
                continue
            if names.intersection(markers) or any(
                fnmatch.fnmatch(name, pattern)
                for pattern in ECOSYSTEM_GLOBS.get(ecosystem, ())
                for name in names
            ):
                found.add(ecosystem)
    return [ecosystem for ecosystem, _ in ECOSYSTEM_MARKERS if ecosystem in found]
