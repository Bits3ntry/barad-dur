"""CLI evidence layout: `<reports>/<project>/<version>/<scan-id>/` plus `.barad/state/`.

`<reports>` is the workspace reports directory (or the `--out` directory).
Scan-ids embed a UTC timestamp plus a random suffix, so repeated scans of the
same project version simply add a new scan-id folder; no evidence is replaced.

A Trivy secret finding embeds the matched credential in the raw report, so the
CLI treats its evidence as private: managed directories are 0700 and evidence
files are 0600 on POSIX, both before and after the scanner runs.
"""
import json
import os
import re
import secrets
from pathlib import Path

from .core.errors import EvidenceError
from .core.evidence import sha256_file, utc_timestamp

STATE_FILENAME = "local-inventory.json"


def slug(value):
    """Folder-safe fragment for project names and versions."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-." )
    return cleaned[:120] or "unresolved"


class ScanStore:
    def __init__(self, root, output_directory, scan_id, project=None, version=None):
        self.root = Path(root).resolve()
        self.output = Path(output_directory)
        if not self.output.is_absolute():
            self.output = self.root / output_directory
        self.output = self.output.resolve()
        if self.output == self.root / ".barad" / "state" or (
                self.root / ".barad" / "state").resolve() in self.output.parents:
            raise ValueError("output directory overlaps the workspace state")
        self.scan_id = scan_id
        self.project = slug(project) if project else None
        self.version = slug(version) if version else None
        if self.project:
            # Even an unresolved version gets its own folder so later scans of the
            # same project never mix evidence.
            self.evidence = self.output / self.project / (self.version or "unresolved")
        else:
            self.evidence = self.output
        self.run_dir = self.evidence / scan_id
        self.state_dir = self.root / ".barad" / "state"
        self.state_path = self.state_dir / STATE_FILENAME
        self.sync_path = self.state_dir / "remote-sync.json"
        self.log_path = self.run_dir / "execution.log"

    def prepare(self):
        """Create the evidence directories (project/version/scan-id when known)."""
        _private_directory(self.root / ".barad")
        if self.output != self.root:
            _private_directory(self.output)
        _private_directory(self.evidence)
        _private_directory(self.state_dir)
        _private_directory(self.run_dir)
        _private_file(self.log_path)
        return self

    def protect_evidence(self):
        """Tighten scanner-produced evidence to owner-only files where possible.

        The 0700 run directory is the primary control, so a container that writes
        root-owned reports cannot make the scan fail; such files are returned so
        the manifest can record that their mode could not be tightened.
        """
        unprotected = []
        for path in self.run_dir.rglob("*"):
            if path.is_file() and not path.is_symlink():
                if not _chmod(path, 0o600, strict=False):
                    unprotected.append(str(path))
        if self.state_path.is_file():
            if not _chmod(self.state_path, 0o600, strict=False):
                unprotected.append(str(self.state_path))
        return unprotected

    def artifact_path(self, name):
        return self.run_dir / name

    def write_json(self, name, payload):
        path = self.artifact_path(name)
        _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True,
                                       ensure_ascii=False) + "\n")
        return path

    def sha256(self, name):
        return sha256_file(self.artifact_path(name))

    def write_checksums(self, names):
        entries = {}
        for name in names:
            path = self.artifact_path(name)
            if path.is_file():
                entries[name] = sha256_file(path)
        lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items()))
        _atomic_write(self.artifact_path("checksums.sha256"), lines)
        return entries

    def inventory_record(self, project, target_key):
        document = _load(self.state_path)
        projects = document.get("targets")
        if not isinstance(projects, dict):
            return None
        records = projects.get(project)
        if not isinstance(records, dict):
            return None
        record = records.get(target_key)
        return record if isinstance(record, dict) else None

    def sync_record(self, key):
        return _load(self.sync_path).get(key)

    def record_sync(self, key, record):
        document = _load(self.sync_path)
        document[key] = record
        _atomic_write(self.sync_path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    def record_inventory(self, project, target_key, record):
        document = _load(self.state_path)
        targets = document.get("targets")
        if not isinstance(targets, dict):
            targets = {}
            document["targets"] = targets
        projects = targets.get(project)
        if not isinstance(projects, dict):
            projects = {}
            targets[project] = projects
        projects[target_key] = record
        document["version"] = 1
        document["updated_at"] = utc_timestamp()
        _atomic_write(self.state_path, json.dumps(document, indent=2, sort_keys=True) + "\n")


def _private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise EvidenceError(f"refusing symlinked evidence directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    _chmod(path, 0o700)


def _private_file(path):
    path = Path(path)
    if path.is_symlink():
        raise EvidenceError(f"refusing symlinked evidence file: {path}")
    path.touch(exist_ok=True)
    _chmod(path, 0o600)


def _chmod(path, mode, *, strict=True):
    if os.name != "posix":  # pragma: no cover - Windows has no POSIX mode contract
        return True
    try:
        os.chmod(path, mode)
    except OSError as error:
        if strict:
            raise EvidenceError(
                f"cannot secure evidence permissions for {path}: {error}"
            ) from None
        return False
    return True


def _load(path):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return document if isinstance(document, dict) else {}


def _atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    _chmod(temporary, 0o600)
    os.replace(temporary, path)
    _chmod(path, 0o600)
    return path
