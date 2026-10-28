"""Evidence store: every run leaves a directory that explains itself.

Layout (inside `artifacts.directory`, `.barad-dur/security` by default):

    runs/<run-id>/manifest.json        structured result and effective config
    runs/<run-id>/decisions.json       why each step ran or was skipped
    runs/<run-id>/trivy-report.json    Trivy JSON report (always)
    runs/<run-id>/sbom.cdx.json        CycloneDX inventory (conditional)
    runs/<run-id>/execution.log        JSON Lines log
    runs/<run-id>/publication.json     per-integration publication outcome
    runs/<run-id>/checksums.sha256     SHA-256 of every evidentiary file
    state/inventory.json               last known inventory per service+version
    state/publications.json            idempotency ledger for publications
    pending/<run-id>.json              evidence waiting to be published later

Everything is written atomically so an interrupted run never leaves a truncated
manifest or a half-written ledger.
"""
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

# Enumerated step/result states (uppercase on purpose: they are the contract).
PENDING = "PENDING"
RUNNING = "RUNNING"
SUCCESS = "SUCCESS"
FAILED = "FAILED"
SKIPPED = "SKIPPED"
PARTIAL = "PARTIAL"


def utc_now():
    return datetime.now(timezone.utc)


def utc_timestamp(moment=None):
    return (moment or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_run_id(source, moment=None):
    stamp = (moment or utc_now()).strftime("%Y%m%dT%H%M%SZ")
    return f"{source}-{stamp}-{secrets.token_hex(3)}"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    kwargs = {} if mode == "wb" else {"encoding": "utf-8"}
    with open(temporary, mode, **kwargs) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return path


class RunStore:
    def __init__(self, config, run_id, logger=None):
        self.config = config
        self.run_id = run_id
        self.logger = logger
        self.root = config.artifacts_root()
        self.run_dir = self.root / "runs" / run_id
        self.state_dir = self.root / "state"
        self.pending_dir = self.root / "pending"
        self.inventory_path = self.state_dir / "inventory.json"
        self.ledger_path = self.state_dir / "publications.json"
        self.log_path = self.run_dir / "execution.log"

    # -- paths -------------------------------------------------------------
    def prepare(self):
        for directory in (self.run_dir, self.state_dir, self.pending_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    def artifact_path(self, name):
        return self.run_dir / name

    def relative(self, path):
        try:
            return str(Path(path).resolve().relative_to(self.root.resolve()))
        except ValueError:
            return str(path)

    # -- artifacts ---------------------------------------------------------
    def write_json(self, name, payload):
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return _atomic_write(self.artifact_path(name), text)

    def write_text(self, name, text):
        return _atomic_write(self.artifact_path(name), text)

    def write_bytes(self, name, data):
        return _atomic_write(self.artifact_path(name), data)

    def copy_in(self, name, source):
        return self.write_bytes(name, Path(source).read_bytes())

    def sha256(self, name):
        return sha256_file(self.artifact_path(name))

    def checksum_entries(self, names):
        entries = {}
        for name in names:
            path = self.artifact_path(name)
            if path.is_file():
                entries[name] = sha256_file(path)
        return entries

    def write_checksums(self, names):
        entries = self.checksum_entries(names)
        lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items()))
        _atomic_write(self.artifact_path("checksums.sha256"), lines)
        entries["checksums.sha256"] = self.sha256("checksums.sha256")
        return entries

    # -- state -------------------------------------------------------------
    def _load(self, path, default):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _save(self, path, payload):
        _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def inventory(self):
        document = self._load(self.inventory_path, {})
        return document if isinstance(document, dict) else {}

    def inventory_record(self, service, version):
        entry = self.inventory().get("services", {}).get(service, {})
        return entry.get(str(version)) if isinstance(entry, dict) else None

    def has_inventory(self, service, version):
        record = self.inventory_record(service, version)
        return bool(record and record.get("sbom_sha256"))

    def record_inventory(self, service, version, record):
        document = self.inventory()
        services = document.setdefault("services", {})
        versions = services.setdefault(service, {})
        versions[str(version)] = record
        document["updated_at"] = utc_timestamp()
        self._save(self.inventory_path, document)

    def ledger(self):
        document = self._load(self.ledger_path, {})
        return document if isinstance(document, dict) else {}

    def ledger_get(self, key):
        entry = self.ledger().get(key)
        return entry if isinstance(entry, dict) else None

    def ledger_put(self, key, record):
        document = self.ledger()
        document[key] = record
        self._save(self.ledger_path, document)

    # -- deferred publication ---------------------------------------------
    def enqueue_pending(self, payload):
        payload = dict(payload)
        payload.setdefault("run_id", self.run_id)
        payload["queued_at"] = utc_timestamp()
        path = self.pending_dir / f"{self.run_id}.json"
        self._save(path, payload)
        return path

    def pending_entries(self):
        entries = []
        for path in sorted(self.pending_dir.glob("*.json")):
            document = self._load(path, None)
            if isinstance(document, dict):
                document["_path"] = str(path)
                entries.append(document)
        return entries

    def drop_pending(self, run_id=None):
        run_id = run_id or self.run_id
        path = self.pending_dir / f"{run_id}.json"
        if path.exists():
            path.unlink()
            return True
        return False
