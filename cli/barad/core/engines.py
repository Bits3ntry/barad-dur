"""Pinned engine distribution: one lockfile, one verified persistent user cache.

Barad ships the exact OpenGrep release it runs.  The lockfile is packaged inside
the CLI (`barad/resources/engines.lock.json`), so `pip install barad` is the only
installation step: there is no `latest` tag, no community container image and no
action-specific installer.

Guarantees the runner depends on:

* only the exact pinned release asset for the current platform is downloaded;
* a bare binary or an archive is verified against the locked SHA-256 *before*
  anything is extracted or published, so untrusted bytes are never executed;
* archive members are validated (no absolute paths, no `..`, no links or device
  entries), staged in a private directory and published file by file with an
  atomic rename, executable last, so a partially published install is impossible;
* the Windows executable keeps its sibling DLLs next to it in the cache;
* the cache is verified on every use, and a per-engine file lock serializes
  concurrent installs, with the integrity check repeated after the lock is held;
* the cache is per user (`XDG_CACHE_HOME`/`~/Library/Caches`), never inside the
  scanned repository, and an unsupported platform fails closed instead of
  downloading an unverified binary.
"""
import contextlib
import json
import os
import platform
import re
import shutil
import socket
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__
from .errors import ScannerError
from .evidence import sha256_file

ENGINE_NAME = "opengrep"
LOCK_DIRECTORY = "resources"
LOCK_FILENAME = "engines.lock.json"
CACHE_ENV = "BARAD_ENGINE_CACHE"
RECORD_FILENAME = ".barad-engine.json"
USER_AGENT = f"barad/{__version__}"

# Locked archive containers.  Anything else is rejected: an unpacker Barad has
# not reasoned about must never touch a cache directory.
ARCHIVE_FORMATS = ("tar.gz", "zip")

_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PLATFORM = re.compile(r"^[a-z0-9_]+-[a-z0-9_]+$")

# Only aliases with published release evidence are accepted; anything else is an
# unsupported host and must fail closed.
_PLATFORM_ALIASES = {
    "linux": {
        "x86_64": "linux-x86_64",
        "amd64": "linux-x86_64",
        "aarch64": "linux-aarch64",
        "arm64": "linux-aarch64",
    },
    "darwin": {
        "arm64": "macos-aarch64",
        "aarch64": "macos-aarch64",
    },
    "windows": {
        "x86": "windows-x86",
        "i386": "windows-x86",
        "i686": "windows-x86",
    },
}


class EngineError(ScannerError):
    """The pinned engine cannot be resolved, downloaded, unpacked or verified."""

    step = "opengrep"
    kind = "engine_error"


@dataclass(frozen=True)
class EngineSpec:
    """One pinned engine binary (bare or archived) for one platform."""

    name: str
    version: str
    platform: str
    asset: str
    sha256: str
    url: str
    archive: str = None
    entry: str = None

    @property
    def executable_name(self):
        """File name of the runnable binary inside the install directory."""
        return self.entry or self.name

    def public(self):
        return {
            "name": self.name,
            "version": self.version,
            "platform": self.platform,
            "asset": self.asset,
            "sha256": self.sha256,
            "url": self.url,
            "archive": self.archive,
            "entry": self.entry,
        }


def packaged_lock_path():
    """Absolute path of the lockfile shipped inside the installed package."""
    return Path(str(resources.files("barad").joinpath(LOCK_DIRECTORY, LOCK_FILENAME)))


def platform_key(system=None, machine=None):
    """Map a host to a locked platform key, or `None` when it is unsupported."""
    system = str(system or "").strip().lower()
    machine = str(machine or "").strip().lower()
    return _PLATFORM_ALIASES.get(system, {}).get(machine)


def default_cache_root(environ=None, *, home=None, system=None):
    """Persistent, per-user cache root; the environment can override it."""
    environment = dict(os.environ if environ is None else environ)
    override = environment.get(CACHE_ENV)
    if override:
        return Path(override).expanduser()
    home = Path(home) if home is not None else Path.home()
    system = str(system or platform.system() or "").strip().lower()
    if system == "darwin":
        base = home / "Library" / "Caches"
    elif system == "windows":
        base = Path(environment.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
    else:
        xdg = environment.get("XDG_CACHE_HOME")
        base = Path(xdg).expanduser() if xdg else home / ".cache"
    return base / "barad" / "engines"


def safe_member_path(name):
    """Return a normalized relative archive member path, or `None` if unsafe."""
    if not isinstance(name, str):
        return None
    relative = name
    while relative.startswith("./"):
        relative = relative[2:]
    if not relative or relative.startswith(("/", "\\")):
        return None
    if "\\" in relative or ":" in relative:
        return None
    parts = [part for part in relative.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return PurePosixPath(*parts).as_posix()


def load_lock(path=None):
    """Read and validate the lockfile; a mutable or malformed lock is an error."""
    source = Path(path) if path is not None else packaged_lock_path()
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except OSError as error:
        raise EngineError(
            f"engine lockfile is unreadable: {source}: {error.strerror or error}"
        ) from None
    except ValueError as error:
        raise EngineError(f"engine lockfile is not JSON: {source}: {error}") from None
    return _validate_lock(document, source)


def _validate_lock(document, source):
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise EngineError(f"engine lockfile must declare schema_version 1: {source}")
    engines = document.get("engines")
    if not isinstance(engines, dict) or not engines:
        raise EngineError(f"engine lockfile declares no engines: {source}")
    for name, engine in engines.items():
        location = f"engines.{name}"
        if not isinstance(engine, dict):
            raise EngineError(f"engine lockfile entry is not an object: {location}")
        version = engine.get("version")
        if not isinstance(version, str) or not _VERSION.match(version):
            raise EngineError(
                f"engine lockfile must pin an exact version instead of {version!r}: {location}"
            )
        if engine.get("release_tag") != f"v{version}":
            raise EngineError(
                f"engine lockfile release_tag must be v{version}: {location}"
            )
        base_url = engine.get("base_url")
        if (not isinstance(base_url, str) or not base_url.startswith("https://")
                or "latest" in base_url.lower()):
            raise EngineError(
                f"engine lockfile base_url must be a pinned https release URL: {location}"
            )
        binaries = engine.get("binaries")
        if not isinstance(binaries, dict) or not binaries:
            raise EngineError(f"engine lockfile declares no binaries: {location}")
        for key, binary in binaries.items():
            where = f"{location}.binaries.{key}"
            if not isinstance(key, str) or not _PLATFORM.match(key):
                raise EngineError(f"engine lockfile platform key is invalid: {where}")
            if not isinstance(binary, dict):
                raise EngineError(f"engine lockfile binary entry is not an object: {where}")
            asset = binary.get("asset")
            if not isinstance(asset, str) or not _ASSET.match(asset):
                raise EngineError(
                    f"engine lockfile asset must be a bare file name, not {asset!r}: {where}"
                )
            digest = binary.get("sha256")
            if not isinstance(digest, str) or not _DIGEST.match(digest):
                raise EngineError(
                    f"engine lockfile sha256 must be 64 lowercase hex characters: {where}"
                )
            archive = binary.get("archive")
            entry = binary.get("entry")
            if archive is None:
                if entry is not None:
                    raise EngineError(
                        f"engine lockfile declares entry without an archive format: {where}"
                    )
                continue
            if archive not in ARCHIVE_FORMATS:
                raise EngineError(
                    f"engine lockfile archive must be one of {', '.join(ARCHIVE_FORMATS)}, "
                    f"not {archive!r}: {where}"
                )
            if not isinstance(entry, str) or safe_member_path(entry) != entry:
                raise EngineError(
                    f"engine lockfile entry must be a safe relative member path, "
                    f"not {entry!r}: {where}"
                )
    return document


class EngineManager:
    """Resolve, download once and verify the pinned engine for this host."""

    def __init__(self, *, cache_dir=None, lock_path=None, platform=None, logger=None,
                 fetcher=None, environ=None, timeout=180.0, home=None, system=None,
                 lock_timeout=120.0, lock_poll=0.05):
        self.environ = dict(os.environ if environ is None else environ)
        self.lock_path = Path(lock_path) if lock_path is not None else None
        self.platform_override = platform
        self.logger = logger
        self.timeout = float(timeout)
        self.home = Path(home) if home is not None else None
        self.system = system
        self.lock_timeout = float(lock_timeout)
        self.lock_poll = float(lock_poll)
        self._fetch = fetcher
        self._lock = None
        self.cache_dir = (
            Path(cache_dir).expanduser() if cache_dir is not None
            else default_cache_root(self.environ, home=self.home, system=self.system)
        )

    # -- lockfile ----------------------------------------------------------
    def lock(self):
        if self._lock is None:
            self._lock = load_lock(self.lock_path)
        return self._lock

    def platform_key(self):
        if self.platform_override:
            return self.platform_override
        return platform_key(platform.system(), platform.machine())

    def host(self):
        return f"{platform.system() or 'unknown'}/{platform.machine() or 'unknown'}"

    def engine(self, name=ENGINE_NAME):
        """The pinned specification for `name` on this host, or an error."""
        engines = self.lock()["engines"]
        if name not in engines:
            raise EngineError(f"engine lockfile has no {name} entry: {self.lock_path or LOCK_FILENAME}")
        engine = engines[name]
        binaries = engine["binaries"]
        key = self.platform_key()
        if key is None or key not in binaries:
            raise EngineError(
                f"Barad pins {name} {engine['version']} only for "
                f"{', '.join(sorted(binaries))}; this host reports {self.host()}, and Barad "
                "does not download an unverified binary"
            )
        binary = binaries[key]
        url = (f"{engine['base_url'].rstrip('/')}/{engine['release_tag']}/"
               f"{binary['asset']}")
        return EngineSpec(name=name, version=engine["version"], platform=key,
                          asset=binary["asset"], sha256=binary["sha256"], url=url,
                          archive=binary.get("archive"), entry=binary.get("entry"))

    # -- cache layout ------------------------------------------------------
    def install_dir(self, spec):
        """Directory that holds the installed executable and its siblings."""
        return Path(self.cache_dir) / f"{spec.name}-{spec.version}" / spec.platform

    def executable_path(self, spec):
        """Absolute path the runner must invoke, whether or not it exists yet."""
        return self.install_dir(spec) / spec.executable_name

    def cached_path(self, name=ENGINE_NAME):
        return self.executable_path(self.engine(name))

    def lock_file(self, spec):
        """Per-engine, per-platform install lock shared by every Barad process."""
        return Path(self.cache_dir) / f"{spec.name}-{spec.version}" / f".{spec.platform}.lock"

    def verify(self, spec, path=None):
        """True when the cache still holds exactly the bytes the lockfile pins."""
        path = Path(path) if path is not None else self.executable_path(spec)
        if spec.archive is None:
            return path.is_file() and sha256_file(path) == spec.sha256
        record = self._read_record(spec)
        if record is None or not path.is_file():
            return False
        for relative, digest in record["files"].items():
            candidate = self.install_dir(spec) / relative
            if not candidate.is_file() or sha256_file(candidate) != digest:
                return False
        return True

    def inspect(self, name=ENGINE_NAME):
        """Report the pinned engine cache state without downloading or mutating it."""
        try:
            spec = self.engine(name)
        except EngineError as error:
            return {"status": "UNAVAILABLE", "reason": error.message}
        cached = self.verify(spec)
        return {
            "status": "HEALTHY" if cached else "UNAVAILABLE",
            "version": spec.version,
            "platform": spec.platform,
            "cached": cached,
            **({} if cached else {"reason": "engine_not_cached_or_verified"}),
        }

    def resolve(self, name=ENGINE_NAME):
        """Absolute path of the pinned, verified engine; downloads only when needed."""
        spec = self.engine(name)
        target = self.executable_path(spec)
        if self.verify(spec, target):
            self._log("engine_verified", spec, cached=True)
            return target.resolve()
        with self.cache_lock(spec):
            # Another Barad process may have installed it while we waited.
            if self.verify(spec, target):
                self._log("engine_verified", spec, cached=True)
                return target.resolve()
            if self.install_dir(spec).exists():
                self._log("engine_cache_mismatch", spec, cached=True)
            self._install(spec)
        return target.resolve()

    # -- install lock ------------------------------------------------------
    @contextlib.contextmanager
    def cache_lock(self, spec):
        """Serialize installs of one engine for one platform across processes."""
        path = self.lock_file(spec)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as error:
            raise EngineError(
                f"cannot open the {spec.name} install lock {path}: "
                f"{error.strerror or error}"
            ) from None
        try:
            _acquire_lock(handle, path, self.lock_timeout, self.lock_poll,
                          f"{spec.name} {spec.version} ({spec.platform})")
            yield path
        finally:
            try:
                _release_lock(handle)
            finally:
                os.close(handle)

    # -- installation ------------------------------------------------------
    def _install(self, spec):
        if spec.archive is None:
            self._install_binary(spec)
        else:
            self._install_archive(spec)
        self._log("engine_installed", spec, cached=False)

    def _install_binary(self, spec):
        target = self.executable_path(spec)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = self._staging_file(target, spec)
        try:
            self.fetcher(spec.url, staging)
            _require_digest(spec, staging)
            os.chmod(staging, 0o755)
            os.replace(staging, target)
        finally:
            if staging.exists():
                staging.unlink()

    def _install_archive(self, spec):
        install_dir = self.install_dir(spec)
        install_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{install_dir.name}-",
                                        dir=str(install_dir.parent)))
        try:
            download = staging / f"download.{spec.archive.replace('.', '_')}"
            self.fetcher(spec.url, download)
            # The archive checksum is verified before a single member is unpacked.
            _require_digest(spec, download)
            unpacked = self._extract(spec, download, staging / "tree")
            executable = spec.executable_name
            if executable not in unpacked:
                raise EngineError(
                    f"{spec.asset} does not contain the pinned entry {executable!r}"
                )
            install_dir.mkdir(parents=True, exist_ok=True)
            published = {}
            # Siblings (Windows DLLs) first: the executable appears only once
            # everything it needs is already in place.
            for relative in sorted(unpacked, key=lambda item: (item == executable, item)):
                staged = unpacked[relative]
                destination = install_dir / Path(*PurePosixPath(relative).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if relative == executable:
                    os.chmod(staged, 0o755)
                os.replace(staged, destination)
                published[relative] = sha256_file(destination)
            self._write_record(spec, published)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _extract(self, spec, archive_path, destination):
        destination.mkdir(parents=True, exist_ok=True)
        if spec.archive == "tar.gz":
            return self._extract_tar(spec, archive_path, destination)
        return self._extract_zip(spec, archive_path, destination)

    def _extract_tar(self, spec, archive_path, destination):
        unpacked = {}
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                for member in archive.getmembers():
                    if member.isdir():
                        # Directories are never published, but a traversing
                        # directory entry still marks the archive as unsafe.
                        self._member_path(spec, member.name, unpacked, directory=True)
                        continue
                    if not member.isfile():
                        raise EngineError(
                            f"{spec.asset} contains {member.name!r}, which is a link or "
                            "special file; Barad extracts regular files only"
                        )
                    relative = self._member_path(spec, member.name, unpacked)
                    source = archive.extractfile(member)
                    if source is None:
                        raise EngineError(
                            f"{spec.asset} member {member.name!r} has no readable content"
                        )
                    with source:
                        unpacked[relative] = _write_member(destination, relative, source)
        except tarfile.TarError as error:
            raise EngineError(f"{spec.asset} is not a readable .tar.gz archive: {error}") from None
        return unpacked

    def _extract_zip(self, spec, archive_path, destination):
        unpacked = {}
        try:
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        self._member_path(spec, info.filename, unpacked, directory=True)
                        continue
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        raise EngineError(
                            f"{spec.asset} contains {info.filename!r}, which is a symlink; "
                            "Barad extracts regular files only"
                        )
                    relative = self._member_path(spec, info.filename, unpacked)
                    with archive.open(info) as source:
                        unpacked[relative] = _write_member(destination, relative, source)
        except zipfile.BadZipFile as error:
            raise EngineError(f"{spec.asset} is not a readable .zip archive: {error}") from None
        return unpacked

    def _member_path(self, spec, name, unpacked, *, directory=False):
        relative = safe_member_path(name)
        if relative is None:
            if directory and str(name).strip() in ("", ".", "./"):
                return None  # a root directory entry carries no content
            raise EngineError(
                f"{spec.asset} contains the unsafe entry {name!r}; Barad refuses absolute "
                "paths, parent references and backslash or drive paths"
            )
        if relative in unpacked:
            raise EngineError(f"{spec.asset} contains the duplicate entry {relative!r}")
        return relative

    def _staging_file(self, target, spec):
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, staging_name = tempfile.mkstemp(
            prefix=f".{spec.name}-", suffix=".part", dir=str(target.parent)
        )
        os.close(handle)
        return Path(staging_name)

    def _record_path(self, spec):
        return self.install_dir(spec) / RECORD_FILENAME

    def _read_record(self, spec):
        try:
            record = json.loads(self._record_path(spec).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(record, dict):
            return None
        files = record.get("files")
        if not isinstance(files, dict) or not files:
            return None
        if record.get("asset_sha256") != spec.sha256:
            return None
        if record.get("entry") != spec.executable_name:
            return None
        return record

    def _write_record(self, spec, published):
        record = {
            "name": spec.name,
            "version": spec.version,
            "platform": spec.platform,
            "asset": spec.asset,
            "asset_sha256": spec.sha256,
            "archive": spec.archive,
            "entry": spec.executable_name,
            "files": dict(sorted(published.items())),
        }
        destination = self._record_path(spec)
        handle, staging_name = tempfile.mkstemp(
            prefix=f".{RECORD_FILENAME}-", suffix=".part", dir=str(destination.parent)
        )
        staging = Path(staging_name)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as output:
                json.dump(record, output, indent=2, sort_keys=True)
                output.write("\n")
            os.replace(staging, destination)
        finally:
            if staging.exists():
                staging.unlink()

    # -- transport ---------------------------------------------------------
    @property
    def fetcher(self):
        return self._fetch or self._download

    def _download(self, url, destination):
        """Fetch one pinned asset over https; redirects must stay on https."""
        if not url.startswith("https://"):
            raise EngineError(f"refusing to download an engine from a non-https URL: {url}")
        request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise EngineError(f"engine download returned HTTP {status}: {url}")
                final_url = str(getattr(response, "geturl", lambda: url)())
                if not final_url.startswith("https://"):
                    raise EngineError(
                        f"engine download left https via a redirect: {final_url}"
                    )
                with open(destination, "wb") as handle:
                    shutil.copyfileobj(response, handle, 256 * 1024)
        except EngineError:
            raise
        except (HTTPError, URLError, socket.timeout, OSError) as error:
            reason = getattr(error, "reason", error)
            raise EngineError(f"cannot download {url}: {reason}") from None

    def _log(self, event, spec, *, cached):
        if self.logger is None:
            return
        self.logger.info("engines", event, {
            "engine": spec.name,
            "version": spec.version,
            "platform": spec.platform,
            "sha256": spec.sha256,
            "cached": cached,
        })


def _write_member(destination, relative, source):
    target = destination / Path(*PurePosixPath(relative).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as handle:
        shutil.copyfileobj(source, handle, 256 * 1024)
    return target


def _require_digest(spec, path):
    observed = sha256_file(path)
    if observed != spec.sha256:
        raise EngineError(
            f"{spec.name} {spec.version} download failed sha256 verification: "
            f"expected {spec.sha256}, got {observed} ({spec.url})"
        )


try:  # POSIX advisory locks
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None

try:  # Windows advisory locks
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - POSIX
    _msvcrt = None


def _try_lock(handle):
    if _fcntl is not None:
        try:
            _fcntl.flock(handle, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    if _msvcrt is not None:  # pragma: no cover - exercised on Windows only
        try:
            _msvcrt.locking(handle, _msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    return True  # pragma: no cover - no advisory locking available


def _release_lock(handle):
    if _fcntl is not None:
        try:
            _fcntl.flock(handle, _fcntl.LOCK_UN)
        except OSError:
            pass
    elif _msvcrt is not None:  # pragma: no cover - exercised on Windows only
        try:
            _msvcrt.locking(handle, _msvcrt.LK_UNLCK, 1)
        except OSError:
            pass


def _acquire_lock(handle, path, timeout, poll, label):
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if _try_lock(handle):
            return
        if time.monotonic() >= deadline:
            raise EngineError(
                f"timed out after {timeout:g}s waiting for the {label} install lock: {path}; "
                "another Barad process may be installing the pinned engine"
            )
        time.sleep(max(0.01, poll))
