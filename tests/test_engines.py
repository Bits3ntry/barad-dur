"""Contract tests for the packaged engine lockfile and its verified user cache.

Installing the Barad CLI is the only installation step: the pinned OpenGrep
release is resolved from a lockfile shipped inside the wheel, downloaded on
demand, and verified against its SHA-256 on every use.  Every test here injects
the download transport and builds its archives in memory, so nothing touches the
network and no external binary is installed.
"""
import dataclasses
import hashlib
import io
import json
import os
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from cli_support import REPO_ROOT

from barad.core.engines import (
    RECORD_FILENAME,
    EngineError,
    EngineManager,
    default_cache_root,
    load_lock,
    packaged_lock_path,
    platform_key,
    safe_member_path,
)

PAYLOAD = b"#!/bin/sh\nexit 0\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
BASE_URL = "https://github.com/opengrep/opengrep/releases/download"
ASSET = "opengrep_manylinux_x86"

MAC_PLATFORM = "macos-aarch64"
MAC_ASSET = "opengrep-core_osx_aarch64.tar.gz"
MAC_ENTRY = "opengrep-core"
MAC_MEMBERS = {MAC_ENTRY: PAYLOAD, "LICENSE": b"license text\n"}

WIN_PLATFORM = "windows-x86"
WIN_ASSET = "opengrep-core_windows_x86.zip"
WIN_ENTRY = "opengrep-core.exe"
WIN_MEMBERS = {
    WIN_ENTRY: b"MZ pinned executable\n",
    "libtre.dll": b"dll bytes\n",
    "libpcre2-8.dll": b"second dll\n",
}


def tar_gz(members, *, symlinks=(), directories=()):
    """Build a deterministic .tar.gz in memory."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(content))
        for name, target in symlinks:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    return buffer.getvalue()


def zip_bytes(members, *, symlinks=()):
    """Build a deterministic .zip in memory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
        for name, target in symlinks:
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, target)
    return buffer.getvalue()


MAC_TARBALL = tar_gz(MAC_MEMBERS)
MAC_DIGEST = hashlib.sha256(MAC_TARBALL).hexdigest()
WIN_ARCHIVE = zip_bytes(WIN_MEMBERS)
WIN_DIGEST = hashlib.sha256(WIN_ARCHIVE).hexdigest()


def lock_document(**overrides):
    engine = {
        "version": "1.33.1",
        "release_tag": "v1.33.1",
        "base_url": BASE_URL,
        "binaries": {"linux-x86_64": {"asset": ASSET, "sha256": DIGEST}},
    }
    engine.update({key: value for key, value in overrides.items() if key in engine})
    document = {"schema_version": 1, "engines": {"opengrep": engine}}
    document.update({key: value for key, value in overrides.items() if key in document})
    return document


def write_lock(directory, document):
    path = Path(directory) / "engines.lock.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def archive_lock(directory, *, platform, asset, digest, archive, entry):
    binary = {"asset": asset, "sha256": digest, "archive": archive, "entry": entry}
    return write_lock(directory, lock_document(binaries={platform: binary}))


class Recorder:
    """Deterministic transport: records the URL and writes fixed bytes."""

    def __init__(self, payload=PAYLOAD):
        self.payload = payload
        self.calls = []

    def __call__(self, url, destination):
        self.calls.append(url)
        Path(destination).write_bytes(self.payload)


class LockfileTests(unittest.TestCase):
    def test_packaged_lock_pins_the_exact_official_release_assets(self):
        lock = load_lock()
        engine = lock["engines"]["opengrep"]

        self.assertEqual(engine["version"], "1.33.1")
        self.assertEqual(engine["release_tag"], "v1.33.1")
        self.assertEqual(engine["base_url"], BASE_URL)
        self.assertEqual(
            sorted(engine["binaries"]),
            ["linux-aarch64", "linux-x86_64", "macos-aarch64", "windows-x86"],
        )
        self.assertEqual(
            engine["binaries"]["linux-x86_64"],
            {"asset": "opengrep_manylinux_x86",
             "sha256": "46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808"},
        )
        self.assertEqual(
            engine["binaries"]["linux-aarch64"],
            {"asset": "opengrep_manylinux_aarch64",
             "sha256": "d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf"},
        )
        self.assertEqual(
            engine["binaries"]["macos-aarch64"],
            {"asset": "opengrep_osx_arm64",
             "sha256": "a17c1881bb40e3214266a7a291cf4f2ae3bc56c1715628b5712d2ec816bc3e2d"},
        )
        self.assertEqual(
            engine["binaries"]["windows-x86"],
            {"asset": "opengrep_windows_x86.exe",
             "sha256": "132e606e071bdd3928286fddc893198a6106a90820d46e21197e0ace1a23e0c1"},
        )

    def test_packaged_lock_never_references_a_mutable_or_community_source(self):
        text = packaged_lock_path().read_text(encoding="utf-8").lower()

        self.assertNotIn("latest", text)
        self.assertNotIn("ghcr.io", text)
        self.assertNotIn("aquasec", text)
        self.assertNotIn("install-opengrep", text)

    def test_packaged_lock_ships_with_the_installed_cli(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("resources/*.json", pyproject)
        self.assertTrue(packaged_lock_path().is_file())
        self.assertEqual(packaged_lock_path().parent.name, "resources")

    def test_lock_rejects_unpinned_versions_and_malformed_digests(self):
        cases = [
            lock_document(version="latest", release_tag="vlatest"),
            lock_document(release_tag="main"),
            lock_document(base_url="https://github.com/opengrep/opengrep/releases/latest"),
            lock_document(binaries={"linux-x86_64": {"asset": "../opengrep", "sha256": DIGEST}}),
            lock_document(binaries={"linux-x86_64": {"asset": ASSET, "sha256": "deadbeef"}}),
            lock_document(binaries={}),
            {"schema_version": 2, "engines": {}},
            {"engines": {}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            for document in cases:
                with self.subTest(document=document):
                    with self.assertRaises(EngineError):
                        load_lock(write_lock(directory, document))

    def test_lock_rejects_unsafe_archive_entries_and_unknown_containers(self):
        cases = [
            {"asset": MAC_ASSET, "sha256": DIGEST, "archive": "tar", "entry": MAC_ENTRY},
            {"asset": MAC_ASSET, "sha256": DIGEST, "archive": "tar.gz"},
            {"asset": MAC_ASSET, "sha256": DIGEST, "archive": "tar.gz", "entry": "../opengrep"},
            {"asset": MAC_ASSET, "sha256": DIGEST, "archive": "tar.gz", "entry": "/bin/sh"},
            {"asset": MAC_ASSET, "sha256": DIGEST, "archive": "tar.gz", "entry": "bin\\evil.exe"},
            {"asset": MAC_ASSET, "sha256": DIGEST, "entry": MAC_ENTRY},
            {"asset": WIN_ARCHIVE.decode("latin-1"), "sha256": DIGEST, "archive": "zip",
             "entry": WIN_ENTRY},
        ]
        with tempfile.TemporaryDirectory() as directory:
            for binary in cases:
                with self.subTest(binary=binary):
                    with self.assertRaises(EngineError):
                        load_lock(write_lock(
                            directory, lock_document(binaries={"macos-aarch64": binary})))

    def test_safe_member_paths_reject_escapes_and_accept_pinned_names(self):
        for name in ("opengrep-core", "opengrep-core.exe", "bin/opengrep", "./opengrep-core",
                     "lib/libpcre2-8.dll"):
            with self.subTest(name=name):
                self.assertIsNotNone(safe_member_path(name))
        for name in ("", ".", "..", "../opengrep", "bin/../../etc/passwd", "/etc/passwd",
                     "\\windows\\system32", "C:opengrep.exe", None, 7):
            with self.subTest(name=name):
                self.assertIsNone(safe_member_path(name))


class PlatformResolutionTests(unittest.TestCase):
    def test_every_locked_platform_resolves_from_a_host_identity(self):
        cases = {
            ("Linux", "x86_64"): "linux-x86_64",
            ("linux", "amd64"): "linux-x86_64",
            ("Linux", "aarch64"): "linux-aarch64",
            ("LINUX", "arm64"): "linux-aarch64",
            ("Darwin", "arm64"): "macos-aarch64",
            ("darwin", "aarch64"): "macos-aarch64",
            ("Windows", "x86"): "windows-x86",
            ("Windows", "i386"): "windows-x86",
            ("Windows", "i686"): "windows-x86",
        }
        for (system, machine), expected in cases.items():
            with self.subTest(system=system, machine=machine):
                self.assertEqual(platform_key(system, machine), expected)

    def test_hosts_without_published_assets_stay_unsupported(self):
        for system, machine in (("Darwin", "x86_64"), ("Windows", "AMD64"),
                                ("Linux", "riscv64"), ("FreeBSD", "amd64"), ("", "")):
            with self.subTest(system=system, machine=machine):
                self.assertIsNone(platform_key(system, machine))

    def test_locked_platform_keys_match_the_platform_resolver_output(self):
        locked = sorted(load_lock()["engines"]["opengrep"]["binaries"])
        resolved = sorted({
            platform_key("Linux", "x86_64"), platform_key("Linux", "aarch64"),
            platform_key("Darwin", "arm64"), platform_key("Windows", "x86"),
        })

        self.assertEqual(locked, resolved)

    def test_unsupported_host_fails_closed_and_downloads_nothing(self):
        binaries = {
            "linux-x86_64": {"asset": ASSET, "sha256": DIGEST},
            "linux-aarch64": {"asset": "opengrep_manylinux_aarch64", "sha256": DIGEST},
        }
        with tempfile.TemporaryDirectory() as directory:
            fetcher = Recorder()
            manager = EngineManager(cache_dir=Path(directory) / "cache",
                                    lock_path=write_lock(
                                        directory, lock_document(binaries=binaries)),
                                    fetcher=fetcher, platform="freebsd-amd64")

            with self.assertRaises(EngineError) as caught:
                manager.resolve("opengrep")

        message = caught.exception.message
        self.assertIn("linux-aarch64", message)
        self.assertIn("linux-x86_64", message)
        self.assertIn("this host reports", message)
        self.assertIn("does not download an unverified binary", message)
        self.assertEqual(fetcher.calls, [])


class EngineCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        self.cache_dir = self.directory / "user-cache"
        self.lock_path = write_lock(self.directory, lock_document())

    def manager(self, fetcher, **kwargs):
        kwargs.setdefault("platform", "linux-x86_64")
        return EngineManager(cache_dir=self.cache_dir, lock_path=self.lock_path,
                             fetcher=fetcher, **kwargs)

    def target(self):
        return self.cache_dir / "opengrep-1.33.1" / "linux-x86_64" / "opengrep"

    def test_cache_hit_verifies_the_cached_binary_without_downloading(self):
        self.target().parent.mkdir(parents=True)
        self.target().write_bytes(PAYLOAD)
        fetcher = Recorder()
        manager = self.manager(fetcher)

        resolved = manager.resolve("opengrep")

        self.assertEqual(fetcher.calls, [])
        self.assertEqual(resolved, self.target().resolve())
        self.assertTrue(resolved.is_absolute())
        self.assertEqual(resolved, Path(self.cache_dir).resolve() / "opengrep-1.33.1"
                         / "linux-x86_64" / "opengrep")

    def test_missing_binary_is_downloaded_into_place_with_an_atomic_rename(self):
        fetcher = Recorder()
        manager = self.manager(fetcher)

        resolved = manager.resolve("opengrep")

        self.assertEqual(fetcher.calls, [f"{BASE_URL}/v1.33.1/{ASSET}"])
        self.assertEqual(resolved.read_bytes(), PAYLOAD)
        self.assertEqual(resolved.stat().st_mode & 0o777, 0o755)
        leftovers = [path.name for path in resolved.parent.iterdir()
                     if path.name != "opengrep"]
        self.assertEqual(leftovers, [])

    def test_staging_file_never_becomes_the_engine_path_before_verification(self):
        observations = {}
        target = self.target()

        def fetcher(url, destination):
            observations["destination"] = Path(destination)
            observations["target_exists_during_download"] = target.exists()
            observations["staged_in_designated_directory"] = Path(destination).parent == target.parent
            Path(destination).write_bytes(PAYLOAD)

        resolved = self.manager(fetcher).resolve("opengrep")

        self.assertNotEqual(observations["destination"], target)
        self.assertFalse(observations["target_exists_during_download"])
        self.assertTrue(observations["staged_in_designated_directory"])
        self.assertEqual(resolved.read_bytes(), PAYLOAD)

    def test_hash_mismatch_redownloads_and_replaces_the_untrusted_bytes(self):
        self.target().parent.mkdir(parents=True)
        self.target().write_bytes(b"tampered binary\n")
        fetcher = Recorder()
        manager = self.manager(fetcher)

        resolved = manager.resolve("opengrep")

        self.assertEqual(fetcher.calls, [f"{BASE_URL}/v1.33.1/{ASSET}"])
        self.assertEqual(resolved.read_bytes(), PAYLOAD)

    def test_verification_runs_on_every_use_not_only_on_install(self):
        fetcher = Recorder()
        manager = self.manager(fetcher)

        first = manager.resolve("opengrep")
        first.write_bytes(b"tampered after install\n")
        second = manager.resolve("opengrep")

        self.assertEqual(len(fetcher.calls), 2)
        self.assertEqual(second.read_bytes(), PAYLOAD)

    def test_a_download_that_fails_verification_leaves_no_runnable_binary(self):
        fetcher = Recorder(b"wrong bytes\n")
        manager = self.manager(fetcher)

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn(DIGEST, caught.exception.message)
        self.assertFalse(self.target().exists())
        self.assertEqual(list(self.target().parent.iterdir()), [])

    def test_unsupported_platform_never_reaches_the_transport(self):
        fetcher = Recorder()
        manager = EngineManager(cache_dir=self.cache_dir, lock_path=self.lock_path,
                                fetcher=fetcher, platform="linux-riscv64")

        with self.assertRaises(EngineError):
            manager.resolve("opengrep")

        self.assertEqual(fetcher.calls, [])
        self.assertFalse(self.cache_dir.exists())


class ArchiveInstallTests(unittest.TestCase):
    """Archived releases: verified before extraction, staged, published atomically."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        self.cache_dir = self.directory / "user-cache"

    def manager(self, fetcher, *, platform=MAC_PLATFORM, asset=MAC_ASSET,
                digest=MAC_DIGEST, archive="tar.gz", entry=MAC_ENTRY, **kwargs):
        lock_path = archive_lock(self.directory, platform=platform, asset=asset,
                                 digest=digest, archive=archive, entry=entry)
        return EngineManager(cache_dir=self.cache_dir, lock_path=lock_path,
                             fetcher=fetcher, platform=platform, **kwargs)

    def install_dir(self, platform=MAC_PLATFORM):
        return self.cache_dir / "opengrep-1.33.1" / platform

    def test_macos_tarball_installs_the_pinned_executable_with_its_siblings(self):
        fetcher = Recorder(MAC_TARBALL)
        manager = self.manager(fetcher)

        resolved = manager.resolve("opengrep")

        self.assertEqual(fetcher.calls, [f"{BASE_URL}/v1.33.1/{MAC_ASSET}"])
        self.assertEqual(resolved, (self.install_dir() / MAC_ENTRY).resolve())
        self.assertTrue(resolved.is_absolute())
        self.assertEqual(resolved.read_bytes(), PAYLOAD)
        self.assertEqual(resolved.stat().st_mode & 0o777, 0o755)
        self.assertTrue((self.install_dir() / "LICENSE").is_file())
        self.assertTrue((self.install_dir() / RECORD_FILENAME).is_file())
        leftovers = sorted(path.name for path in self.install_dir().parent.iterdir())
        self.assertEqual(leftovers, [".macos-aarch64.lock", "macos-aarch64"])

    def test_windows_zip_preserves_sibling_dlls_and_publishes_the_executable_last(self):
        published = []

        def record_replace(original):
            def wrapper(source, destination):
                published.append(Path(destination).name)
                return original(source, destination)
            return wrapper

        fetcher = Recorder(WIN_ARCHIVE)
        manager = self.manager(fetcher, platform=WIN_PLATFORM, asset=WIN_ASSET,
                               digest=WIN_DIGEST, archive="zip", entry=WIN_ENTRY)

        with mock.patch("barad.core.engines.os.replace",
                        side_effect=record_replace(os.replace)):
            resolved = manager.resolve("opengrep")

        self.assertEqual(resolved.name, WIN_ENTRY)
        self.assertEqual(resolved, (self.install_dir(WIN_PLATFORM) / WIN_ENTRY).resolve())
        for sibling in WIN_MEMBERS:
            self.assertTrue((self.install_dir(WIN_PLATFORM) / sibling).is_file(), sibling)
        files_published = [name for name in published if name in WIN_MEMBERS]
        self.assertEqual(sorted(files_published), sorted(WIN_MEMBERS))
        self.assertEqual(files_published[-1], WIN_ENTRY)

    def test_archive_with_a_bad_checksum_is_never_extracted(self):
        fetcher = Recorder(b"not the pinned archive\n")
        manager = self.manager(fetcher)

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn(MAC_DIGEST, caught.exception.message)
        self.assertFalse((self.install_dir() / MAC_ENTRY).exists())
        self.assertFalse((self.install_dir() / RECORD_FILENAME).exists())
        leftovers = sorted(path.name for path in self.install_dir().parent.iterdir())
        self.assertEqual(leftovers, [".macos-aarch64.lock"])

    def test_archive_entry_that_traverses_is_rejected(self):
        tarball = tar_gz({MAC_ENTRY: PAYLOAD, "../escape.sh": b"echo pwned\n"},
                         directories=())
        manager = self.manager(Recorder(tarball),
                               digest=hashlib.sha256(tarball).hexdigest())

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn("unsafe entry", caught.exception.message)
        self.assertEqual(list(self.cache_dir.rglob("escape.sh")), [])
        self.assertFalse((self.directory / "escape.sh").exists())
        self.assertFalse((self.install_dir() / MAC_ENTRY).exists())

    def test_absolute_archive_entry_is_rejected(self):
        tarball = tar_gz({MAC_ENTRY: PAYLOAD, "/etc/escape": b"echo pwned\n"})
        manager = self.manager(Recorder(tarball),
                               digest=hashlib.sha256(tarball).hexdigest())

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn("unsafe entry", caught.exception.message)
        self.assertFalse((self.install_dir() / MAC_ENTRY).exists())

    def test_tar_symlink_member_is_rejected(self):
        tarball = tar_gz({MAC_ENTRY: PAYLOAD}, symlinks=(("passwd", "/etc/passwd"),))
        manager = self.manager(Recorder(tarball),
                               digest=hashlib.sha256(tarball).hexdigest())

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn("link or special file", caught.exception.message)
        self.assertFalse(any(path.is_symlink() for path in self.cache_dir.rglob("*")))
        self.assertFalse((self.install_dir() / MAC_ENTRY).exists())

    def test_zip_symlink_entry_is_rejected(self):
        archive = zip_bytes({WIN_ENTRY: b"MZ pinned executable\n"},
                            symlinks=(("link.dll", "C:\\Windows\\System32\\evil.dll"),))
        manager = self.manager(Recorder(archive), platform=WIN_PLATFORM,
                               asset=WIN_ASSET, digest=hashlib.sha256(archive).hexdigest(),
                               archive="zip", entry=WIN_ENTRY)

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn("symlink", caught.exception.message)
        self.assertFalse((self.install_dir(WIN_PLATFORM) / WIN_ENTRY).exists())

    def test_duplicate_archive_entry_is_rejected(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for _ in range(2):
                info = tarfile.TarInfo(MAC_ENTRY)
                info.size = len(PAYLOAD)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(PAYLOAD))
        tarball = buffer.getvalue()
        manager = self.manager(Recorder(tarball),
                               digest=hashlib.sha256(tarball).hexdigest())

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn("duplicate entry", caught.exception.message)

    def test_archive_without_the_pinned_entry_is_rejected(self):
        tarball = tar_gz({"LICENSE": b"license text\n"})
        manager = self.manager(Recorder(tarball),
                               digest=hashlib.sha256(tarball).hexdigest())

        with self.assertRaises(EngineError) as caught:
            manager.resolve("opengrep")

        self.assertIn(MAC_ENTRY, caught.exception.message)
        self.assertFalse((self.install_dir() / MAC_ENTRY).exists())

    def test_archive_root_directory_entry_is_tolerated(self):
        tarball = tar_gz(MAC_MEMBERS, directories=("./",))
        manager = self.manager(Recorder(tarball),
                               digest=hashlib.sha256(tarball).hexdigest())

        resolved = manager.resolve("opengrep")

        self.assertEqual(resolved, (self.install_dir() / MAC_ENTRY).resolve())
        self.assertTrue(resolved.is_file())

    def test_archive_cache_hit_skips_the_download_and_reinstalls_after_tampering(self):
        fetcher = Recorder(MAC_TARBALL)
        manager = self.manager(fetcher)

        first = manager.resolve("opengrep")
        second = manager.resolve("opengrep")
        self.assertEqual(fetcher.calls, [f"{BASE_URL}/v1.33.1/{MAC_ASSET}"])
        self.assertEqual(first, second)

        (self.install_dir() / "LICENSE").write_bytes(b"tampered sibling\n")
        third = manager.resolve("opengrep")

        self.assertEqual(len(fetcher.calls), 2)
        self.assertEqual(third, first)
        self.assertEqual((self.install_dir() / "LICENSE").read_bytes(),
                         MAC_MEMBERS["LICENSE"])

    def test_a_record_from_another_lock_revision_is_not_trusted(self):
        fetcher = Recorder(MAC_TARBALL)
        manager = self.manager(fetcher)
        manager.resolve("opengrep")
        record_path = self.install_dir() / RECORD_FILENAME
        record = json.loads(record_path.read_text(encoding="utf-8"))

        record["asset_sha256"] = "0" * 64
        record_path.write_text(json.dumps(record), encoding="utf-8")
        manager.resolve("opengrep")

        self.assertEqual(len(fetcher.calls), 2)
        restored = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(restored["asset_sha256"], MAC_DIGEST)


class CacheLockTests(unittest.TestCase):
    """One install lock per engine and platform, re-checked after acquisition."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        self.cache_dir = self.directory / "user-cache"
        self.lock_path = write_lock(self.directory, lock_document())

    def manager(self, fetcher, **kwargs):
        kwargs.setdefault("platform", "linux-x86_64")
        return EngineManager(cache_dir=self.cache_dir, lock_path=self.lock_path,
                             fetcher=fetcher, **kwargs)

    def target(self):
        return self.cache_dir / "opengrep-1.33.1" / "linux-x86_64" / "opengrep"

    def test_concurrent_installs_serialize_and_download_once(self):
        fetcher = Recorder()
        manager = self.manager(fetcher)
        spec = manager.engine("opengrep")
        finished = threading.Event()
        results = {}

        def worker():
            results["path"] = manager.resolve("opengrep")
            finished.set()

        thread = threading.Thread(target=worker, daemon=True)
        with manager.cache_lock(spec):
            thread.start()
            self.assertFalse(finished.wait(0.3))  # blocked while the lock is held
            self.assertEqual(fetcher.calls, [])
        thread.join(10)

        self.assertTrue(finished.is_set())
        self.assertEqual(len(fetcher.calls), 1)
        self.assertTrue(results["path"].is_file())
        self.assertEqual(results["path"].read_bytes(), PAYLOAD)

    def test_lock_wait_times_out_with_an_actionable_error(self):
        holder = self.manager(Recorder())
        spec = holder.engine("opengrep")
        waiter = self.manager(Recorder(), lock_timeout=0.2, lock_poll=0.02)
        failures = []

        def worker():
            try:
                waiter.resolve("opengrep")
            except EngineError as error:
                failures.append(error)

        with holder.cache_lock(spec):
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            thread.join(10)

        self.assertEqual(len(failures), 1)
        self.assertIn("install lock", failures[0].message)
        self.assertIn("timed out", failures[0].message)
        self.assertEqual(waiter.fetcher.calls, [])
        self.assertFalse(self.target().exists())

    def test_lock_is_released_after_a_successful_install(self):
        fetcher = Recorder()
        manager = self.manager(fetcher)
        manager.resolve("opengrep")
        spec = manager.engine("opengrep")

        self.assertTrue(manager.lock_file(spec).is_file())
        with manager.cache_lock(spec):  # re-acquiring must not deadlock
            self.assertTrue(manager.verify(spec))

    def test_lock_file_is_shared_per_engine_and_platform(self):
        first = self.manager(Recorder())
        second = self.manager(Recorder())
        spec = first.engine("opengrep")
        other = dataclasses.replace(spec, platform="linux-aarch64")

        self.assertEqual(first.lock_file(spec), second.lock_file(spec))
        self.assertNotEqual(first.lock_file(spec), first.lock_file(other))

    def test_integrity_is_rechecked_after_the_lock_is_acquired(self):
        self.target().parent.mkdir(parents=True)
        self.target().write_bytes(PAYLOAD)
        fetcher = Recorder()
        manager = self.manager(fetcher)
        calls = {"n": 0}
        real_verify = manager.verify

        def stale_first_check(spec, path=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return False  # the cache looked stale before the lock
            return real_verify(spec, path)

        manager.verify = stale_first_check
        resolved = manager.resolve("opengrep")

        self.assertEqual(calls["n"], 2)
        self.assertEqual(fetcher.calls, [])
        self.assertEqual(resolved.read_bytes(), PAYLOAD)


class CacheLocationTests(unittest.TestCase):
    def test_cache_root_is_persistent_and_user_scoped(self):
        home = Path("/home/tester")

        self.assertEqual(default_cache_root({}, home=home, system="Linux"),
                         home / ".cache" / "barad" / "engines")
        self.assertEqual(
            default_cache_root({"XDG_CACHE_HOME": "/var/cache/tester"}, home=home,
                               system="Linux"),
            Path("/var/cache/tester") / "barad" / "engines",
        )
        self.assertEqual(default_cache_root({}, home=home, system="Darwin"),
                         home / "Library" / "Caches" / "barad" / "engines")

    def test_explicit_cache_override_wins(self):
        self.assertEqual(
            default_cache_root({"BARAD_ENGINE_CACHE": "/opt/barad-engines"},
                               home=Path("/home/tester"), system="Linux"),
            Path("/opt/barad-engines"),
        )

    def test_cache_is_never_inside_the_scanned_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            repository.mkdir()
            manager = EngineManager(environ={"XDG_CACHE_HOME": str(Path(directory) / "cache")},
                                    home=Path(directory), system="Linux")

        self.assertNotIn(repository, manager.cache_dir.parents)
        self.assertEqual(manager.cache_dir,
                         Path(directory) / "cache" / "barad" / "engines")


if __name__ == "__main__":
    unittest.main()
