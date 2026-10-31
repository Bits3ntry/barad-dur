"""Ephemeral container execution for Shauron scans.

The management plane never runs scanner code itself; a worker that is asked to
run a job may additionally run that scan inside a throwaway container. The
flags below are not configurable defaults to be "tuned later" — they encode the
isolation contract, and `build_command` refuses anything that would quietly
break it (privileged, host networking, a mounted Docker socket, a writable root
filesystem).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

DOCKER = "docker"
# Image names must be pinned by digest to keep execution reproducible.
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")

SANDBOX_FLAGS = [
    "--rm",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "65534:65534",
    "--memory", "1g",
    "--memory-swap", "1g",
    "--cpus", "1",
    "--pids-limit", "256",
]

FORBIDDEN_MOUNTS = ("/var/run/docker.sock", "/run/docker.sock", "/usr/bin/docker")


class SandboxError(RuntimeError):
    pass


def docker_available() -> bool:
    return shutil.which(DOCKER) is not None


def build_command(image: str, argv: list[str], workdir: str,
                  target_path: Path, output_dir: Path) -> list[str]:
    """Compose the docker invocation for one scan; fail closed on bad input."""
    if not DIGEST.search(image):
        raise SandboxError(
            "sandbox images must be digest-pinned (name@sha256:...); "
            f"refusing to run {image!r}")
    if not argv:
        raise SandboxError("sandbox needs a command to run")
    for item in argv:
        lowered = str(item).lower()
        if "docker.sock" in lowered or "docker" in lowered.split("/")[0]:
            raise SandboxError("refusing to expose docker inside the sandbox")
    target = target_path.resolve()
    output = output_dir.resolve()
    if not target.exists():
        raise SandboxError(f"target path does not exist: {target}")
    output.mkdir(parents=True, exist_ok=True)
    for path in (target, output):
        if any(str(path).startswith(prefix) for prefix in FORBIDDEN_MOUNTS):
            raise SandboxError(f"refusing to mount {path}")
    command = [DOCKER, "run", *SANDBOX_FLAGS,
               "--workdir", workdir,
               "-v", f"{target}:/target:ro",
               "-v", f"{output}:/out:rw",
               image, *[str(item) for item in argv]]
    return command


def run(command: list[str], timeout: int = 900) -> tuple[int, str, str]:
    if not docker_available():
        raise SandboxError("docker is not available on this worker")
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"sandbox timed out after {timeout}s") from exc
    return completed.returncode, completed.stdout, completed.stderr
