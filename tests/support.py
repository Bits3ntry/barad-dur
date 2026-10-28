"""Shared test helpers: temporary Git repositories, mock HTTP servers, Trivy shims."""
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Barad Test",
    "GIT_AUTHOR_EMAIL": "barad@example.test",
    "GIT_COMMITTER_NAME": "Barad Test",
    "GIT_COMMITTER_EMAIL": "barad@example.test",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


def git(cwd, *args, check=True):
    env = dict(os.environ)
    env.update(GIT_ENV)
    result = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


def init_repo(path, *, branch="main"):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", branch)
    git(path, "config", "user.name", "Barad Test")
    git(path, "config", "user.email", "barad@example.test")
    git(path, "config", "commit.gpgsign", "false")
    return path


def commit_all(repo, message):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def write_file(repo, relative, content):
    target = Path(repo) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def run_cli(args, *, cwd=None, env=None, timeout=120):
    """Run the runner through its public entry point, never through internals."""
    full_env = dict(os.environ)
    # The package must be importable from any working directory, exactly like bin/barad-security.
    full_env["PYTHONPATH"] = str(REPO_ROOT) + (
        os.pathsep + full_env["PYTHONPATH"] if full_env.get("PYTHONPATH") else "")
    full_env.pop("DTRACK_API_KEY", None)
    full_env.pop("DOJO_TOKEN", None)
    full_env.pop("BARAD_DUR_TOKEN", None)
    full_env.update(env or {})
    return subprocess.run(
        [PYTHON, "-m", "barad_security", *args],
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        env=full_env,
        timeout=timeout,
    )


TRIVY_JSON_TEMPLATE = {
    "SchemaVersion": 2,
    "Trivy": {"Version": "0.76.1"},
    "ReportID": "00000000-0000-0000-0000-000000000000",
    "CreatedAt": "2026-01-01T00:00:00Z",
    "ArtifactName": ".",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "Severity": "HIGH",
                    "Title": "Command Injection in lodash",
                },
                {
                    "VulnerabilityID": "CVE-2022-0235",
                    "PkgName": "node-fetch",
                    "InstalledVersion": "2.6.0",
                    "Severity": "LOW",
                    "Title": "Exposure of Sensitive Information",
                },
            ],
        },
        {
            "Target": ".env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                }
            ],
        },
    ],
}

TRIVY_SBOM_TEMPLATE = {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
    "version": 1,
    "metadata": {
        "timestamp": "2026-01-01T00:00:00Z",
        "tools": {
            "components": [
                {"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.76.1"}
            ]
        },
        "component": {"bom-ref": "root", "type": "application", "name": "probe"},
    },
    "components": [
        {
            "bom-ref": "pkg:npm/lodash@4.17.20",
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
        },
        {
            "bom-ref": "pkg:npm/node-fetch@2.6.0",
            "type": "library",
            "name": "node-fetch",
            "version": "2.6.0",
            "purl": "pkg:npm/node-fetch@2.6.0",
        },
    ],
    "dependencies": [
        {"ref": "root", "dependsOn": ["pkg:npm/lodash@4.17.20", "pkg:npm/node-fetch@2.6.0"]},
        {"ref": "pkg:npm/lodash@4.17.20", "dependsOn": []},
        {"ref": "pkg:npm/node-fetch@2.6.0", "dependsOn": []},
    ],
    "vulnerabilities": [],
}

FAKE_TRIVY_SOURCE = '''#!/usr/bin/env python3
"""Deterministic stand-in for the Trivy CLI used by unit and integration tests."""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
args = sys.argv[1:]
if "--version" in args:
    print("Version: 0.76.1")
    print("Vulnerability DB: 2")
    sys.exit(0)
mode = os.environ.get("FAKE_TRIVY_MODE", "success")
output = None
if "--output" in args:
    output = args[args.index("--output") + 1]
fmt = args[args.index("--format") + 1] if "--format" in args else "json"
log = os.environ.get("FAKE_TRIVY_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"argv": args, "cwd": os.getcwd()}) + "\\n")
if mode == "fail":
    print("FATAL\\tFatal error\\trun error: unable to initialize the vulnerability database", file=sys.stderr)
    sys.exit(1)
if mode == "hang":
    import time
    time.sleep(60)
if mode == "empty-json":
    payload = {"SchemaVersion": 2, "Trivy": {"Version": "0.76.1"}, "Results": []}
elif fmt == "cyclonedx":
    payload = json.loads((HERE / "trivy-sbom.json").read_text(encoding="utf-8"))
else:
    payload = json.loads((HERE / "trivy-report.json").read_text(encoding="utf-8"))
if output:
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(payload), encoding="utf-8")
else:
    print(json.dumps(payload))
'''


def install_fake_trivy(directory):
    """Create an executable Trivy shim plus its canned reports; return its path."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "trivy-report.json").write_text(json.dumps(TRIVY_JSON_TEMPLATE), encoding="utf-8")
    (directory / "trivy-sbom.json").write_text(json.dumps(TRIVY_SBOM_TEMPLATE), encoding="utf-8")
    script = directory / "trivy"
    script.write_text(FAKE_TRIVY_SOURCE, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return script


class RecordedRequest:
    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<RecordedRequest {self.method} {self.path}>"


class MockServer:
    """Tiny HTTP server: records requests and replays scripted responses."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests = []
        self._server = None
        self._thread = None
        self._queues = {}

    def enqueue(self, key, *responses):
        self._queues.setdefault(key, []).extend(responses)

    @property
    def url(self):
        host, port = self._server.server_address[:2]
        return f"http://127.0.0.1:{port}"

    def start(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence test output
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                recorded = RecordedRequest(self.command, self.path, dict(self.headers.items()), body)
                server.requests.append(recorded)
                key = f"{self.command} {self.path.split('?')[0]}"
                queue = server._queues.get(key)
                if queue:
                    status, payload, headers = queue.pop(0)
                else:
                    route = server.routes.get(key) or server.routes.get("*")
                    if callable(route):
                        status, payload, headers = route(recorded)
                    elif route is not None:
                        status, payload, headers = route
                    else:
                        status, payload, headers = 404, {"error": "not found"}, {}
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
                self.send_response(status)
                payload_headers = {"Content-Type": "application/json"}
                payload_headers.update(headers or {})
                for header, value in payload_headers.items():
                    self.send_header(header, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_PATCH = _handle
            do_DELETE = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join(timeout=5)
            self._server = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc_info):
        self.stop()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def docker_available(image="aquasec/trivy:0.76.1"):
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, text=True
    )
    return result.returncode == 0
