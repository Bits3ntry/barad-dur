"""The pipeline builder: the file a repository needs, from a selection.

A pipeline **announces**; it never scans. The console offers a closed catalog
(`scan_actions`), the platform mints a signed ticket, and the daemon executes it.
So the artefact a repository needs is small: post the commit to `/api/v1/scans`
with the organization key, then hold the build on the flow's own verdict
(`/scans/{id}/gate`, read with the ticket token that the announce returned).

Two rules shape every file generated here:

* **What CI may ask for is what `push_allowed` allows.** Attack surface and
  verified secrets mean the platform acts alone, so they need a grant and the
  console; a workflow asking for them would be refused with a 422 at runtime.
  This module refuses to generate one and the blueprint says why.
* **The runner holds no credentials beyond the organization key.** Evidence and
  events travel to the platform from the daemon using the ticket's own token, so
  the job never needs a scanner, a database, or a second secret.

The generated script is the same on every provider; only the workflow file and
the variables that name the commit differ, and that difference lives here.
"""
from __future__ import annotations

# The one script every provider runs. Tokens (`__ACTION_LIST__`, …) are replaced
# literally instead of str.format: the body is full of braces that YAML, bash and
# JSON all want kept as they are.
SCRIPT = '''\
"""Announce this commit to Barad-dûr and let the flow's verdict gate the build.

The scan itself runs on the platform's daemon: this job only asks for it and
waits. Evidence and events are delivered by the daemon with the ticket token, so
no scanner runs here and no second credential exists in this job.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["BARAD_URL"].rstrip("/")
KEY = os.environ["BARAD_API_KEY"]
ACTIONS = __ACTION_LIST__
ATTEMPTS = __ATTEMPTS__
PAUSE_S = __PAUSE__

BODY = {
    "project": __PROJECT__,
    "component": __COMPONENT__,
    "commit": os.environ.get("GITHUB_SHA") or os.environ.get("CI_COMMIT_SHA", ""),
    "branch": (os.environ.get("GITHUB_HEAD_REF")
               or os.environ.get("CI_COMMIT_REF_NAME")
               or os.environ.get("GITHUB_REF_NAME") or ""),
    "pull_request": (os.environ.get("GITHUB_EVENT_PR") or os.environ.get("CI_MERGE_REQUEST_IID")
                     or None),
    "origin": "ci",
    "actor": (os.environ.get("GITHUB_ACTOR") or os.environ.get("GITLAB_USER_LOGIN")
              or os.environ.get("USER") or "ci"),
}


def call(path, method="GET", body=None, token=None):
    """One request to the platform. Raises with the platform's own message."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    request.add_header("X-API-Key", KEY)
    if token:
        request.add_header("X-Ticket-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise SystemExit(f"{path} answered {error.code}: {detail}") from None


def main():
    if not BODY["commit"]:
        raise SystemExit("this runner exported no commit sha; the platform needs the exact one")
    failed = []
    for action in ACTIONS:
        status, flow = call("/api/v1/scans", "POST", dict(BODY, action=action))
        ticket = flow.get("ticket") or {}
        if status != 201 or not ticket:
            # 202 means the repository maps to no single component: the run is
            # parked for attribution instead of scanning the wrong one.
            print(f"{action}: not scanned — {flow.get('data') or flow}")
            failed.append(action)
            continue
        job = ticket["ticket_id"]
        token = ticket["evidence"]["upload_token"]
        print(f"{action}: flow {job} — waiting on the gate")
        verdict, reason = "running", ""
        for _ in range(ATTEMPTS):
            time.sleep(PAUSE_S)
            _, state = call(f"/api/v1/scans/{job}/gate", token=token)
            verdict, reason = state["data"]["verdict"], state["data"].get("reason", "")
            if verdict != "running":
                break
        print(f"{action}: {verdict} — {reason}")
        if verdict != "pass":
            failed.append(action)
    if failed:
        raise SystemExit("blocked by: " + ", ".join(failed))


if __name__ == "__main__":
    main()
'''

PROVIDERS = {
    "github": {
        "label": "GitHub Actions",
        "path": ".github/workflows/barad-dur.yml",
        "key_store": "Settings → Secrets and variables → Actions",
    },
    "gitea": {
        "label": "Gitea Actions",
        "path": ".gitea/workflows/barad-dur.yml",
        "key_store": "Settings → Secrets → Actions",
    },
    "gitlab": {
        "label": "GitLab CI",
        "path": ".gitlab-ci.yml",
        "key_store": "Settings → CI/CD → Variables (masked)",
    },
    "generic": {
        "label": "Any other CI",
        "path": "barad-ci.py",
        "key_store": "your CI's own secret store",
    },
}

# A GitHub/Gitea workflow that publishes a check: the gate is the verdict, so the
# job waits long enough for a real scan and no longer.
WORKFLOW_MINUTES = 45
ATTEMPTS = 60
PAUSE_SECONDS = 20


def provider_for(provider: str | None, remote: str | None = None) -> str:
    """Which CI the repository already uses.

    The registered provider wins; the remote host is the fallback for a
    repository registered before providers were recorded. Anything unrecognised
    gets the portable script instead of a workflow file that would not run.
    """
    value = (provider or "").strip().lower()
    if value in PROVIDERS:
        return value
    if "gitlab" in value:
        return "gitlab"
    remote_value = (remote or "").lower()
    if "gitlab" in remote_value:
        return "gitlab"
    if "github" in remote_value:
        return "github"
    if "gitea" in remote_value or "forgejo" in remote_value:
        return "gitea"
    return "generic"


def render_script(project: str, component: str | None, actions: list[str]) -> str:
    return (SCRIPT
            .replace("__ACTION_LIST__", repr(actions))
            .replace("__ATTEMPTS__", str(ATTEMPTS))
            .replace("__PAUSE__", str(PAUSE_SECONDS))
            .replace("__PROJECT__", repr(project))
            .replace("__COMPONENT__", repr(component)))


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line.strip() else line for line in text.splitlines())


def _on_block(triggers: list[str], branch: str, flavour: str) -> str:
    """The `on:` block, per flavour. A trigger nobody asked for is noise, and a
    pull-request build is the one that blocks a merge."""
    if flavour == "gitlab":
        return ""
    lines = []
    if "push" in triggers:
        lines.append("  push:")
        lines.append(f"    branches: [{branch}]")
    if "pull_request" in triggers:
        lines.append("  pull_request:")
    if "manual" in triggers:
        lines.append("  workflow_dispatch:")
    return "on:\n" + "\n".join(lines) + "\n" if lines else "on: workflow_dispatch\n"


def _github(project: str, component: str | None, actions: list[str], triggers: list[str],
            branch: str, api_url: str | None) -> str:
    slug = f"{project}-{component}" if component else project
    # A URL the operator typed is written in; without one the file reads a
    # repository variable, so the workflow carries no address that looks real
    # and points nowhere.
    url_line = api_url or "${{ vars.BARAD_URL }}"
    url_hint = (
        f"# BARAD_URL is written below; move it to a repository variable if it "
        f"differs per fork.\n"
        if api_url else
        "# Set a repository variable BARAD_URL to this platform's API root, e.g.\n"
        "# https://barad.example.com:8090 — no trailing slash.\n"
    )
    return (
        f"# Generated by Barad-dûr for {project}"
        + (f" / {component}" if component else "")
        + """.

# A pipeline announces; the scan runs on the platform's daemon. This job needs
# one secret, BARAD_API_KEY (the console's "api key").
"""
        + url_hint
        + """# The build fails when the flow's own verdict is fail: HIGH and above block.
"""
        f"name: barad-dûr {slug}\n"
        + _on_block(triggers, branch, "github")
        + f"""concurrency:
  group: barad-dur-{slug}-${{{{ github.ref }}}}
  cancel-in-progress: false

permissions:
  contents: read

jobs:
  announce:
    runs-on: ubuntu-latest
    timeout-minutes: {WORKFLOW_MINUTES}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1

      - name: Announce to Barad-dûr and wait for the verdict
        env:
          BARAD_URL: {url_line}
          BARAD_API_KEY: ${{{{ secrets.BARAD_API_KEY }}}}
          GITHUB_EVENT_PR: ${{{{ github.event.pull_request.number }}}}
        run: |
          python3 - <<'PY'
"""
        + _indent(render_script(project, component, actions), 10)
        + """
          PY
""")


def _gitlab(project: str, component: str | None, actions: list[str], triggers: list[str],
            branch: str, api_url: str | None) -> str:
    rules = []
    if "push" in triggers:
        rules.append(f"    - if: '$CI_PIPELINE_SOURCE == \"push\" && $CI_COMMIT_BRANCH == \"{branch}\"'")
    if "pull_request" in triggers:
        rules.append("    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'")
    if "manual" in triggers:
        rules.append("    - if: '$CI_PIPELINE_SOURCE == \"web\"'")
    url_block = (f'  variables:\n    BARAD_URL: "{api_url}"\n' if api_url else "")
    url_hint = ("" if api_url else
                "# BARAD_URL comes from Settings → CI/CD → Variables.\n")
    return (
        f"# Generated by Barad-dûr for {project}"
        + (f" / {component}" if component else "")
        + """.

# A pipeline announces; the scan runs on the platform's daemon. Set a masked
# BARAD_API_KEY in Settings → CI/CD → Variables; the job fails when the flow's
# own verdict is fail: HIGH and above block.
"""
        + url_hint
        + """stages:
  - security

barad-dur:
  stage: security
  image: python:3.12-slim
  timeout: 45m
"""
        + url_block
        + """  rules:
""" + ("\n".join(rules) if rules else "    - when: manual") + """
  script:
    - |
""" + _indent("python3 - <<'PY'\n" + render_script(project, component, actions) + "PY", 6) + """
""")


def _generic(project: str, component: str | None, actions: list[str], **_) -> str:
    return (
        f"#!/usr/bin/env python3\n"
        f"# Generated by Barad-dûr for {project}"
        + (f" / {component}" if component else "")
        + """.

# Drop this file in the repository and run it from any CI with two variables set:
#   BARAD_URL       the platform's API root, no trailing slash
#   BARAD_API_KEY   the console's "api key"
# The job fails when the flow's own verdict is fail: HIGH and above block.
"""
        + render_script(project, component, actions))


RENDERERS = {"github": _github, "gitea": _github, "gitlab": _gitlab, "generic": _generic}


def snippet(*, project: str, component: str | None, actions: list[str], provider: str,
            triggers: list[str], branch: str, api_url: str | None) -> dict:
    """The file, where it goes, and the three steps that make it run."""
    flavour = provider_for(provider)
    meta = PROVIDERS[flavour]
    body = RENDERERS[flavour](project=project, component=component, actions=actions,
                              triggers=triggers, branch=branch, api_url=api_url)
    notes = [
        f"Save it as {meta['path']} in the repository root.",
        f"Add BARAD_API_KEY as a secret in {meta['key_store']} — the key the "
        "console issues under “api key”.",
        (f"BARAD_URL is written as {api_url}; move it to a variable if it "
         "differs per fork or per environment."
         if api_url else
         "Set BARAD_URL (a variable, not a secret) to this platform's API root on "
         "port 8090 — a runner cannot see 127.0.0.1."),
    ]
    if flavour in {"github", "gitea"}:
        notes.append("The job posts one flow per action and waits on "
                     "/scans/{id}/gate; the build fails only when the verdict is fail.")
    if flavour == "gitlab":
        notes.append("Keep BARAD_API_KEY masked: it is an organization credential, "
                     "not a scan token.")
    if flavour == "generic":
        notes.append("This is the portable script; a workflow file would be a guess "
                     "about your runner.")
    return {
        "provider": flavour,
        "label": meta["label"],
        "path": meta["path"],
        "body": body.rstrip() + "\n",
        "notes": notes,
        "secrets": ["BARAD_API_KEY"],
        # A URL written into the file is not a variable the repository has to
        # define; saying both would send the reader looking twice.
        "variables": [] if api_url else ["BARAD_URL"],
    }
