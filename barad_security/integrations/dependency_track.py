"""Dependency-Track adapter: publish inventory without rewriting history.

Deliberate behaviour:

* a project is looked up by stable `name` + `version`; it is created only when
  `auto_create` is enabled, so a pull request never produces a permanent project;
* `main` is a development line, never `Latest`; promotion happens only under the
  configured `latest_policy` and only for the highest semantic version;
* a release whose SBOM differs from the one already recorded for that version is
  classified (identical, correction, distinct rebuild) and **not** overwritten
  unless `allow_release_overwrite` is true;
* a 5xx or transport failure defers publication (PENDING) instead of losing it.
"""
import base64
import hashlib
import json
import re
import urllib.parse

from ..errors import PublishError
from ..http import HttpStatusError, HttpTransportError
from .base import DUPLICATE, FAILED, PENDING, PUBLISHED, PublicationResult, Publisher

MUTABLE_VERSIONS = {"latest", "main", "master", "head", "snapshot", "develop"}


def _quote(value):
    return urllib.parse.quote(str(value), safe="")


def _semver_key(value):
    """Order versions by numbers; returns None when the value is not semantic."""
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?([-+].*)?$", str(value or "").strip())
    if not match:
        return None
    parts = [int(match.group(index) or 0) for index in (1, 2, 3)]
    if match.group(4):
        return None  # pre-release ordering is not trivial; refuse to guess
    return tuple(parts)


def _component_fingerprint(document):
    purls = sorted(
        component.get("purl")
        for component in document.get("components") or []
        if isinstance(component, dict) and component.get("purl")
    )
    return hashlib.sha256("\n".join(purls).encode("utf-8")).hexdigest(), len(purls)


class DependencyTrackPublisher(Publisher):
    service = "dependency_track"
    log_step = "dependency_track"

    # -- public API --------------------------------------------------------
    def publish(self, context):
        settings = self.settings()
        target = context.publish_target or ("release" if context.event == "release" else "development")
        if context.sbom_path is None:
            return self.skip("no_sbom")
        version = context.version if target == "release" else settings.get("development_version", "main")
        version = str(version or "").strip()
        if target == "release" and (not version or version.lower() in MUTABLE_VERSIONS):
            return self.fail("invalid_release_identity",
                             ValueError(f"release version {version!r} is not an immutable version"))
        if not version:
            return self.fail("invalid_release_identity", ValueError("no version to publish"))

        document = self._load_sbom(context.sbom_path)
        if document is None:
            return self.fail("invalid_sbom", ValueError("the SBOM is not readable JSON"))
        fingerprint, component_count = _component_fingerprint(document)

        conflict = self._release_conflict(settings, context, target, fingerprint)
        if conflict is not None:
            return conflict

        try:
            endpoint, token, token_name = self.endpoint()
        except PublishError as error:
            return self._deferred("not_configured", error, [])
        if not token:
            return self._deferred("not_configured",
                                  PublishError(f"{token_name} is not set", service=self.service), [])

        client = self.client()
        headers = {"X-Api-Key": token}
        attempts = []
        try:
            project_uuid = self._ensure_project(client, endpoint, headers, settings, context, version, attempts)
            if project_uuid is None:
                return self.fail("project_missing",
                                 PublishError("project does not exist and dependency_track.auto_create is false"),
                                 attempts=attempts)
        except HttpStatusError as error:
            return self._http_failure(error, attempts, stage="project_lookup")
        except HttpTransportError as error:
            return self._transport_failure(error, attempts, stage="project_lookup")

        try:
            token_value = self._upload_bom(client, endpoint, headers, context, project_uuid, attempts)
        except HttpStatusError as error:
            return self._http_failure(error, attempts, stage="bom_upload")
        except HttpTransportError as error:
            return self._transport_failure(error, attempts, stage="bom_upload")

        waited = None
        if settings.get("wait_for_analysis"):
            waited = self._wait_for_analysis(client, endpoint, headers, token_value, attempts,
                                             float(settings.get("wait_timeout_seconds", 300)))

        latest = False
        if target == "release" and settings.get("latest_policy") == "semver_highest":
            latest = self._promote_if_highest(client, endpoint, headers, context, version, attempts)

        self.logger.info(self.log_step, "published", {
            "project": context.service, "version": version, "target": target,
            "project_uuid": project_uuid, "waited": waited, "latest": latest,
        })
        return PublicationResult(
            service=self.service,
            status=PUBLISHED,
            reason=None,
            external_ids={"project": project_uuid, "token": token_value},
            attempts=attempts,
            artifact="sbom.cdx.json",
            required=self.required(),
            detail={"version": version, "target": target, "wait_for_analysis": bool(waited),
                    "components": component_count, "component_fingerprint": fingerprint,
                    "latest": latest},
        )

    # -- helpers -----------------------------------------------------------
    def _load_sbom(self, path):
        try:
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            return None
        return document if isinstance(document, dict) else None

    def _release_conflict(self, settings, context, target, fingerprint):
        """Never overwrite a recorded release inventory silently."""
        if target != "release":
            return None
        previous_sha = (context.known_external_ids or {}).get("release_sbom_sha256")
        previous_fingerprint = (context.known_external_ids or {}).get("release_component_fingerprint")
        if not previous_sha:
            return None
        if previous_sha == (context.known_external_ids or {}).get("sbom_sha256"):
            return PublicationResult(service=self.service, status=DUPLICATE,
                                     reason="unchanged_release_inventory",
                                     message="the same SBOM was already published for this version",
                                     external_ids={}, required=self.required(),
                                     detail={"classification": "identical_reimport"})
        classification = "distinct_rebuild"
        if previous_fingerprint and previous_fingerprint == fingerprint:
            classification = "inventory_correction"
        if settings.get("allow_release_overwrite"):
            self.logger.warning(self.log_step, "release_inventory_replaced", {
                "version": context.version, "classification": classification})
            return None
        self.logger.warning(self.log_step, "release_inventory_conflict", {
            "version": context.version, "classification": classification})
        return self.fail(
            "release_inventory_conflict",
            PublishError(f"version {context.version} already has a different SBOM ({classification})"),
            detail={"classification": classification, "previous_sbom_sha256": previous_sha},
        )

    def _ensure_project(self, client, endpoint, headers, settings, context, version, attempts):
        name = context.service
        query = f"{endpoint}/api/v1/project?name={_quote(name)}&version={_quote(version)}&excludeInactive=false"
        response = client.request("GET", query, headers=headers, idempotent=True)
        attempts.extend(response.attempts)
        projects = response.json() or []
        projects = projects.get("objects", []) if isinstance(projects, dict) else projects
        if projects:
            first = projects[0]
            return first.get("uuid") if isinstance(first, dict) else None
        if not settings.get("auto_create", True):
            return None
        body = {"name": name, "version": version, "active": True}
        parent_name = settings.get("parent_name")
        if parent_name:
            parent_version = settings.get("parent_version", "")
            parent_uuid = self._find_project_uuid(client, endpoint, headers, parent_name, parent_version, attempts)
            if parent_uuid:
                body["parent"] = {"uuid": parent_uuid}
        created = client.request("PUT", f"{endpoint}/api/v1/project", headers=headers, json_body=body)
        attempts.extend(created.attempts)
        created_document = created.json() or {}
        project_uuid = created_document.get("uuid") if isinstance(created_document, dict) else None
        self.logger.info(self.log_step, "project_created", {"name": name, "version": version,
                                                            "project_uuid": project_uuid})
        return project_uuid

    def _find_project_uuid(self, client, endpoint, headers, name, version, attempts):
        query = f"{endpoint}/api/v1/project?name={_quote(name)}&version={_quote(version)}"
        response = client.request("GET", query, headers=headers, idempotent=True)
        attempts.extend(response.attempts)
        projects = response.json() or []
        projects = projects.get("objects", []) if isinstance(projects, dict) else projects
        if projects and isinstance(projects[0], dict):
            return projects[0].get("uuid")
        return None

    def _upload_bom(self, client, endpoint, headers, context, project_uuid, attempts):
        with open(context.sbom_path, "rb") as handle:
            encoded = base64.b64encode(handle.read()).decode("ascii")
        body = {"project": project_uuid, "bom": encoded}
        response = client.request("PUT", f"{endpoint}/api/v1/bom", headers=headers, json_body=body)
        attempts.extend(response.attempts)
        document = response.json() or {}
        token_value = document.get("token") if isinstance(document, dict) else None
        if not token_value:
            raise HttpTransportError("no_processing_token", attempts, f"{endpoint}/api/v1/bom")
        return token_value

    def _wait_for_analysis(self, client, endpoint, headers, token_value, attempts, timeout):
        import time as _time

        deadline = _time.monotonic() + max(timeout, 0)
        while True:
            response = client.request("GET", f"{endpoint}/api/v1/bom/token/{_quote(token_value)}",
                                      headers=headers, idempotent=True)
            attempts.extend(response.attempts)
            document = response.json() or {}
            processing = document.get("processing") if isinstance(document, dict) else None
            if processing is False:
                return True
            if _time.monotonic() >= deadline:
                self.logger.warning(self.log_step, "analysis_incomplete", {"timeout_seconds": timeout})
                return False
            _time.sleep(min(1.0, max(deadline - _time.monotonic(), 0.0)))

    def _promote_if_highest(self, client, endpoint, headers, context, version, attempts):
        current = _semver_key(version)
        if current is None:
            self.logger.warning(self.log_step, "latest_not_promoted",
                                {"reason": "non_semantic_version", "version": version})
            return False
        response = client.request("GET",
                                  f"{endpoint}/api/v1/project?name={_quote(context.service)}&excludeInactive=false",
                                  headers=headers, idempotent=True)
        attempts.extend(response.attempts)
        projects = response.json() or []
        projects = projects.get("objects", []) if isinstance(projects, dict) else projects
        versions = []
        for project in projects:
            if not isinstance(project, dict):
                continue
            key = _semver_key(project.get("version"))
            if key is not None:
                versions.append((key, project))
        if not versions:
            return False
        highest_key, highest_project = max(versions, key=lambda item: item[0])
        if highest_key != current or highest_project.get("version") != version:
            return False
        if highest_project.get("isLatest"):
            return True
        body = {"uuid": highest_project.get("uuid"), "name": highest_project.get("name"),
                "version": highest_project.get("version"), "isLatest": True}
        updated = client.request("POST", f"{endpoint}/api/v1/project", headers=headers, json_body=body)
        attempts.extend(updated.attempts)
        return True

    # -- failure mapping ---------------------------------------------------
    def _http_failure(self, error, attempts, stage):
        attempts = attempts or error.attempts
        if error.status in (401, 403):
            return self.fail("unauthorized", PublishError(f"HTTP {error.status} on {stage}"), attempts=attempts)
        if error.status >= 500 or error.status == 429:
            result = self.fail("server_error", PublishError(f"HTTP {error.status} on {stage}"),
                               attempts=attempts, detail={"deferred": True, "stage": stage})
            result.status = PENDING
            return result
        return self.fail("rejected", PublishError(f"HTTP {error.status} on {stage}: {error.snippet()}"),
                         attempts=attempts, detail={"stage": stage})

    def _deferred(self, reason, error, attempts):
        result = self.fail(reason, error, attempts=attempts, detail={"deferred": True})
        result.status = PENDING
        return result

    def _transport_failure(self, error, attempts, stage):
        result = self.fail("unreachable", PublishError(f"{error.reason} on {stage}"),
                           attempts=attempts or error.attempts,
                           detail={"deferred": True, "stage": stage})
        result.status = PENDING
        return result
