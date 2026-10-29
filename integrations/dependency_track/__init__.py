"""Dependency-Track project, version, and CycloneDX SBOM synchronization."""
import base64
import json
import time
from urllib.parse import quote

from barad.core.http import HttpClient, HttpStatusError, HttpTransportError, validate_endpoint
from barad.core.inventory import fingerprint
from barad.core.sbom import validate as validate_sbom
from barad.core.versioning import is_mutable_version


def synchronize(settings, manifest, sbom_path, *, pending=None):
    block = settings.block('dependency_track')
    if not block['enabled']:
        return {'status': 'NOT_CONFIGURED'}
    git = manifest['git']
    event = git.get('event') or 'local'
    branch = git.get('branch')
    default = settings.environ.get('BARAD_DEFAULT_BRANCH', 'main')
    temporary = branch and branch not in (default, 'master') and event != 'release'
    if event == 'pr' or (temporary and not block.get('publish_branches', False)):
        return {'status': 'SKIPPED', 'reason': 'temporary_branch'}
    version = manifest['application_version']['value']
    if not version:
        return {'status': 'FAILED', 'reason': 'version_unresolved'}
    if event == 'release' and is_mutable_version(version):
        return {'status': 'FAILED', 'reason': 'invalid_release_identity'}
    endpoint = settings.endpoint('dependency_track')
    token = settings.environ.get(block['token_env'])
    if not endpoint or not token:
        return {'status': 'FAILED', 'reason': 'connection_not_configured'}
    try:
        endpoint = validate_endpoint(endpoint)
    except ValueError:
        return {'status': 'FAILED', 'reason': 'invalid_endpoint'}
    name = manifest['project']['name']
    headers = {'X-Api-Key': token}
    client = HttpClient(timeout=block.get('timeout_seconds', 15),
                        max_attempts=block.get('max_attempts', 2))
    project_url = f'{endpoint}/api/v1/project?name={quote(name, safe="")}&version={quote(version, safe="")}&excludeInactive=false'
    try:
        projects = client.request('GET', project_url, headers=headers).json()
        if isinstance(projects, dict):
            projects = projects.get('objects')
        if not isinstance(projects, list):
            return {'status': 'FAILED', 'reason': 'invalid_project_response'}
        exact = [p for p in projects if isinstance(p, dict) and p.get('name', name) == name
                 and p.get('version', version) == version and p.get('uuid')]
        if len(exact) > 1:
            return {'status': 'FAILED', 'reason': 'ambiguous_project_version'}
        created = not exact
        if created:
            if not block.get('auto_create', False):
                return {'status': 'FAILED', 'reason': 'project_missing_creation_disabled'}
            response = client.request('PUT', f'{endpoint}/api/v1/project', headers=headers,
                                      json_body={'name': name, 'version': version, 'active': True}).json()
            uuid = response.get('uuid') if isinstance(response, dict) else None
        else:
            uuid = exact[0]['uuid']
        if not uuid:
            return {'status': 'FAILED', 'reason': 'project_identifier_missing'}

        reason = 'new_project_version' if created else 'remote_inventory_unverifiable'
        if not created:
            url = f'{endpoint}/api/v1/bom/cyclonedx/project/{quote(uuid, safe="")}'
            try:
                remote = client.request('GET', url, headers=headers).json()
                if isinstance(remote, dict) and validate_sbom(remote).ok:
                    remote_fingerprint = fingerprint(remote, target_type=manifest['source']['target_type'],
                                                     target=manifest['source']['target'])
                    if remote_fingerprint == manifest['inventory']['fingerprint']:
                        return {'status': 'UNCHANGED', 'reason': 'remote_inventory_verified',
                                'project_uuid': uuid, 'version': version,
                                'inventory_fingerprint': remote_fingerprint}
                    reason = 'remote_inventory_changed'
            except (HttpStatusError, HttpTransportError, ValueError):
                pass

        if (not created and isinstance(pending, dict) and pending.get('status') == 'PENDING'
                and pending.get('project_uuid') == uuid and pending.get('version') == version
                and pending.get('inventory_fingerprint') == manifest['inventory']['fingerprint']
                and pending.get('processing_token')):
            old_token = pending['processing_token']
            try:
                processing = client.request('GET',
                    f'{endpoint}/api/v1/bom/token/{quote(old_token, safe="")}',
                    headers=headers).json()
                if isinstance(processing, dict) and processing.get('processing') is True:
                    return {**pending, 'reason': 'previous_processing_pending'}
                if isinstance(processing, dict) and processing.get('processing') is False:
                    exported = client.request('GET',
                        f'{endpoint}/api/v1/bom/cyclonedx/project/{quote(uuid, safe="")}',
                        headers=headers).json()
                    if (isinstance(exported, dict) and validate_sbom(exported).ok
                            and fingerprint(exported, target_type=manifest['source']['target_type'],
                                            target=manifest['source']['target']) ==
                            manifest['inventory']['fingerprint']):
                        return {'status': 'UNCHANGED', 'reason': 'previous_processing_verified',
                                'project_uuid': uuid, 'version': version,
                                'inventory_fingerprint': manifest['inventory']['fingerprint']}
            except (HttpStatusError, HttpTransportError, ValueError):
                return {**pending, 'reason': 'previous_processing_unverifiable'}

        encoded = base64.b64encode(_deduplicate_dependencies(sbom_path)).decode('ascii')
        uploader = HttpClient(timeout=block.get('timeout_seconds', 15), max_attempts=1)
        submitted = uploader.request('PUT', f'{endpoint}/api/v1/bom', headers=headers,
                                     json_body={'project': uuid, 'bom': encoded}).json()
        processing_token = submitted.get('token') if isinstance(submitted, dict) else None
        if not processing_token:
            return {'status': 'PENDING', 'reason': 'processing_token_missing',
                    'project_uuid': uuid, 'version': version}
        result = {'status': 'PENDING', 'reason': 'processing_pending', 'project_uuid': uuid,
                  'version': version, 'processing_token': processing_token,
                  'inventory_fingerprint': manifest['inventory']['fingerprint']}
        deadline = time.monotonic() + block.get('wait_timeout_seconds', 30)
        while True:
            response = client.request('GET', f'{endpoint}/api/v1/bom/token/{quote(processing_token, safe="")}',
                                      headers=headers).json()
            if isinstance(response, dict) and response.get('processing') is False:
                try:
                    exported = client.request(
                        'GET', f'{endpoint}/api/v1/bom/cyclonedx/project/{quote(uuid, safe="")}',
                        headers=headers,
                    ).json()
                    verified = (isinstance(exported, dict) and validate_sbom(exported).ok
                                and fingerprint(exported,
                                                target_type=manifest['source']['target_type'],
                                                target=manifest['source']['target']) ==
                                manifest['inventory']['fingerprint'])
                except (HttpStatusError, HttpTransportError, ValueError):
                    verified = False
                if verified:
                    result.update(status='PUBLISHED', reason=reason, processing='complete',
                                  remote_inventory_verified=True)
                else:
                    result.update(reason='post_processing_inventory_unverified', processing='complete')
                return result
            if time.monotonic() >= deadline:
                return result
            time.sleep(min(.5, max(deadline - time.monotonic(), 0)))
    except (HttpStatusError, HttpTransportError, ValueError, OSError) as error:
        result = {'status': 'FAILED', 'reason': 'remote_error',
                  'http_status': error.status if isinstance(error, HttpStatusError) else None}
        detail = _safe_validation_detail(error, settings.secret_values())
        if detail:
            result['detail'] = detail
        return result


def _deduplicate_dependencies(sbom_path):
    """Normalize CycloneDX dependency edges for Dependency-Track validation."""
    document = json.loads(sbom_path.read_text(encoding='utf-8'))
    for dependency in document.get('dependencies', []):
        if isinstance(dependency, dict) and isinstance(dependency.get('dependsOn'), list):
            dependency['dependsOn'] = list(dict.fromkeys(dependency['dependsOn']))
    return json.dumps(document, separators=(',', ':')).encode('utf-8')


def _safe_validation_detail(error, secrets):
    """Expose only a bounded JSON `message`, never arbitrary response content."""
    if not isinstance(error, HttpStatusError):
        return None
    try:
        body = json.loads(error.body.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return None
    message = body.get('message') if isinstance(body, dict) else None
    if not isinstance(message, str):
        return None
    detail = ' '.join(message.split())[:240]
    for secret in secrets:
        if secret:
            detail = detail.replace(str(secret), '[redacted]')
    return detail or None
