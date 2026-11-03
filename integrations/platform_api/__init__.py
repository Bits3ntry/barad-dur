"""Platform API project/version/inventory publication."""
from urllib.parse import quote

from barad.core.http import HttpClient, HttpStatusError, HttpTransportError, validate_endpoint


def synchronize(settings, manifest, sbom_path, *, pending=None):
    """Publish the validated SBOM to the Barad platform API.

    Mirrors the Dependency-Track contract: PUBLISHED only against a verified
    remote receipt, never against a local file. The receipt counters must
    match the local inventory before publication is claimed.
    """
    block = settings.block('platform_api')
    if not block['enabled']:
        return {'status': 'NOT_CONFIGURED'}
    version = manifest['application_version']['value']
    if not version:
        return {'status': 'FAILED', 'reason': 'version_unresolved'}
    endpoint = settings.endpoint('platform_api')
    token = settings.environ.get(block['token_env'])
    if not endpoint or not token:
        return {'status': 'FAILED', 'reason': 'connection_not_configured'}
    try:
        endpoint = validate_endpoint(endpoint)
    except ValueError:
        return {'status': 'FAILED', 'reason': 'invalid_endpoint'}
    name = manifest['project']['name']
    count = _inventory_size(manifest)
    if count is None:
        return {'status': 'FAILED', 'reason': 'inventory_unresolved'}
    headers = {'X-API-Key': token}
    client = HttpClient(timeout=block.get('timeout_seconds', 15),
                        max_attempts=block.get('max_attempts', 2))
    url = (f'{endpoint}/api/v1/sbom?source=cli'
           f'&project={quote(name, safe="")}&version={quote(version, safe="")}')
    try:
        # Raw bytes: the API validates the document itself; Trivy SBOMs carry
        # no metadata.component.version, so the version arrives as a query
        # override resolved by the CLI's versioning module.
        response = client.request('POST', url, headers=headers,
                                  body=_sbom_bytes(sbom_path),
                                  content_type='application/octet-stream',
                                  idempotent=True)
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get('receipt'), dict):
            return {'status': 'FAILED', 'reason': 'invalid_receipt_response'}
        receipt = body['receipt']
        remote_name = receipt.get('project')
        remote_version = receipt.get('version')
        if remote_name != name or remote_version != version:
            return {'status': 'FAILED', 'reason': 'identity_mismatch',
                    'remote': {'project': remote_name, 'version': remote_version}}
        received = (receipt.get('counts') or {}).get('components_received')
        if received != count:
            return {'status': 'FAILED', 'reason': 'inventory_count_mismatch',
                    'remote_components': received, 'local_components': count}
        if body.get('status') == 'duplicate':
            return {'status': 'UNCHANGED', 'reason': 'content_receipt_verified',
                    'import_id': receipt['import_id']}
        return {'status': 'PUBLISHED', 'reason': 'receipt_verified',
                'import_id': receipt['import_id'],
                'remote_components': received}
    except (HttpStatusError, HttpTransportError, ValueError, OSError) as error:
        result = {'status': 'FAILED', 'reason': 'remote_error',
                  'http_status': error.status if isinstance(error, HttpStatusError) else None}
        detail = _safe_detail(error, settings.secret_values())
        if detail:
            result['detail'] = detail
        return result


def synchronize_findings(settings, manifest, sanitized_path, sast_path):
    """Push sanitized Trivy + OpenGrep findings to the platform ingest API.

    Builds the `barad-findings-v1` payload from the sanitized evidence only:
    secret match lines never travel (the sanitizer redacts them before this
    runs, and this function drops match text entirely — only rule id, path,
    line and severity cross the boundary). Returns an ingest receipt dict.

    Inside a GitHub Actions context (GITHUB_ACTIONS=true) the function runs
    the whole CI flow in order: register the run, push findings with the run
    link, then close the run so the platform computes the gate verdict.
    """
    import json
    import os

    block = settings.block('platform_api')
    if not block['enabled']:
        return {'status': 'NOT_CONFIGURED'}
    endpoint = settings.endpoint('platform_api')
    token = settings.environ.get(block['token_env'])
    if not endpoint or not token:
        return {'status': 'FAILED', 'reason': 'connection_not_configured'}
    try:
        endpoint = validate_endpoint(endpoint)
    except ValueError:
        return {'status': 'FAILED', 'reason': 'invalid_endpoint'}
    name = manifest['project']['name']
    version = manifest['application_version']['value']
    if not version:
        return {'status': 'FAILED', 'reason': 'version_unresolved'}
    findings = _trivy_findings(sanitized_path, manifest) + _opengrep_findings(sast_path, manifest)
    if not findings:
        return {'status': 'EMPTY', 'reason': 'no_secrets_misconfig_or_sast_findings'}
    headers = {'X-API-Key': token}
    client = HttpClient(timeout=block.get('timeout_seconds', 15),
                        max_attempts=block.get('max_attempts', 2))
    result = {'status': 'INGESTED'}

    run_id = None
    ci_context = os.environ.get('GITHUB_ACTIONS') == 'true'
    if ci_context:
        registration = client.request(
            'POST', f'{endpoint}/api/v1/ci/runs', headers=headers,
            json_body={'provider': 'github',
                       'repository': os.environ.get('GITHUB_REPOSITORY', ''),
                       'workflow_path': os.environ.get('GITHUB_WORKFLOW', ''),
                       'ref': os.environ.get('GITHUB_REF', ''),
                       'commit_sha': os.environ.get('GITHUB_SHA', ''),
                       'event': os.environ.get('GITHUB_EVENT_NAME', ''),
                       'actor': os.environ.get('GITHUB_ACTOR', '')}).json()
        run_id = (registration.get('data') or {}).get('id') if isinstance(registration, dict) else None
        if not run_id:
            return {'status': 'FAILED', 'reason': 'ci_run_registration_failed'}
        result['ci_run_id'] = run_id
        source = 'ci'
    else:
        source = 'cli'
    query = (f'{endpoint}/api/v1/findings/ingest?source={source}'
             f'&project={quote(name, safe="")}&version={quote(version, safe="")}')
    if run_id:
        query += f'&run_id={quote(run_id, safe="")}'
    payload = {'schema': 'barad-findings-v1', 'tool': 'trivy', 'findings': findings}
    # OpenGrep findings ride in the same payload; their records declare their
    # own tool override.
    try:
        response = client.request('POST', query, headers=headers,
                                  body=json.dumps(payload).encode('utf-8'),
                                  content_type='application/json', idempotent=True)
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get('counts'), dict):
            return {'status': 'FAILED', 'reason': 'invalid_ingest_response'}
        result.update(counts=body['counts'], project=body.get('project'),
                      version=body.get('version'))
        if run_id:
            finish = client.request(
                'POST', f'{endpoint}/api/v1/ci/runs/{quote(run_id, safe="")}/finish',
                headers=headers, json_body={'status': 'succeeded'}).json()
            summary = (finish.get('data') or {}) if isinstance(finish, dict) else {}
            reasons = None
            try:
                detail = client.request(
                    'GET', f'{endpoint}/api/v1/ci/runs/{quote(run_id, safe="")}',
                    headers=headers).json()
                reasons = (detail.get('data') or {}).get('verdict_reasons')
            except (HttpStatusError, HttpTransportError, ValueError):
                pass
            result['ci_run'] = {'verdict': summary.get('verdict'),
                                'findings_count': summary.get('findings_count'),
                                'verdict_reasons': reasons}
        return result
    except (HttpStatusError, HttpTransportError, ValueError, OSError) as error:
        result = {'status': 'FAILED', 'reason': 'remote_error',
                  'http_status': error.status if isinstance(error, HttpStatusError) else None}
        detail = _safe_detail(error, settings.secret_values())
        if detail:
            result['detail'] = detail
        return result


def _relative(path, manifest):
    target = (manifest.get('source') or {}).get('target') or ''
    try:
        from pathlib import Path

        absolute = Path(path)
        root = Path(target).resolve()
        return absolute.relative_to(root).as_posix() if str(absolute).startswith(str(root)) else path
    except (ValueError, OSError, TypeError):
        return path


def _trivy_findings(sanitized_path, manifest):
    import json

    try:
        report = json.loads(sanitized_path.read_text(encoding='utf-8')
                            if hasattr(sanitized_path, 'read_text') else
                            json.dumps(json.loads(open(sanitized_path).read())))
    except (OSError, ValueError):
        return []
    if isinstance(report, str):
        report = json.loads(report)
    findings = []
    for result in report.get('Results') or []:
        target = _relative(result.get('Target') or '', manifest)
        for secret in result.get('Secrets') or []:
            findings.append({
                'kind': 'secret', 'tool': 'trivy', 'severity': secret.get('Severity'),
                'title': secret.get('Title') or secret.get('RuleID'),
                'rule_id': secret.get('RuleID'), 'path': target,
                'line': _first_match_line(secret), 'detail': None,})
        for misconfig in result.get('Misconfigurations') or []:
            cause = misconfig.get('CauseMetadata') or {}
            findings.append({
                'kind': 'misconfiguration', 'tool': 'trivy',
                'severity': misconfig.get('Severity'),
                'title': misconfig.get('Title'),
                'rule_id': misconfig.get('ID'), 'path': target,
                'line': cause.get('StartLine'), 'detail': None,})
    return findings


def _first_match_line(secret):
    for match in secret.get('MatchData') or []:
        line = match.get('Line')
        if isinstance(line, int):
            return line
        if isinstance(line, str) and line.isdigit():
            return int(line)
    return None


def _opengrep_findings(sast_path, manifest):
    import json

    try:
        report = json.loads(sast_path.read_text(encoding='utf-8')
                            if hasattr(sast_path, 'read_text') else open(sast_path).read())
    except (OSError, ValueError):
        return []
    findings = []
    for result in report.get('results') or []:
        rule_id = (result.get('check_id') or '').split('.')[-1]
        severity = (result.get('extra') or {}).get('severity')
        findings.append({
            'kind': 'code-weakness', 'tool': 'opengrep',
            'severity': _sast_severity(severity),
            'title': (result.get('extra') or {}).get('message') or rule_id,
            'rule_id': rule_id, 'path': _relative(result.get('path') or '', manifest),
            'line': (result.get('start') or {}).get('line'), 'detail': None,})
    return findings


def _sast_severity(severity):
    mapping = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}
    return mapping.get(str(severity).upper())


def _inventory_size(manifest):
    inventory = manifest.get('inventory') or {}
    for key in ('component_count', 'components', 'size'):
        value = inventory.get(key)
        if isinstance(value, int):
            return value
    return None


def _sbom_bytes(sbom_path):
    import json

    with open(sbom_path, encoding='utf-8') as handle:
        document = json.load(handle)
    for dependency in document.get('dependencies') or []:
        if isinstance(dependency, dict) and isinstance(dependency.get('dependsOn'), list):
            dependency['dependsOn'] = list(dict.fromkeys(dependency['dependsOn']))
    return json.dumps(document, separators=(',', ':')).encode('utf-8')


def _safe_detail(error, secrets):
    """Expose only a bounded JSON `message`, never arbitrary response content."""
    if not isinstance(error, HttpStatusError):
        return None
    try:
        import json

        body = json.loads(error.body.decode('utf-8'))
    except (UnicodeDecodeError, ValueError, AttributeError):
        return None
    message = body.get('message') or body.get('detail') if isinstance(body, dict) else None
    if not isinstance(message, str):
        return None
    detail = ' '.join(message.split())[:240]
    for secret in secrets:
        if secret:
            detail = detail.replace(str(secret), '[redacted]')
    return detail or None
