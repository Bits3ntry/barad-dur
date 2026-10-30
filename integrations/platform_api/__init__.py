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
