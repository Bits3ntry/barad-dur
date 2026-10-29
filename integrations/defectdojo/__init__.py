"""DefectDojo Trivy Scan import and reimport adapter."""
from urllib.parse import quote

from barad_security.http import HttpClient, HttpStatusError, HttpTransportError, multipart, validate_endpoint


def synchronize(settings, manifest, sanitized_path):
    block = settings.block('defectdojo')
    if not block['enabled']:
        return {'status': 'NOT_CONFIGURED'}
    endpoint = settings.endpoint('defectdojo')
    token = settings.environ.get(block['token_env'])
    if not endpoint or not token:
        return {'status': 'FAILED', 'reason': 'connection_not_configured'}
    try:
        endpoint = validate_endpoint(endpoint)
    except ValueError:
        return {'status': 'FAILED', 'reason': 'invalid_endpoint'}
    name = block.get('product_name') or manifest['project']['name']
    version = manifest['application_version']['value'] or 'unresolved'
    title = f"{block.get('test_title_prefix', '')}{name} {version} trivy"
    headers = {'Authorization': f'Token {token}', 'Accept': 'application/json'}
    client = HttpClient(timeout=block.get('timeout_seconds', 15), max_attempts=block.get('max_attempts', 2))
    try:
        response = client.request('GET', f'{endpoint}/api/v2/tests/?title={quote(title, safe="")}&limit=100',
                                  headers=headers).json()
        tests = response.get('results') if isinstance(response, dict) else None
        if not isinstance(tests, list):
            return {'status': 'FAILED', 'reason': 'invalid_test_response'}
        matches = [t for t in tests if isinstance(t, dict) and t.get('title') == title and t.get('id')]
        if len(matches) > 1 or (response.get('next') and len(tests) >= 100):
            return {'status': 'FAILED', 'reason': 'ambiguous_test_identity'}
        test_id = matches[0]['id'] if matches else None
        if test_id is not None and not _belongs_to_product(client, endpoint, headers,
                                                             matches[0], name):
            return {'status': 'FAILED', 'reason': 'test_product_mismatch'}
        mode = 'reimport' if test_id is not None else 'import'
        fields = {'scan_type': 'Trivy Scan', 'close_old_findings': 'false',
                  'active': 'true', 'verified': 'false', 'test_title': title,
                  'minimum_severity': 'Info', 'commit_hash': manifest['commit'],
                  'branch_tag': manifest['git']['branch'], 'build_id': manifest['run_id']}
        if test_id is not None:
            fields['test'] = str(test_id)
        else:
            fields.update({'product_name': name,
                           'product_type_name': block.get('product_type_name'),
                           'engagement_name': block.get('engagement_name') or f'{name} Barad CLI',
                           'auto_create_context': str(block.get('auto_create_context', False)).lower()})
        body, content_type = multipart(fields, {'file': ('security.json', sanitized_path.read_bytes(),
                                                        'application/json')})
        writer = HttpClient(timeout=block.get('timeout_seconds', 15), max_attempts=1)
        submitted = writer.request('POST', f'{endpoint}/api/v2/{mode}-scan/', headers=headers,
                                   body=body, content_type=content_type).json()
        imported_id = submitted.get('test') if isinstance(submitted, dict) else None
        if isinstance(imported_id, dict):
            imported_id = imported_id.get('id')
        if not imported_id or (test_id is not None and str(imported_id) != str(test_id)):
            return {'status': 'PENDING', 'reason': 'test_identifier_unverified', 'mode': mode}
        verified = client.request('GET', f'{endpoint}/api/v2/tests/{quote(str(imported_id), safe="")}/',
                                  headers=headers).json()
        if not isinstance(verified, dict) or str(verified.get('id')) != str(imported_id):
            return {'status': 'PENDING', 'reason': 'test_not_visible', 'mode': mode}
        if not _belongs_to_product(client, endpoint, headers, verified, name):
            return {'status': 'PENDING', 'reason': 'test_product_unverified', 'mode': mode}
        findings = client.request('GET',
            f'{endpoint}/api/v2/findings/?test={quote(str(imported_id), safe="")}&limit=1',
            headers=headers).json()
        count = findings.get('count') if isinstance(findings, dict) else None
        if not isinstance(count, int) or (manifest['scan']['counts'].get('total', 0) and count == 0):
            return {'status': 'PENDING', 'reason': 'findings_unverified', 'mode': mode,
                    'test_id': imported_id}
        return {'status': 'PUBLISHED', 'mode': mode, 'test_id': imported_id,
                'observed_findings': count,
                'test_title': title, 'close_old_findings': False}
    except (HttpStatusError, HttpTransportError, ValueError, OSError) as error:
        return {'status': 'FAILED', 'reason': 'remote_error',
                'http_status': error.status if isinstance(error, HttpStatusError) else None}


def _belongs_to_product(client, endpoint, headers, test, name):
    engagement_id = test.get('engagement')
    if isinstance(engagement_id, dict):
        engagement_id = engagement_id.get('id')
    if not engagement_id:
        return False
    engagement = client.request('GET',
        f'{endpoint}/api/v2/engagements/{quote(str(engagement_id), safe="")}/',
        headers=headers).json()
    if not isinstance(engagement, dict):
        return False
    product_id = engagement.get('product')
    if isinstance(product_id, dict):
        product_id = product_id.get('id')
    if not product_id:
        return False
    product = client.request('GET', f'{endpoint}/api/v2/products/{quote(str(product_id), safe="")}/',
                             headers=headers).json()
    return isinstance(product, dict) and product.get('name') == name
