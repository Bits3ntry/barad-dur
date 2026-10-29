"""`barad health`: read-only diagnostics, no project or scan mutations."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from barad_security import __version__ as security_version
from barad_security.http import HttpClient, HttpStatusError, HttpTransportError, validate_endpoint
from barad_security.trivy import TrivyRunner
from barad_security.errors import ConfigError

from .. import __version__
from ..config import CONFIG_FILENAME, load_settings, read_project_config
from ..project import derive_name, detect_ecosystems


def register(subparsers):
    parser = subparsers.add_parser('health', help='check local tools and configured endpoints without mutation')
    parser.add_argument('--config', help='path to .barad.yml (default: current directory)')
    parser.add_argument('--json', action='store_true', help='machine-readable diagnostics')
    parser.set_defaults(execute=execute)


def execute(args):
    root = Path.cwd().resolve()
    config_path = Path(args.config).expanduser().resolve() if args.config else root / CONFIG_FILENAME
    document, source = read_project_config(config_path if config_path.is_file() or args.config else None)
    project = document.get('project') if isinstance(document.get('project'), dict) else {}
    name, _ = derive_name(project.get('name'), None, root)
    settings = load_settings(document, source=source, root=root, project_name=name,
                             ecosystems=detect_ecosystems(root), environ=os.environ)
    checks = {'cli': {'status': 'HEALTHY', 'version': __version__},
              'configuration': {'status': 'HEALTHY', 'source': str(source) if source else 'defaults'}}
    git = shutil.which('git')
    checks['git'] = {'status': 'HEALTHY' if git else 'UNAVAILABLE'}
    if git:
        try:
            result = subprocess.run([git, '--version'], capture_output=True, text=True, timeout=4)
            if result.returncode == 0:
                checks['git']['version'] = result.stdout.strip()
            else:
                checks['git']['status'] = 'UNAVAILABLE'
        except (OSError, subprocess.SubprocessError):
            checks['git']['status'] = 'UNAVAILABLE'
    runner = settings.security.get('trivy.runner')
    if runner == 'docker' and not _image_present(settings.security.get('trivy.image')):
        trivy_version = None
    else:
        trivy_version = TrivyRunner(settings.security, None).version()
    checks['trivy'] = {'status': 'HEALTHY' if trivy_version else 'UNAVAILABLE',
                       'version': trivy_version, 'runner': runner}
    for name, path in (('dependency_track', '/api/v1/project?name=barad-health-check&version=0'),
                       ('defectdojo', '/api/v2/test_types/?limit=1')):
        block = settings.block(name)
        enabled = block['enabled']
        if not enabled:
            checks[name] = {'status': 'NOT CONFIGURED'}
            continue
        endpoint = settings.endpoint(name)
        token = settings.environ.get(block['token_env'])
        if not endpoint or not token:
            checks[name] = {'status': 'DEGRADED', 'reason': 'connection_not_configured'}
            continue
        try:
            endpoint = validate_endpoint(endpoint)
            headers = {'X-Api-Key': token} if name == 'dependency_track' else {
                'Authorization': f'Token {token}' if name == 'defectdojo' else f'Bearer {token}'}
            HttpClient(timeout=5, max_attempts=1).request('GET', endpoint + path,
                                                        headers=headers)
            checks[name] = {'status': 'HEALTHY'}
        except (HttpStatusError, HttpTransportError, ValueError) as error:
            checks[name] = {'status': 'DEGRADED', 'reason': 'authentication_or_connection_failed',
                            'http_status': error.status if isinstance(error, HttpStatusError) else None}
    if checks['trivy']['status'] != 'HEALTHY':
        status, exit_code = 'UNAVAILABLE', 1
    elif any(check['status'] != 'HEALTHY' for key, check in checks.items()
             if key not in ('cli', 'configuration', 'trivy') and check['status'] != 'NOT CONFIGURED'):
        status, exit_code = 'DEGRADED', 4
    else:
        status, exit_code = 'HEALTHY', 0
    result = {'status': status, 'checks': checks, 'versions': {'barad_security': security_version}}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f'health: {status}')
        for name, check in checks.items():
            print(f"  {name}: {check['status']}" +
                  (f" ({check['version']})" if check.get('version') else ''))
    return exit_code


def _image_present(image):
    if not shutil.which('docker'):
        return False
    try:
        result = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True,
                                timeout=5)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
