"""Autonomous workflow: scan once, then synchronize independent endpoints."""
from dataclasses import dataclass

from .commands.scan import resolve
from .scan import SANITIZED_REPORT, SBOM, SAST_REPORT, run_scan
from .store import ScanStore
from .core.versioning import branch_version, resolve_version
from integrations import dependency_track, defectdojo, platform_api

EXIT_PARTIAL = 4


@dataclass
class RunResult:
    exit_code: int
    manifest: dict
    run_dir: object
    error: str = None


def run_workflow(args):
    settings, target_type, target, git, name_source = resolve(args)
    version = _publication_version(settings, git)
    scan = run_scan(settings, target_type=target_type, target_value=target,
                    git_context=git, name_source=name_source, application_version=version)
    manifest = scan.manifest
    if scan.exit_code:
        manifest['sync'] = {'dependency_track': {'status': 'SKIPPED', 'reason': 'scan_failed'},
                            'defectdojo': {'status': 'SKIPPED', 'reason': 'scan_failed'},
                            'platform_api': {'status': 'SKIPPED', 'reason': 'scan_failed'}}
        return _finish(scan, settings, manifest, scan.exit_code, scan.error)
    sbom = scan.run_dir / SBOM
    sanitized = scan.run_dir / SANITIZED_REPORT
    sast = scan.run_dir / SAST_REPORT
    results = {}
    store = ScanStore(settings.workspace or settings.root,
                      settings.document['output']['directory'], manifest['run_id'],
                      project=manifest['project']['name'],
                      version=manifest['application_version']['value'])
    sync_key = f"{manifest['project']['name']}:{manifest['application_version']['value']}:{target_type}:{target}"
    for key, action, path, uses_pending in (
        ('dependency_track', dependency_track.synchronize, sbom, True),
        ('platform_api', platform_api.synchronize, sbom, False),
        ('defectdojo', defectdojo.synchronize, sanitized, False),
    ):
        try:
            if uses_pending:
                pending = store.sync_record(sync_key)
                results[key] = action(settings, manifest, path, pending=pending)
                if results[key]['status'] == 'PENDING' and results[key].get('processing_token'):
                    store.record_sync(sync_key, results[key])
                elif results[key]['status'] in ('PUBLISHED', 'UNCHANGED'):
                    store.record_sync(sync_key, {'status': results[key]['status']})
            else:
                results[key] = action(settings, manifest, path)
        except Exception:  # unexpected failures are bounded and never erase scan evidence
            results[key] = {'status': 'FAILED', 'reason': 'internal_integration_error'}
        if (key == 'platform_api'
                and results.get('platform_api', {}).get('status') == 'PUBLISHED'):
            try:
                results[key]['findings'] = platform_api.synchronize_findings(
                    settings, manifest, sanitized, sast)
            except Exception:  # same bound: evidence survives, sync reports failure
                results[key]['findings'] = {'status': 'FAILED',
                                            'reason': 'internal_integration_error'}
    manifest['sync'] = results
    failed = any(result['status'] in ('FAILED', 'PENDING') for result in results.values())
    manifest['status'] = 'partial' if failed else 'completed'
    return _finish(scan, settings, manifest, EXIT_PARTIAL if failed else 0)


def _publication_version(settings, git):
    version = resolve_version(settings.security, environ=settings.environ)
    branch = git.branch if git is not None else None
    temporary = branch and branch not in (
        settings.environ.get('BARAD_DEFAULT_BRANCH', 'main'), 'master'
    )
    if not temporary or not settings.block('dependency_track').get('publish_branches', False):
        return version
    isolated = branch_version(version.value, branch)
    if isolated:
        version.value = isolated
        version.source = f'{version.source}+branch'
    return version


def _finish(scan, settings, manifest, code, error=None):
    store = ScanStore(settings.workspace or settings.root,
                      settings.document['output']['directory'], manifest['run_id'],
                      project=manifest['project']['name'],
                      version=manifest['application_version']['value'])
    store.write_json('manifest.json', manifest)
    store.write_checksums(list(manifest['artifacts']) + ['manifest.json'])
    return RunResult(code, manifest, scan.run_dir, error)
