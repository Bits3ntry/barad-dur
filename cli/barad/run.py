"""Autonomous workflow: scan once, then synchronize independent endpoints."""
from dataclasses import dataclass

from .commands.scan import resolve
from .scan import SANITIZED_REPORT, SBOM, run_scan
from .store import ScanStore
from integrations import dependency_track, defectdojo

EXIT_PARTIAL = 4


@dataclass
class RunResult:
    exit_code: int
    manifest: dict
    run_dir: object
    error: str = None


def run_workflow(args):
    settings, target_type, target, git, name_source = resolve(args)
    scan = run_scan(settings, target_type=target_type, target_value=target,
                    git_context=git, name_source=name_source)
    manifest = scan.manifest
    if scan.exit_code:
        manifest['sync'] = {'dependency_track': {'status': 'SKIPPED', 'reason': 'scan_failed'},
                            'defectdojo': {'status': 'SKIPPED', 'reason': 'scan_failed'}}
        return _finish(scan, settings, manifest, scan.exit_code, scan.error)
    sbom = scan.run_dir / SBOM
    sanitized = scan.run_dir / SANITIZED_REPORT
    results = {}
    store = ScanStore(settings.workspace or settings.root,
                      settings.document['output']['directory'], manifest['run_id'])
    sync_key = f"{manifest['project']['name']}:{manifest['application_version']['value']}:{target_type}:{target}"
    for key, action, path in (
        ('dependency_track', dependency_track.synchronize, sbom),
        ('defectdojo', defectdojo.synchronize, sanitized),
    ):
        try:
            if key == 'dependency_track':
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
    manifest['sync'] = results
    failed = any(result['status'] in ('FAILED', 'PENDING') for result in results.values())
    manifest['status'] = 'partial' if failed else 'completed'
    return _finish(scan, settings, manifest, EXIT_PARTIAL if failed else 0)


def _finish(scan, settings, manifest, code, error=None):
    store = ScanStore(settings.workspace or settings.root,
                      settings.document['output']['directory'], manifest['run_id'])
    store.write_json('manifest.json', manifest)
    store.write_checksums(list(manifest['artifacts']) + ['manifest.json'])
    return RunResult(code, manifest, scan.run_dir, error)
