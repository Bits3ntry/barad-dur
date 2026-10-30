"""Public run workflow and remote inventory contract (no real services mutated)."""
import base64
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from cli_support import CliTestCase, FakeOpenGrep, FakeTrivy, invoke, cyclonedx
from barad.core.http import Response, HttpStatusError


class Remote:
    """Small deterministic HTTP service boundary, keyed by method and path."""
    calls = []
    project = set()
    uploaded = None
    dojo_test = None
    bom = None
    token_pending = False
    fail_dojo = False
    processed_bom = None
    wrong_product = False
    findings_count = 1
    fail_dt_upload = False
    dt_upload_error = None

    @classmethod
    def reset(cls):
        cls.calls = []
        cls.project = set()
        cls.uploaded = None
        cls.dojo_test = None
        cls.bom = None
        cls.token_pending = False
        cls.fail_dojo = False
        cls.processed_bom = None
        cls.wrong_product = False
        cls.findings_count = 1
        cls.fail_dt_upload = False
        cls.dt_upload_error = None

    def __init__(self, *args, **kwargs):
        pass

    def request(self, method, url, **kwargs):
        Remote.calls.append((method, url, kwargs))
        if '/api/v1/project?' in url:
            version = url.split('version=', 1)[1].split('&', 1)[0]
            return self._ok([{'uuid': 'project-uuid', 'version': version}] if version in Remote.project else [])
        if url.endswith('/api/v1/project') and method == 'PUT':
            Remote.project.add(kwargs['json_body']['version'])
            return self._ok({'uuid': 'project-uuid'})
        if '/api/v1/bom/cyclonedx/project/' in url:
            if Remote.bom is None:
                raise HttpStatusError(404, b'not found', [], url)
            return self._ok(Remote.bom)
        if url.endswith('/api/v1/bom'):
            if Remote.dt_upload_error is not None:
                raise Remote.dt_upload_error
            if Remote.fail_dt_upload:
                raise HttpStatusError(503, b'unavailable', [], url)
            Remote.uploaded = kwargs['json_body']['bom']
            return self._ok({'token': 'processing-token'})
        if '/api/v1/bom/token/' in url:
            if not Remote.token_pending:
                Remote.bom = Remote.processed_bom or FakeTrivy.sbom
            return self._ok({'processing': Remote.token_pending})
        if '/api/v2/tests/?' in url:
            return self._ok({'results': [{'id': 42, 'title': 'poc 1.0 trivy', 'engagement': 9}] if Remote.dojo_test else []})
        if '/api/v2/tests/42/' in url:
            return self._ok({'id': 42, 'title': 'poc 1.0 trivy', 'engagement': 9})
        if '/api/v2/findings/?' in url:
            return self._ok({'count': Remote.findings_count, 'results': []})
        if '/api/v2/engagements/9/' in url:
            return self._ok({'id': 9, 'product': 7})
        if '/api/v2/products/7/' in url:
            return self._ok({'id': 7, 'name': 'other' if Remote.wrong_product else 'poc'})
        if url.endswith('/api/v2/import-scan/') or url.endswith('/api/v2/reimport-scan/'):
            if Remote.fail_dojo:
                raise HttpStatusError(503, b'unavailable', [], url)
            Remote.dojo_test = True
            return self._ok({'test': 42})
        raise AssertionError(f'unexpected request {method} {url}')

    @staticmethod
    def _ok(body):
        return Response(200, body=json.dumps(body).encode('utf-8'))


class RunContractTests(CliTestCase):
    def setUp(self):
        super().setUp()
        Remote.reset()
        self.write('pyproject.toml', '[project]\nname="poc"\nversion="1.0"\n')
        self.write_config('''version: 1
project:
  name: poc
integrations:
  dependency_track:
    enabled: true
    auto_create: true
    wait_timeout_seconds: 1
    endpoint: http://localhost:18080
  defectdojo:
    enabled: true
    endpoint: http://localhost:18082
    auto_create_context: true
    product_type_name: Barad CLI POC
''')
        self.env = {'DTRACK_API_KEY': 'private-dt', 'DOJO_TOKEN': 'private-dojo'}

    def run_cli(self, *args):
        from barad import scan
        with mock.patch.dict('os.environ', self.env), \
             mock.patch('barad.scan.TrivyRunner', FakeTrivy), \
             mock.patch('barad.scan.OpenGrepRunner', FakeOpenGrep), \
             mock.patch('integrations.dependency_track.HttpClient', Remote), \
             mock.patch('integrations.defectdojo.HttpClient', Remote):
            code, out, err = invoke(['run', *args], cwd=self.root)
        reports = list((self.root / '.barad/reports').glob('**/manifest.json'))
        manifest = json.loads(max(reports, key=lambda p: p.stat().st_mtime_ns).read_text()) if reports else None
        return code, out, err, manifest

    def test_workspace_dotenv_enables_an_explicit_profile_for_external_target(self):
        external = tempfile.TemporaryDirectory()
        self.addCleanup(external.cleanup)
        target = Path(external.name) / 'councilbox-server'
        target.mkdir()
        (target / 'pyproject.toml').write_text(
            '[project]\nname="councilbox-server"\nversion="1.0"\n', encoding='utf-8'
        )
        profile = self.write('config/local/councilbox-server.barad.yml', '''version: 1
project:
  name: poc
integrations:
  dependency_track:
    enabled: true
    endpoint_env: DTRACK_URL
    token_env: DTRACK_API_KEY
    auto_create: true
    wait_timeout_seconds: 1
  defectdojo:
    enabled: true
    endpoint_env: DOJO_URL
    token_env: DOJO_TOKEN
    auto_create_context: true
    product_type_name: CBX
    engagement_name: councilbox-server security
''')
        self.write('.env', '''DTRACK_URL=http://localhost:18080
DTRACK_API_KEY=dotenv-dt-secret
DOJO_URL=http://localhost:18082
DOJO_TOKEN=dotenv-dojo-secret
''')

        from barad import scan
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch('barad.scan.TrivyRunner', FakeTrivy), \
             mock.patch('barad.scan.OpenGrepRunner', FakeOpenGrep), \
             mock.patch('integrations.dependency_track.HttpClient', Remote), \
             mock.patch('integrations.defectdojo.HttpClient', Remote):
            code, out, err = invoke(['run', str(target), '--config', str(profile)], cwd=self.root)

        manifests = list((self.root / '.barad/reports').glob('**/manifest.json'))
        manifest = json.loads(manifests[0].read_text(encoding='utf-8'))
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PUBLISHED')
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'PUBLISHED')
        self.assertTrue((self.root / '.barad/state/local-inventory.json').is_file())
        self.assertFalse((target / '.barad').exists())
        self.assertFalse((target / '.barad.yml').exists())
        persisted = out + err + json.dumps(manifest)
        self.assertNotIn('dotenv-dt-secret', persisted)
        self.assertNotIn('dotenv-dojo-secret', persisted)

    def test_initial_run_creates_version_uploads_and_imports(self):
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual((code, err), (0, ''))
        self.assertIn('run poc: completed', out)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PUBLISHED')
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'PUBLISHED')
        self.assertEqual(manifest['sync']['defectdojo']['mode'], 'import')
        self.assertEqual(len([c for c in Remote.calls if c[0] == 'PUT' and c[1].endswith('/api/v1/bom')]), 1)
        self.assertEqual(FakeTrivy.scan_calls, 1)
        self.assertEqual(FakeTrivy.sbom_calls, 1)
        self.assertNotIn('private-dt', json.dumps(manifest) + out + err)
        self.assertNotIn('private-dojo', json.dumps(manifest) + out + err)

    def test_repeat_verifies_remote_inventory_and_reimports_without_upload(self):
        self.assertEqual(self.run_cli('.')[0], 0)
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'UNCHANGED')
        self.assertEqual(manifest['sync']['defectdojo']['mode'], 'reimport')
        self.assertEqual(len([c for c in Remote.calls if c[1].endswith('/api/v1/bom')]), 1)
        self.assertEqual(FakeTrivy.scan_calls, 2)
        self.assertEqual(FakeTrivy.sbom_calls, 2)
        self.assertTrue(any(c[1].endswith('/api/v2/reimport-scan/') for c in Remote.calls))
        self.assertTrue(all(b'close_old_findings"\r\n\r\nfalse' in c[2].get('body', b'')
                            for c in Remote.calls if c[1].endswith('import-scan/')))

    def test_import_does_not_claim_success_if_parser_produces_no_findings(self):
        Remote.findings_count = 0
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'PENDING')
        self.assertEqual(manifest['sync']['defectdojo']['reason'], 'findings_unverified')

    def test_existing_test_in_another_product_is_never_reimported(self):
        Remote.dojo_test = True
        Remote.wrong_product = True
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'FAILED')
        self.assertEqual(manifest['sync']['defectdojo']['reason'], 'test_product_mismatch')
        self.assertFalse(any(c[1].endswith('/api/v2/reimport-scan/') for c in Remote.calls))

    def test_dt_upload_deduplicates_cyclonedx_dependency_edges(self):
        FakeTrivy.sbom = cyclonedx(dependencies=[{'ref': 'pkg:pypi/demo@1.2.3',
                                                  'dependsOn': ['pkg:pypi/a@1', 'pkg:pypi/a@1']}])
        code, out, err, manifest = self.run_cli('.')
        uploaded = json.loads(base64.b64decode(Remote.uploaded))
        self.assertEqual(code, 0, err)
        self.assertEqual(uploaded['dependencies'][0]['dependsOn'], ['pkg:pypi/a@1'])

    def test_changed_inventory_uploads_even_with_same_version(self):
        self.assertEqual(self.run_cli('.')[0], 0)
        FakeTrivy.sbom = cyclonedx('2.0')
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 0, err)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PUBLISHED')
        self.assertEqual(len([c for c in Remote.calls if c[1].endswith('/api/v1/bom')]), 2)

    def test_new_application_version_creates_new_project_version_even_with_same_sbom(self):
        self.assertEqual(self.run_cli('.')[0], 0)
        self.write('pyproject.toml', '[project]\nname="poc"\nversion="2.0"\n')
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 0, err)
        self.assertEqual(manifest['sync']['dependency_track']['version'], '2.0')
        self.assertEqual(len([c for c in Remote.calls if c[0] == 'PUT' and c[1].endswith('/api/v1/project')]), 2)
        self.assertEqual(len([c for c in Remote.calls if c[1].endswith('/api/v1/bom')]), 2)

    def test_missing_optional_integrations_do_not_fail_a_scan(self):
        self.write_config('version: 1\n')
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'NOT_CONFIGURED')
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'NOT_CONFIGURED')
        self.assertEqual(Remote.calls, [])

    def test_unknown_remote_inventory_never_claims_unchanged(self):
        Remote.project.add('1.0')
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 0, err)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PUBLISHED')
        self.assertEqual(manifest['sync']['dependency_track']['reason'], 'remote_inventory_unverifiable')

    def test_dt_validation_message_is_bounded_and_does_not_expose_payload(self):
        message = 'token private-dt rejected: ' + ('x' * 300)
        Remote.dt_upload_error = HttpStatusError(
            400, json.dumps({'message': message}).encode('utf-8'), [], 'http://localhost/api/v1/bom'
        )
        code, out, err, manifest = self.run_cli('.')
        detail = manifest['sync']['dependency_track']['detail']
        self.assertEqual(code, 4)
        self.assertIn('[redacted]', detail)
        self.assertEqual(len(detail), 240)
        self.assertNotIn('private-dt', detail + out + err + json.dumps(manifest))

    def test_dt_upload_failure_keeps_scan_and_dojo_import(self):
        Remote.fail_dt_upload = True
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'FAILED')
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'PUBLISHED')
        self.assertEqual(manifest['scan']['status'], 'SUCCESS')
        self.assertEqual(manifest['sync']['dependency_track']['http_status'], 503)
        self.assertNotIn('detail', manifest['sync']['dependency_track'])

    def test_partial_dojo_failure_keeps_scan_and_exits_four(self):
        Remote.fail_dojo = True
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertIn('run poc: partial', out)
        self.assertEqual(manifest['sync']['defectdojo']['status'], 'FAILED')
        self.assertEqual(manifest['scan']['status'], 'SUCCESS')
        self.assertEqual(manifest['status'], 'partial')
        self.assertTrue((self.root / manifest['run']['directory'] / 'security.json').is_file())
        self.assertNotIn('private-dojo', json.dumps(manifest) + out + err)

    def test_processed_token_without_matching_remote_inventory_is_partial(self):
        Remote.processed_bom = cyclonedx('other')
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PENDING')
        self.assertEqual(manifest['sync']['dependency_track']['reason'],
                         'post_processing_inventory_unverified')
        self.assertEqual(manifest['scan']['status'], 'SUCCESS')

    def test_processing_token_pending_is_partial(self):
        Remote.token_pending = True
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PENDING')
        self.assertEqual(manifest['sync']['dependency_track']['processing_token'], 'processing-token')

    def test_pending_token_is_resumed_without_duplicate_upload(self):
        Remote.token_pending = True
        self.assertEqual(self.run_cli('.')[0], 4)
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['dependency_track']['reason'],
                         'previous_processing_pending')
        self.assertEqual(len([c for c in Remote.calls if c[1].endswith('/api/v1/bom')]), 1)

    def test_mutable_release_version_cannot_create_remote_project(self):
        self.env['GITHUB_EVENT_NAME'] = 'release'
        self.write_config('''version: 1
project:
  name: poc
  version:
    source: literal
    value: main
integrations:
  dependency_track:
    enabled: true
    auto_create: true
    endpoint: http://localhost:18080
''')
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 4)
        self.assertEqual(manifest['sync']['dependency_track']['reason'],
                         'invalid_release_identity')
        self.assertFalse(any('/api/v1/' in c[1] for c in Remote.calls))

    def test_temporary_branch_publishes_under_an_isolated_version_when_enabled(self):
        self.write_config('''version: 1
project:
  name: poc
integrations:
  dependency_track:
    enabled: true
    auto_create: true
    publish_branches: true
    wait_timeout_seconds: 1
    endpoint: http://localhost:18080
  defectdojo:
    enabled: true
    endpoint: http://localhost:18082
    auto_create_context: true
    product_type_name: Barad CLI POC
''')
        from barad.core.gitctx import GitContext
        from barad.core.versioning import branch_version
        context = GitContext(repository_root=self.root, available=True,
                             event='local', branch='feature/security-hardening')
        with mock.patch('barad.commands.scan._git_context', return_value=context):
            code, out, err, manifest = self.run_cli('.')

        isolated = branch_version('1.0', 'feature/security-hardening')
        self.assertEqual(code, 0, err)
        self.assertEqual(manifest['application_version']['value'], isolated)
        self.assertEqual(manifest['application_version']['source'], 'pyproject+branch')
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'PUBLISHED')
        self.assertIn(isolated, manifest['sync']['defectdojo']['test_title'])

    def test_unicode_branch_has_an_isolated_remote_version(self):
        from barad.core.versioning import branch_version

        isolated = branch_version('1.0', '日本語')

        self.assertIsNotNone(isolated)
        self.assertNotEqual(isolated, '1.0')
        self.assertRegex(isolated, r'^1\.0-branch-branch-[0-9a-f]{10}$')

    def test_temporary_branch_stays_skipped_without_opt_in(self):
        from barad.core.gitctx import GitContext
        context = GitContext(repository_root=self.root, available=True,
                             event='local', branch='feature/default-safety')
        with mock.patch('barad.commands.scan._git_context', return_value=context):
            code, out, err, manifest = self.run_cli('.')

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest['application_version']['value'], '1.0')
        self.assertEqual(manifest['sync']['dependency_track'],
                         {'status': 'SKIPPED', 'reason': 'temporary_branch'})

    def test_pr_context_never_publishes_stable_version(self):
        self.env['GITHUB_EVENT_NAME'] = 'pull_request'
        code, out, err, manifest = self.run_cli('.')
        self.assertEqual(code, 0, err)
        self.assertEqual(manifest['sync']['dependency_track']['status'], 'SKIPPED')
        self.assertFalse(any('/api/v1/' in c[1] for c in Remote.calls))

    def test_invalid_path_has_no_scan_or_remote_side_effects(self):
        code, out, err, manifest = self.run_cli('not-here')
        self.assertEqual(code, 2)
        self.assertEqual(out, '')
        self.assertIn('error: scan path not found:', err)
        self.assertEqual(Remote.calls, [])
        self.assertEqual(FakeTrivy.scan_calls, 0)
        self.assertFalse(self.state_path.exists())
