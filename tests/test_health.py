"""Non-destructive public health contract."""
import os
from unittest import mock

from cli_support import CliTestCase, invoke
from barad.core.http import Response, HttpStatusError


class ReadOnlyClient:
    calls = []
    fail = False

    def __init__(self, *args, **kwargs):
        pass

    def request(self, method, url, **kwargs):
        ReadOnlyClient.calls.append((method, url, kwargs))
        if ReadOnlyClient.fail:
            raise HttpStatusError(401, b'private-token', [], url)
        return Response(200, body=b'[]' if '/api/v1/' in url else b'{"count": 1}')


class FakeEngineManager:
    result = {
        'status': 'HEALTHY', 'version': '1.33.1', 'platform': 'linux-x86_64',
        'cached': True,
    }
    inspect_calls = 0

    def __init__(self, *args, **kwargs):
        pass

    def inspect(self, name):
        self.__class__.inspect_calls += 1
        self.__class__.last_name = name
        return dict(self.__class__.result)

    def resolve(self, *_args, **_kwargs):
        raise AssertionError('health must not install an engine')


class HealthTests(CliTestCase):
    def setUp(self):
        super().setUp()
        ReadOnlyClient.calls = []
        ReadOnlyClient.fail = False
        FakeEngineManager.result = {
            'status': 'HEALTHY', 'version': '1.33.1', 'platform': 'linux-x86_64',
            'cached': True,
        }
        FakeEngineManager.inspect_calls = 0
        self.write('pyproject.toml', '[project]\nname="demo"\nversion="1.0"\n')

    def check(self, *, env=None, trivy='0.76.1', config=None):
        env = env or {}
        argv = ['health'] + (['--config', str(config)] if config else [])
        with mock.patch.dict('os.environ', env), \
             mock.patch('barad.commands.health.TrivyRunner.version', return_value=trivy), \
             mock.patch('barad.commands.health.EngineManager', FakeEngineManager), \
             mock.patch('barad.commands.health.HttpClient', ReadOnlyClient):
            return invoke(argv, cwd=self.root)

    def test_optional_integrations_not_configured_is_healthy_and_read_only(self):
        code, out, err = self.check()
        self.assertEqual((code, err), (0, ''))
        self.assertIn('health: HEALTHY\n', out)
        self.assertIn('dependency_track: NOT CONFIGURED', out)
        self.assertIn('defectdojo: NOT CONFIGURED', out)
        self.assertIn('trivy: HEALTHY', out)
        self.assertIn('opengrep: HEALTHY (1.33.1)', out)
        self.assertEqual(FakeEngineManager.inspect_calls, 1)
        self.assertEqual(FakeEngineManager.last_name, 'opengrep')
        self.assertEqual(ReadOnlyClient.calls, [])
        self.assertFalse((self.root / '.barad').exists())

    def test_workspace_dotenv_configures_enabled_health_checks(self):
        config = self.write_config('''version: 1
scan:
  runner: local
integrations:
  dependency_track:
    enabled: true
    endpoint_env: DTRACK_URL
    token_env: DTRACK_API_KEY
  defectdojo:
    enabled: true
    endpoint_env: DOJO_URL
    token_env: DOJO_TOKEN
''')
        self.write('.env', '''DTRACK_URL=http://localhost:18080
DTRACK_API_KEY=dotenv-dt-secret
DOJO_URL=http://localhost:18082
DOJO_TOKEN=dotenv-dojo-secret
''')
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch('barad.commands.health.TrivyRunner.version', return_value='0.76.1'), \
             mock.patch('barad.commands.health.EngineManager', FakeEngineManager), \
             mock.patch('barad.commands.health.HttpClient', ReadOnlyClient):
            code, out, err = invoke(['health', '--config', str(config)], cwd=self.root)
        self.assertEqual((code, err), (0, ''))
        self.assertIn('health: HEALTHY', out)
        self.assertTrue(ReadOnlyClient.calls)
        self.assertTrue(all(method == 'GET' for method, _, _ in ReadOnlyClient.calls))
        self.assertNotIn('dotenv-dt-secret', out + err)
        self.assertNotIn('dotenv-dojo-secret', out + err)

    def test_remote_auth_failure_is_degraded_without_secret_leak(self):
        config = self.write_config('''version: 1
integrations:
  dependency_track:
    enabled: true
    endpoint: http://localhost:18080
''')
        ReadOnlyClient.fail = True
        code, out, err = self.check(env={'DTRACK_API_KEY': 'private-token'}, config=config)
        self.assertEqual((code, err), (4, ''))
        self.assertIn('health: DEGRADED', out)
        self.assertIn('dependency_track: DEGRADED', out)
        self.assertNotIn('private-token', out + err)
        self.assertTrue(ReadOnlyClient.calls)
        self.assertTrue(all(method == 'GET' for method, _, _ in ReadOnlyClient.calls))
        self.assertFalse((self.root / '.barad').exists())

    def test_missing_opengrep_cache_is_unavailable_without_installing(self):
        FakeEngineManager.result = {
            'status': 'UNAVAILABLE', 'version': '1.33.1', 'platform': 'darwin-aarch64',
            'cached': False, 'reason': 'engine_not_cached_or_verified',
        }

        code, out, err = self.check()

        self.assertEqual((code, err), (1, ''))
        self.assertIn('health: UNAVAILABLE', out)
        self.assertIn('opengrep: UNAVAILABLE', out)
        self.assertEqual(FakeEngineManager.inspect_calls, 1)
        self.assertFalse((self.root / '.barad').exists())

    def test_missing_scanner_is_unavailable(self):
        code, out, err = self.check(trivy=None)
        self.assertEqual((code, err), (1, ''))
        self.assertIn('health: UNAVAILABLE', out)
        self.assertIn('trivy: UNAVAILABLE', out)

    def test_null_project_mapping_uses_defaults_without_internal_error(self):
        config = self.write_config('version: 1\nproject: null\n')
        code, out, err = self.check(config=config)
        self.assertEqual((code, err), (0, ''))
        self.assertIn('health: HEALTHY', out)

    def test_invalid_local_config_is_not_silently_healthy(self):
        config = self.write_config('version: 1\nscan:\n  runner: unsupported\n')
        code, out, err = self.check(config=config)
        self.assertEqual(code, 2)
        self.assertEqual(out, '')
        self.assertIn('error: invalid configuration:', err)
        self.assertEqual(ReadOnlyClient.calls, [])
