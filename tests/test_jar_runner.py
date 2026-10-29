"""Shared Trivy command regression: directory behavior remains, JAR file is mounted."""
from unittest import TestCase, mock
from pathlib import Path
from tempfile import TemporaryDirectory

from barad.core.config import build_config
from barad.core.trivy import TrivyRunner


class JarRunnerTests(TestCase):
    def test_docker_file_target_mounts_parent_and_addresses_jar(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / 'libs').mkdir()
            (root / 'libs/app.jar').write_bytes(b'PK\x03\x04')
            config = build_config({'version': 1, 'project': {'name': 'demo', 'service': 'demo'},
                                   'trivy': {'target': 'libs/app.jar'}}, repo_root=root)
            with mock.patch('barad.core.trivy.shutil.which', return_value='/usr/local/bin/docker'):
                argv, cwd, mounted = TrivyRunner(config, None)._docker_command(
                    format_name='json', output_path=root/'output/security.json')
            self.assertIn(f'{root / "libs"}:/scan:ro', argv)
            self.assertEqual(argv[-1], '/scan/app.jar')
            self.assertEqual(mounted, root/'libs')

    def test_existing_directory_target_still_mounts_directory(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            config = build_config({'version': 1, 'project': {'name': 'demo', 'service': 'demo'}},
                                  repo_root=root)
            with mock.patch('barad.core.trivy.shutil.which', return_value='/usr/local/bin/docker'):
                argv, cwd, mounted = TrivyRunner(config, None)._docker_command(
                    format_name='json', output_path=root/'output/security.json')
            self.assertIn(f'{root}:/scan:ro', argv)
            self.assertEqual(argv[-1], '/scan')
            self.assertEqual(mounted, root)
