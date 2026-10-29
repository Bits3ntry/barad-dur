import unittest

from cli_support import CliTestCase, invoke


class CommandSurfaceTests(CliTestCase):
    def test_help_lists_exactly_scan_run_and_health(self):
        code, out, err = invoke(["--help"])

        self.assertEqual(code, 0)
        self.assertIn("{scan,run,health}", out)
        from barad.cli import build_parser
        choices = next(action.choices for action in build_parser()._actions
                       if getattr(action, 'dest', None) == 'command')
        self.assertEqual(list(choices), ['scan', 'run', 'health'])
        self.assertEqual(err, "")

    def test_unknown_command_is_rejected_with_usage_exit(self):
        code, out, err = invoke(["check"])

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("invalid choice: 'check'", err)
        self.assertIn("choose from scan, run, health", err)

    def test_run_uses_scan_when_optional_integrations_are_missing(self):
        from unittest import mock
        from cli_support import FakeTrivy
        with mock.patch('barad.scan.TrivyRunner', FakeTrivy):
            code, out, err = invoke(['run', str(self.root)])
        self.assertEqual((code, err), (0, ''))
        self.assertIn('run ', out)
        self.assertIn('dependency_track: NOT_CONFIGURED', out)

    def test_health_diagnostic_is_a_public_command(self):
        from unittest import mock
        with mock.patch('barad.commands.health.TrivyRunner.version', return_value='0.76.1'):
            code, out, err = invoke(['health'], cwd=self.root)
        self.assertEqual((code, err), (0, ''))
        self.assertIn('health: HEALTHY', out)


if __name__ == "__main__":
    unittest.main()
