"""Logging contract: JSON Lines, readable line, and no secret ever persisted."""
import io
import json
import tempfile
import unittest
from pathlib import Path

from barad_security.logs import Logger, Redactor


class LoggingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "execution.log"
        self.stream = io.StringIO()
        self.log = Logger("local-20260101T000000Z-abcdef", path=self.path, stream=self.stream)

    def tearDown(self):
        self._tmp.cleanup()

    def records(self):
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]

    def test_json_lines_and_human_output_share_one_event(self):
        self.log.info("change_detection", "dependency_change_detected", {"file": "package-lock.json"})
        record = self.records()[0]
        self.assertEqual(record["level"], "INFO")
        self.assertEqual(record["step"], "change_detection")
        self.assertEqual(record["event"], "dependency_change_detected")
        self.assertEqual(record["run_id"], "local-20260101T000000Z-abcdef")
        self.assertEqual(record["details"]["file"], "package-lock.json")
        self.assertTrue(record["timestamp"].endswith("Z"))
        human = self.stream.getvalue()
        self.assertIn("dependency_change_detected", human)
        self.assertIn("package-lock.json", human)

    def test_known_secret_values_are_redacted_in_both_sinks(self):
        secret = "dtrack-super-secret-value"
        log = Logger("run-1", path=self.path, stream=self.stream, redactor=Redactor([secret]))
        log.error("dependency_track", "upload_failed", {"hint": f"key {secret} rejected", "nested": [secret]})
        record = self.records()[0]
        self.assertNotIn(secret, self.path.read_text(encoding="utf-8"))
        self.assertNotIn(secret, self.stream.getvalue())
        self.assertEqual(record["details"]["hint"], "key [REDACTED] rejected")
        self.assertEqual(record["details"]["nested"], ["[REDACTED]"])

    def test_header_redaction_keeps_names_and_hides_values(self):
        redactor = Redactor(["abcdef123456"])
        safe = redactor.headers({"X-Api-Key": "abcdef123456", "Authorization": "Token abc", "Accept": "application/json"})
        self.assertEqual(safe["X-Api-Key"], "[REDACTED]")
        self.assertEqual(safe["Authorization"], "[REDACTED]")
        self.assertEqual(safe["Accept"], "application/json")

    def test_level_filter_suppresses_lower_severity(self):
        log = Logger("run-1", path=self.path, stream=self.stream, level="WARNING")
        log.info("step", "ignored")
        log.warning("step", "kept")
        self.assertEqual([record["event"] for record in self.records()], ["kept"])

    def test_logging_never_raises_when_the_sink_is_unwritable(self):
        log = Logger("run-1", path=Path("/proc/definitely/not/here/execution.log"), stream=self.stream)
        log.info("step", "still_reported")  # must not raise
        self.assertIn("still_reported", self.stream.getvalue())

    def test_short_values_are_not_treated_as_secrets(self):
        redactor = Redactor(["abc"])
        self.assertEqual(redactor.text("abc def"), "abc def")


if __name__ == "__main__":
    unittest.main()
