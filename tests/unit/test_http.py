"""HTTP contract: bounded retries, no redirects, no proxy, no duplicate writes."""
import unittest

from barad_security.http import (
    HttpClient,
    HttpStatusError,
    HttpTransportError,
    multipart,
    validate_endpoint,
)
from tests.support import MockServer


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.server = MockServer().start()
        self.sleeps = []
        self.client = HttpClient(timeout=2, max_attempts=3, backoff=0.01,
                                 sleeper=self.sleeps.append)

    def tearDown(self):
        self.server.stop()

    def test_successful_json_post(self):
        self.server.routes["POST /api/v1/bom"] = (200, {"token": "abc"}, {})
        response = self.client.request("POST", f"{self.server.url}/api/v1/bom", json_body={"a": 1},
                                       headers={"X-Api-Key": "k"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json(), {"token": "abc"})
        self.assertEqual(len(self.server.requests), 1)

    def test_5xx_is_retried_only_for_idempotent_calls(self):
        self.server.enqueue("POST /api/v1/bom", (503, {"error": "down"}, {}), (200, {"token": "t"}, {}))
        with self.assertRaises(HttpStatusError):
            self.client.request("POST", f"{self.server.url}/api/v1/bom", json_body={})
        self.assertEqual(len(self.server.requests), 1)

        self.server.enqueue("POST /api/v1/bom-with-key", (503, {"error": "down"}, {}), (200, {"token": "t"}, {}))
        response = self.client.request("POST", f"{self.server.url}/api/v1/bom-with-key", json_body={},
                                       headers={"Idempotency-Key": "run-1"})
        self.assertEqual(response.status, 200)
        self.assertEqual([attempt["status"] for attempt in response.attempts], [503, 200])
        self.assertEqual(len(self.sleeps), 1)

    def test_transport_failure_is_retried_then_reported_with_attempts(self):
        client = HttpClient(timeout=0.2, max_attempts=2, backoff=0.01, sleeper=self.sleeps.append)
        with self.assertRaises(HttpTransportError) as caught:
            client.request("GET", "http://127.0.0.1:9/unreachable")
        self.assertEqual(len(caught.exception.attempts), 2)

    def test_redirects_are_not_followed(self):
        self.server.routes["POST /api/v1/bom"] = (307, {"error": "moved"}, {"Location": "http://127.0.0.1:9/steal"})
        with self.assertRaises(HttpStatusError) as caught:
            self.client.request("POST", f"{self.server.url}/api/v1/bom", json_body={})
        self.assertEqual(caught.exception.status, 307)
        self.assertEqual(len(self.server.requests), 1)

    def test_retry_after_is_honoured(self):
        self.server.enqueue("PUT /api/v1/bom", (429, {"error": "slow"}, {"Retry-After": "0"}), (200, {"token": "t"}, {}))
        self.client.request("PUT", f"{self.server.url}/api/v1/bom", json_body={})
        self.assertEqual(len(self.server.requests), 2)

    def test_error_snippet_is_single_line(self):
        self.server.routes["POST /x"] = (400, {"error": "bad request body"}, {})
        with self.assertRaises(HttpStatusError) as caught:
            self.client.request("POST", f"{self.server.url}/x", json_body={})
        self.assertNotIn("\n", caught.exception.snippet())


class MultipartTests(unittest.TestCase):
    def test_multipart_fields_and_file(self):
        body, content_type = multipart({"scan_type": "Trivy Scan", "active": True},
                                       {"file": ("trivy.json", b'{"a":1}', "application/json")})
        self.assertTrue(content_type.startswith("multipart/form-data; boundary="))
        self.assertIn(b'name="scan_type"', body)
        self.assertIn(b"Trivy Scan", body)
        self.assertIn(b'filename="trivy.json"', body)
        self.assertIn(b'{"a":1}', body)
        self.assertTrue(body.endswith(b"--\r\n"))


class EndpointValidationTests(unittest.TestCase):
    def test_rejects_credentials_and_non_http(self):
        with self.assertRaises(ValueError):
            validate_endpoint("http://user:pass@127.0.0.1:8080", name="DTRACK_URL")
        with self.assertRaises(ValueError):
            validate_endpoint("ftp://127.0.0.1", name="DTRACK_URL")
        with self.assertRaises(ValueError):
            validate_endpoint("", name="DTRACK_URL")

    def test_accepts_internal_and_loopback_hosts(self):
        self.assertEqual(validate_endpoint("http://127.0.0.1:18080/", name="DTRACK_URL"), "http://127.0.0.1:18080")
        self.assertEqual(validate_endpoint("https://dt.internal/api", name="DTRACK_URL"), "https://dt.internal/api")


if __name__ == "__main__":
    unittest.main()
