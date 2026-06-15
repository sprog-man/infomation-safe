"""
test_server_api.py — HTTP API tests for server_api.py

Tests all /api/* endpoints and static file serving via an embedded
ThreadingHTTPServer in a daemon thread.

Usage: python test_server_api.py
"""

import sys
import os
import json
import time
import threading
import unittest
import http.client

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server_api import ThreadedHTTPServer, _API_HANDLERS, _WEB_ROOT


class TestServerApi(unittest.TestCase):
    """HTTP API endpoint tests."""

    @classmethod
    def setUpClass(cls):
        """Start the HTTP server on a random port."""
        from server_api import WebHandler
        cls.server = ThreadedHTTPServer(("127.0.0.1", 0), WebHandler)
        cls.server.request_queue_size = 5
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _post(self, path: str, body: dict) -> dict:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("POST", path, body=json.dumps(body).encode("utf-8"),
                      headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return data

    def _get(self, path: str) -> http.client.HTTPResponse:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        return conn.getresponse()

    # ------------------------------------------------------------------
    # Sensor Data
    # ------------------------------------------------------------------

    def test_01_sensor_data(self):
        """POST /api/sensor-data returns valid JSON with readings."""
        res = self._post("/api/sensor-data", {"count": 3})
        self.assertIn("json", res)
        self.assertIn("count", res)
        self.assertIn("size_bytes", res)
        self.assertEqual(res["count"], 3)
        data = json.loads(res["json"])
        self.assertEqual(data["reading_count"], 3)

    def test_02_sensor_data_invalid_count(self):
        """POST /api/sensor-data with count=0 returns error."""
        res = self._post("/api/sensor-data", {"count": 0})
        self.assertIn("error", res)

    # ------------------------------------------------------------------
    # AES Encrypt / Decrypt
    # ------------------------------------------------------------------

    def test_03_aes_encrypt(self):
        """POST /api/aes-encrypt returns hex ciphertext."""
        res = self._post("/api/aes-encrypt", {
            "plaintext": "Hello, sensor!",
            "key_hex": "4d79536573734b657931323334353637",
        })
        self.assertIn("ciphertext_hex", res)
        # Ciphertext should be longer than plaintext (PKCS7 padding)
        self.assertGreater(len(res["ciphertext_hex"]), len("Hello, sensor!") * 2)

    def test_04_aes_decrypt(self):
        """POST /api/aes-decrypt recovers original plaintext."""
        ct_res = self._post("/api/aes-encrypt", {
            "plaintext": "Roundtrip test data!",
            "key_hex": "4d79536573734b657931323334353637",
        })
        dec_res = self._post("/api/aes-decrypt", {
            "ciphertext_hex": ct_res["ciphertext_hex"],
            "key_hex": "4d79536573734b657931323334353637",
        })
        self.assertIn("plaintext", dec_res)
        self.assertEqual(dec_res["plaintext"], "Roundtrip test data!")

    def test_05_aes_wrong_key(self):
        """POST /api/aes-decrypt with wrong key should fail."""
        ct_res = self._post("/api/aes-encrypt", {
            "plaintext": "secret",
            "key_hex": "4d79536573734b657931323334353637",
        })
        dec_res = self._post("/api/aes-decrypt", {
            "ciphertext_hex": ct_res["ciphertext_hex"],
            "key_hex": "00000000000000000000000000000000",
        })
        self.assertIn("error", dec_res)

    # ------------------------------------------------------------------
    # RSA Key Generation
    # ------------------------------------------------------------------

    def test_06_keys_2048(self):
        """POST /api/keys generates valid 2048-bit keypair."""
        res = self._post("/api/keys", {"bits": 2048})
        self.assertIn("public_key", res)
        self.assertIn("private_key", res)
        self.assertIn("n", res["public_key"])
        self.assertIn("e", res["public_key"])
        self.assertEqual(res["public_key"]["e"], 65537)
        self.assertIn("d", res["private_key"])

    def test_07_keys_512(self):
        """POST /api/keys with bits=512 returns smaller keypair."""
        res = self._post("/api/keys", {"bits": 512})
        self.assertEqual(res["bits"], 512)
        self.assertIn("public_key", res)

    def test_08_keys_invalid_bits(self):
        """POST /api/keys with bits=4096 returns error."""
        res = self._post("/api/keys", {"bits": 4096})
        self.assertIn("error", res)

    # ------------------------------------------------------------------
    # RSA Encrypt Key
    # ------------------------------------------------------------------

    def test_09_encrypt_key(self):
        """POST /api/encrypt-key returns hex encrypted key."""
        keys_res = self._post("/api/keys", {"bits": 512})
        res = self._post("/api/encrypt-key", {
            "public_key": keys_res["public_key"],
            "aes_key_hex": "4d79536573734b657931323334353637",
        })
        self.assertIn("encrypted_key_hex", res)
        self.assertGreater(len(res["encrypted_key_hex"]), 0)

    # ------------------------------------------------------------------
    # HMAC
    # ------------------------------------------------------------------

    def test_10_hmac_compute(self):
        """POST /api/hmac returns a 64-char hex tag."""
        res = self._post("/api/hmac", {
            "key_hex": "4d79536573734b657931323334353637",
            "message_hex": "48656c6c6f",  # "Hello"
        })
        self.assertIn("tag_hex", res)
        self.assertEqual(len(res["tag_hex"]), 64)

    def test_11_hmac_verify(self):
        """POST /api/verify-hmac validates a correct tag."""
        comp_res = self._post("/api/hmac", {
            "key_hex": "4d79536573734b657931323334353637",
            "message_hex": "48656c6c6f",
        })
        ver_res = self._post("/api/verify-hmac", {
            "key_hex": "4d79536573734b657931323334353637",
            "message_hex": "48656c6c6f",
            "tag_hex": comp_res["tag_hex"],
        })
        self.assertTrue(ver_res["valid"])

    def test_12_hmac_verify_invalid(self):
        """POST /api/verify-hmac rejects a wrong tag."""
        ver_res = self._post("/api/verify-hmac", {
            "key_hex": "4d79536573734b657931323334353637",
            "message_hex": "48656c6c6f",
            "tag_hex": "0" * 64,
        })
        self.assertFalse(ver_res["valid"])

    # ------------------------------------------------------------------
    # Static File Serving
    # ------------------------------------------------------------------

    def test_13_static_index(self):
        """GET / returns index.html with 200 status."""
        resp = self._get("/")
        self.assertEqual(resp.status, 200)
        body = resp.read().decode("utf-8")
        self.assertIn("Information Safety Experiment", body)

    def test_14_static_css(self):
        """GET /css/style.css returns CSS file."""
        resp = self._get("/css/style.css")
        self.assertEqual(resp.status, 200)
        body = resp.read().decode("utf-8")
        self.assertIn(":root", body)

    def test_15_static_js(self):
        """GET /js/pipeline.js returns JS file."""
        resp = self._get("/js/pipeline.js")
        self.assertEqual(resp.status, 200)
        body = resp.read().decode("utf-8")
        self.assertIn("pipelineState", body)

    def test_16_404(self):
        """GET /nonexistent returns 404."""
        resp = self._get("/nonexistent")
        self.assertEqual(resp.status, 404)

    def test_17_unknown_endpoint(self):
        """POST /api/nonexistent returns 404."""
        res = self._post("/api/nonexistent", {})
        self.assertIn("error", res)

    def test_18_missing_field(self):
        """POST /api/aes-encrypt without plaintext returns error."""
        res = self._post("/api/aes-encrypt", {"key_hex": "abc"})
        self.assertIn("error", res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
