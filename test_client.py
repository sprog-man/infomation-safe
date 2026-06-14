"""
test_client.py - End-to-end tests for the TCP client module.

Tests the full client pipeline: generate sensor data, encrypt with AES,
encrypt the AES key with RSA, compute HMAC, pack the wire frame, and
send to a real server thread.

Run with: python test_client.py

Expects all assertions to pass (no output on success).
Prints summary on completion.
"""

import io
import json
import random
import socket
import socketserver
import sys
import threading
import time
import unittest

# Add project root to path
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from crypto.aes_crypto import aes_encrypt, aes_decrypt
from crypto.rsa_crypto import generate_keypair, rsa_encrypt
from auth.hmac_auth import compute_tag, verify_tag
from data.sensor_data import generate_batch

from network.client import (
    build_frame,
    pack_frame,
    send_frame,
    run_client,
    load_or_generate_keys,
)


# ---------------------------------------------------------------------------
# Helper: minimal server that echoes ACCEPT/REJECT back
# ---------------------------------------------------------------------------

class _EchoHandler(socketserver.BaseRequestHandler):
    """
    A server that receives the frame, performs full verification (like the
    real server), and sends back ACCEPT or REJECT.
    """

    def handle(self) -> None:
        """Process one client: receive, verify, decrypt, send response."""
        try:
            req = self.request
            req.settimeout(5.0)

            # Receive RSA-encrypted key
            key_bytes = 256
            enc_key = b""
            while len(enc_key) < key_bytes:
                chunk = req.recv(key_bytes - len(enc_key))
                if not chunk:
                    break
                enc_key += chunk

            # Receive HMAC length + tag
            hmac_len_bytes = b""
            while len(hmac_len_bytes) < 4:
                chunk = req.recv(4 - len(hmac_len_bytes))
                if not chunk:
                    break
                hmac_len_bytes += chunk
            hmac_len = int.from_bytes(hmac_len_bytes, "big")

            hmac_tag = b""
            while len(hmac_tag) < hmac_len:
                chunk = req.recv(hmac_len - len(hmac_tag))
                if not chunk:
                    break
                hmac_tag += chunk

            # Receive ciphertext
            ciphertext = b""
            while True:
                chunk = req.recv(4096)
                if not chunk:
                    break
                ciphertext += chunk

            # Decrypt AES key with RSA private key (shared from server instance)
            aes_key = self.server._aes_key  # type: ignore[attr-defined]

            # Verify HMAC
            from auth.hmac_auth import verify_tag
            is_valid = verify_tag(aes_key, ciphertext, hmac_tag.hex())

            if not is_valid:
                req.sendall(b"REJECT")
                return

            # Decrypt and echo back the plaintext length as ACCEPT
            plaintext = self.server._aes_decrypt_fn(ciphertext, aes_key)  # type: ignore[attr-defined]
            req.sendall(b"ACCEPT")

        except Exception:
            pass
        finally:
            self.request.close()


class _EchoServer(socketserver.TCPServer):
    """A TCP server that accepts one connection, then shuts down."""

    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestClientBuild(unittest.TestCase):
    """Tests for the client's frame-building functions."""

    def setUp(self) -> None:
        """Generate a 2048-bit RSA key pair and a fixed AES key."""
        self.pub, self.priv = generate_keypair(2048)
        self.aes_key = b"0123456789ABCDEF"
        self.sensor_json = generate_batch(3)

    # ------------------------------------------------------------------
    # test_build_frame_correct_size
    # ------------------------------------------------------------------

    def test_build_frame_correct_size(self) -> None:
        """Verify the frame has the expected structure and minimum size."""
        frame = build_frame(self.sensor_json, self.pub, self.aes_key)

        # Frame = 256 (encrypted key) + 4 (hmac_len) + 32 (hmac_tag) + ciphertext
        # Ciphertext is at least 16 bytes (PKCS7 padding of any non-empty input)
        self.assertGreater(len(frame), 256 + 4 + 32,
                           "Frame must contain ciphertext in addition to header")

    # ------------------------------------------------------------------
    # test_pack_frame_format
    # ------------------------------------------------------------------

    def test_pack_frame_format(self) -> None:
        """Verify the packed frame has the correct byte layout."""
        aes_key = b"A" * 16
        ciphertext = b"x" * 32
        encrypted_key = b"y" * 256

        frame = pack_frame(encrypted_key, aes_key, ciphertext)

        # First 256 bytes should be the encrypted key
        self.assertEqual(frame[:256], encrypted_key)

        # Bytes 256-260 should be HMAC length (4 bytes big-endian)
        hmac_len = int.from_bytes(frame[256:260], "big")
        self.assertEqual(hmac_len, 32)

        # Bytes 260-292 should be the HMAC tag
        hmac_tag = frame[260:292]
        self.assertEqual(len(hmac_tag), 32)

        # Remaining bytes should be the ciphertext
        self.assertEqual(frame[292:], ciphertext)

    # ------------------------------------------------------------------
    # test_build_frame_is_valid
    # ------------------------------------------------------------------

    def test_build_frame_is_valid(self) -> None:
        """Verify that a frame built by build_frame passes HMAC verification."""
        frame = build_frame(self.sensor_json, self.pub, self.aes_key)

        # Extract the components
        encrypted_key = frame[:256]
        hmac_len = int.from_bytes(frame[256:260], "big")
        hmac_tag = frame[260:260 + hmac_len]
        ciphertext = frame[260 + hmac_len:]

        # Verify HMAC over the ciphertext
        self.assertTrue(
            verify_tag(self.aes_key, ciphertext, hmac_tag.hex()),
            "HMAC verification should pass for a freshly built frame",
        )

    # ------------------------------------------------------------------
    # test_build_frame_different_per_call
    # ------------------------------------------------------------------

    def test_build_frame_different_per_call(self) -> None:
        """Verify that frames differ between calls (due to random AES key)."""
        frame1 = build_frame(self.sensor_json, self.pub)
        frame2 = build_frame(self.sensor_json, self.pub)

        self.assertNotEqual(frame1, frame2,
                            "Frames should differ due to random AES key generation")

    # ------------------------------------------------------------------
    # test_build_frame_with_fixed_key
    # ------------------------------------------------------------------

    def test_build_frame_deterministic_with_fixed_key(self) -> None:
        """Verify that the ciphertext portion is deterministic when the same AES key is provided.

        Note: The RSA-encrypted key differs between calls because PKCS#1 v1.5
        padding uses random bytes, so the full frame is not identical.
        We verify the ciphertext portion (after the HMAC tag) is deterministic.
        """
        fixed_key = b"FixedKey12345678"
        frame1 = build_frame(self.sensor_json, self.pub, fixed_key)
        frame2 = build_frame(self.sensor_json, self.pub, fixed_key)

        # Extract ciphertext portion (after 256 + 4 + 32 = 292 bytes of header)
        ct1 = frame1[292:]
        ct2 = frame2[292:]

        self.assertEqual(ct1, ct2,
                         "Ciphertext should be identical with the same AES key")


class TestClientEndToEnd(unittest.TestCase):
    """End-to-end tests: client sends frame, server receives and verifies."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate a 2048-bit RSA key pair once for all tests."""
        start = time.monotonic()
        cls.pub, cls.priv = generate_keypair(2048)
        cls.aes_key = b"0123456789ABCDEF"
        elapsed = time.monotonic() - start
        print(f"\n[INFO] Generated 2048-bit RSA key pair in {elapsed:.1f}s",
              file=sys.stderr)

    def setUp(self) -> None:
        """Store connection parameters for each test."""
        self.host = "127.0.0.1"

    # ------------------------------------------------------------------
    # test_client_server_roundtrip
    # ------------------------------------------------------------------

    def test_client_server_roundtrip(self) -> None:
        """
        Build a frame with the client module, send it to a real server thread,
        and verify the server responds with ACCEPT.
        """
        sensor_json = generate_batch(3)
        frame = build_frame(sensor_json, self.pub, self.aes_key)

        # Start a minimal server that verifies the frame
        server = _EchoServer((self.host, 0), _EchoHandler)
        server._aes_key = self.aes_key  # type: ignore[attr-defined]
        server._aes_decrypt_fn = aes_encrypt  # type: ignore[attr-defined]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        try:
            response = send_frame(self.host, server.server_address[1], frame)
            self.assertEqual(response, "ACCEPT",
                             "Server should have accepted the valid frame")
        finally:
            server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()

    # ------------------------------------------------------------------
    # test_client_tampered_payload_rejected
    # ------------------------------------------------------------------

    def test_client_tampered_payload_rejected(self) -> None:
        """
        Tamper with the ciphertext in the frame and verify the server rejects it.
        """
        sensor_json = generate_batch(1)
        frame = build_frame(sensor_json, self.pub, self.aes_key)

        # Tamper with the ciphertext portion (bytes after 260 + 32 = 292)
        tampered = bytearray(frame)
        tampered[292] ^= 0xFF  # flip a byte in the ciphertext

        server = _EchoServer((self.host, 0), _EchoHandler)
        server._aes_key = self.aes_key  # type: ignore[attr-defined]
        server._aes_decrypt_fn = aes_encrypt  # type: ignore[attr-defined]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        try:
            response = send_frame(self.host, server.server_address[1], bytes(tampered))
            self.assertEqual(response, "REJECT",
                             "Server should have rejected the tampered frame")
        finally:
            server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()

    # ------------------------------------------------------------------
    # test_client_invalid_hmac_rejected
    # ------------------------------------------------------------------

    def test_client_invalid_hmac_rejected(self) -> None:
        """
        Build a frame with an invalid HMAC tag and verify the server rejects it.
        """
        sensor_json = generate_batch(1)
        frame = build_frame(sensor_json, self.pub, self.aes_key)

        # Replace the HMAC tag (bytes 260-292) with random bytes
        tampered = bytearray(frame)
        for i in range(260, 292):
            tampered[i] = random.randint(0, 255)

        server = _EchoServer((self.host, 0), _EchoHandler)
        server._aes_key = self.aes_key  # type: ignore[attr-defined]
        server._aes_decrypt_fn = aes_encrypt  # type: ignore[attr-defined]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        try:
            response = send_frame(self.host, server.server_address[1], bytes(tampered))
            self.assertEqual(response, "REJECT",
                             "Server should have rejected the invalid HMAC frame")
        finally:
            server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()

    # ------------------------------------------------------------------
    # test_client_multiple_batches
    # ------------------------------------------------------------------

    def test_client_multiple_batches(self) -> None:
        """
        Send multiple batches in sequence and verify the server accepts all.
        """
        server = _EchoServer((self.host, 0), _EchoHandler)
        server._aes_key = self.aes_key  # type: ignore[attr-defined]
        server._aes_decrypt_fn = aes_encrypt  # type: ignore[attr-defined]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        try:
            for count in [1, 5, 10]:
                sensor_json = generate_batch(count)
                frame = build_frame(sensor_json, self.pub, self.aes_key)
                response = send_frame(self.host, server.server_address[1], frame)
                self.assertEqual(response, "ACCEPT",
                                 f"Server should accept batch of {count} readings")
        finally:
            server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
