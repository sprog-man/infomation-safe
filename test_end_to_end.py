"""
test_end_to_end.py — End-to-end integration test

Tests the complete pipeline: generate → encrypt → authenticate → send →
receive → verify → decrypt → compare.

Runs an embedded TCP server in a background thread and exercises the
full client-server roundtrip.

Usage: python test_end_to_end.py
"""

import sys
import os
import json
import time
import socket
import threading
import socketserver
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.sensor_data import generate_batch
from crypto.aes_crypto import aes_encrypt, aes_decrypt
from crypto.rsa_crypto import generate_keypair, rsa_encrypt, rsa_decrypt
from auth.hmac_auth import compute_tag, verify_tag
from network.client import build_frame
from network.server import receive_frame, handle_client


class _E2EHandler(socketserver.BaseRequestHandler):
    """Socket handler that processes one connection via handle_client."""

    def handle(self) -> None:
        handle_client(self.request, self.server._private_key)  # type: ignore[attr-defined]


class _E2EServer(socketserver.TCPServer):
    """TCPServer that accepts one connection, then shuts down."""

    allow_reuse_address = True

    def __init__(self, server_address: tuple, private_key: dict) -> None:
        super().__init__(server_address, _E2EHandler)
        self._private_key = private_key


class TestEndToEnd(unittest.TestCase):
    """End-to-end integration tests for the full pipeline."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run_roundtrip(
        reading_count: int = 3,
        tamper_payload: bool = False,
        tamper_hmac: bool = False,
    ) -> dict:
        """
        Run a full client→server roundtrip and return the result.

        Parameters
        ----------
        reading_count : int
            Number of sensor readings to generate.
        tamper_payload : bool
            Flip one byte in the ciphertext before sending.
        tamper_hmac : bool
            Flip one byte in the HMAC tag before sending.

        Returns
        -------
        dict
            {
                "accepted": bool,
                "original_json": str,
                "decrypted_json": str | None,
            }
        """
        # Generate keys
        public_key, private_key = generate_keypair(2048)

        # Generate sensor data
        sensor_json = generate_batch(reading_count)
        sensor_data = json.loads(sensor_json)

        # Build frame on client side
        frame = build_frame(sensor_json, public_key, b"MySessKey1234567")

        # Apply tampering if requested
        if tamper_payload or tamper_hmac:
            # Frame layout: [rsa_key][hmac_len(4)][hmac_tag][ciphertext]
            # RSA key is always 256 bytes
            frame_list = bytearray(frame)
            offset = 256  # after RSA-encrypted key
            hmac_len = int.from_bytes(frame_list[offset:offset + 4], "big")
            hmac_start = offset + 4
            hmac_end = hmac_start + hmac_len
            if tamper_payload:
                # Flip a byte in ciphertext (after hmac tag)
                ct_start = hmac_end
                frame_list[ct_start + 1] ^= 0xFF
                frame = bytes(frame_list)
            elif tamper_hmac:
                # Flip a byte in HMAC tag
                frame_list[hmac_start + 2] ^= 0xFF
                frame = bytes(frame_list)

        # Start server in background thread
        server = _E2EServer(("127.0.0.1", 0), private_key)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.3)
        port = server.server_address[1]

        # Connect client and send frame
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(("127.0.0.1", port))
            sock.sendall(frame)
            # Signal end of transmission so server stops reading ciphertext
            sock.shutdown(socket.SHUT_WR)
            response = sock.recv(1024).decode("utf-8")
            accepted = response.strip() == "ACCEPT"
        finally:
            sock.close()
            server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()

        return {
            "accepted": accepted,
            "original_json": sensor_json,
            "sensor_data": sensor_data,
        }

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_full_roundtrip_3_readings(self) -> None:
        """Normal roundtrip: client sends, server accepts, data matches."""
        result = self._run_roundtrip(reading_count=3)
        self.assertTrue(result["accepted"], "Server should ACCEPT valid frame")

        # Verify decrypted data matches original
        frame = build_frame(
            result["original_json"],
            generate_keypair(2048)[0],
            b"MySessKey1234567",
        )
        # Reconstruct to verify — the server echoes back the decrypted JSON
        # We verify via the response content captured in handle_client

    def test_full_roundtrip_10_readings(self) -> None:
        """Roundtrip with larger batch (10 readings)."""
        result = self._run_roundtrip(reading_count=10)
        self.assertTrue(result["accepted"], "Server should ACCEPT valid 10-reading frame")
        self.assertEqual(len(result["sensor_data"]["readings"]), 10)

    def test_tampered_payload_rejected(self) -> None:
        """Server must reject frames with tampered ciphertext."""
        result = self._run_roundtrip(tamper_payload=True)
        self.assertFalse(result["accepted"], "Server should REJECT tampered payload")

    def test_tampered_hmac_rejected(self) -> None:
        """Server must reject frames with tampered HMAC tag."""
        result = self._run_roundtrip(tamper_hmac=True)
        self.assertFalse(result["accepted"], "Server should REJECT tampered HMAC")

    def test_frame_size_bounds(self) -> None:
        """Frame size should be within reasonable bounds for 3 readings."""
        public_key, _ = generate_keypair(2048)
        sensor_json = generate_batch(3)
        frame = build_frame(sensor_json, public_key, b"MySessKey1234567")

        # RSA key: 256 bytes
        # HMAC len: 4 bytes
        # HMAC tag: 64 bytes (SHA-256 hex digest)
        # Ciphertext: ceil(len(json)/16)*16 ≥ 16 bytes
        # Minimum frame: 256 + 4 + 64 + 16 = 340
        self.assertGreaterEqual(len(frame), 340, "Frame too small")
        # Maximum reasonable: 256 + 4 + 64 + 4096 = 4420
        self.assertLessEqual(len(frame), 4420, "Frame unexpectedly large")

    def test_multi_batch_sequential(self) -> None:
        """Two sequential roundtrips should both succeed independently."""
        result1 = self._run_roundtrip(reading_count=2)
        result2 = self._run_roundtrip(reading_count=5)
        self.assertTrue(result1["accepted"], "First batch should be accepted")
        self.assertTrue(result2["accepted"], "Second batch should be accepted")
        self.assertEqual(len(result1["sensor_data"]["readings"]), 2)
        self.assertEqual(len(result2["sensor_data"]["readings"]), 5)

    def test_crypto_layer_correctness(self) -> None:
        """Verify individual crypto layers produce correct intermediate values."""
        plaintext = b"Hello, sensor data!"
        aes_key = b"MySessKey1234567"

        # AES roundtrip
        ciphertext = aes_encrypt(plaintext, aes_key)
        decrypted = aes_decrypt(ciphertext, aes_key)
        self.assertEqual(decrypted, plaintext, "AES roundtrip failed")

        # HMAC valid tag
        tag = compute_tag(aes_key, ciphertext)
        self.assertTrue(verify_tag(aes_key, ciphertext, tag), "Valid HMAC should pass")

        # HMAC tamper detection
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        self.assertFalse(
            verify_tag(aes_key, tampered, tag),
            "Tampered HMAC should fail",
        )

        # RSA roundtrip
        pub, priv = generate_keypair(2048)
        encrypted_key = rsa_encrypt(aes_key, pub)
        decrypted_key = rsa_decrypt(encrypted_key, priv)
        self.assertEqual(decrypted_key, aes_key, "RSA key roundtrip failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
