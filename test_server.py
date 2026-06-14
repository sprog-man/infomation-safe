"""
test_server.py - Validate the TCP server's end-to-end secure data reception.

Tests the full server receive/verify/decrypt pipeline by spawning a real
server thread, connecting a simulated client, and verifying the output.

Run with: python test_server.py

Expects all assertions to pass (no output on success).
Prints summary on completion.
"""

import io
import json
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

from network.server import receive_frame, handle_client, load_private_key


# ---------------------------------------------------------------------------
# Helper: simulate a client that packs and sends the wire frame
# ---------------------------------------------------------------------------

def _pack_and_send(conn: socket.socket, sensor_json: str, private_key: dict,
                   tamper_ciphertext: bool = False,
                   tamper_hmac: bool = False) -> None:
    """
    Simulate what a real client does: generate sensor data, encrypt with AES,
    encrypt the AES key with RSA, compute HMAC over ciphertext, pack into the
    wire format and send over the given socket connection.

    Parameters
    ----------
    conn : socket.socket
        Active connection to send data on.
    sensor_json : str
        JSON string of sensor readings (plaintext).
    private_key : dict
        RSA private key (used only to derive the public key from keypair).
    tamper_ciphertext : bool
        If True, flip a byte in the ciphertext before sending.
    tamper_hmac : bool
        If True, compute HMAC over different data (invalidates the tag).
    """
    # 1. Generate a fixed 16-byte AES session key
    aes_key = b"0123456789ABCDEF"

    # 2. Encrypt the sensor data with AES
    ciphertext = aes_encrypt(sensor_json.encode("utf-8"), aes_key)

    # 3. Encrypt the AES key with the RSA public key
    # Derive the public key from the private key (n, e=65537).
    pub_key = {"n": private_key["n"], "e": 65537}
    encrypted_aes_key = rsa_encrypt(aes_key, pub_key)

    # 4. Compute HMAC-SHA256 tag over the ciphertext
    if tamper_hmac:
        # Compute HMAC over wrong data so server verification fails
        hmac_tag_hex = compute_tag(aes_key, b"wrong data for hmac")
    else:
        hmac_tag_hex = compute_tag(aes_key, ciphertext)

    # 5. Optionally tamper the ciphertext
    if tamper_ciphertext:
        ct_list = bytearray(ciphertext)
        ct_list[0] ^= 0xFF  # flip first byte
        ciphertext = bytes(ct_list)

    # 6. Pack into wire format and send over the socket
    # [key_bytes] RSA-encrypted AES session key
    conn.sendall(encrypted_aes_key)

    # [4 bytes] HMAC tag length (big-endian uint32)
    hmac_len = len(bytes.fromhex(hmac_tag_hex))
    conn.sendall(hmac_len.to_bytes(4, "big"))

    # [HMAC bytes] HMAC-SHA256 tag (32 bytes for SHA-256)
    conn.sendall(bytes.fromhex(hmac_tag_hex))

    # [variable] AES ciphertext (remaining data until connection close)
    conn.sendall(ciphertext)

    # Signal end of transmission so server stops reading
    conn.shutdown(socket.SHUT_WR)


# ---------------------------------------------------------------------------
# Test server that runs handle_client for a single client connection
# ---------------------------------------------------------------------------

class _ClientHandler(socketserver.BaseRequestHandler):
    """
    A socket server request handler that calls handle_client for each
    connection, using the private key passed in via the server instance.
    """

    def handle(self) -> None:
        """Process one client: receive, verify, decrypt, output."""
        # self.request is the connected client socket
        handle_client(self.request, self.server._private_key)  # type: ignore[attr-defined]


class _TestServer(socketserver.TCPServer):
    """
    A TCP server that accepts exactly one connection, then shuts down.
    Uses allow_reuse_address so tests can quickly rebind the same port.
    """

    allow_reuse_address = True

    def __init__(self, server_address: tuple, private_key: dict) -> None:
        super().__init__(server_address, _ClientHandler)
        self._private_key = private_key


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestServerReceive(unittest.TestCase):
    """Tests for the server's end-to-end secure data reception."""

    # Generate a 2048-bit RSA key pair once for all tests.
    # The server's receive_frame defaults to key_bytes=256 (2048-bit),
    # so we must use matching key sizes.
    @classmethod
    def setUpClass(cls) -> None:
        """Generate a 2048-bit RSA key pair for all test methods."""
        start = time.monotonic()
        cls.pub, cls.priv = generate_keypair(2048)
        elapsed = time.monotonic() - start
        print(f"\n[INFO] Generated 2048-bit RSA key pair in {elapsed:.1f}s",
              file=sys.stderr)

    def setUp(self) -> None:
        """Store connection parameters for each test."""
        self.aes_key = b"0123456789ABCDEF"
        self.host = "127.0.0.1"

    # ------------------------------------------------------------------
    # test_complete_roundtrip
    # ------------------------------------------------------------------

    def test_complete_roundtrip(self) -> None:
        """
        Spawn server thread, connect with simulated client, verify the
        server receives and correctly decrypts the original sensor data.
        """
        # Generate test sensor data (3 readings)
        sensor_json = generate_batch(3)

        # Start the server in a background thread
        server = _TestServer((self.host, 0), self.priv)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        # Give the server time to bind and start listening
        time.sleep(0.2)

        # Capture stdout and create a client socket to read server responses
        original_stdout = sys.stdout
        capture = io.StringIO()

        try:
            sys.stdout = capture
            # Connect as a simulated client and send the encrypted frame
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(5.0)
                client_sock.connect((self.host, server.server_address[1]))
                _pack_and_send(client_sock, sensor_json, self.priv)

                # Read the server's response (ACCEPT or REJECT)
                response = client_sock.recv(4096)

            # Wait for the server to finish processing this connection
            server.shutdown()
            server_thread.join(timeout=5)
        finally:
            sys.stdout = original_stdout
            server.server_close()

        output = capture.getvalue()

        # Verify the server printed the success message and sent ACCEPT
        self.assertIn("[OK]", output,
                      "Server should have printed [OK] for valid data")
        self.assertEqual(response, b"ACCEPT",
                         "Server should have sent ACCEPT response")

        # Parse the decrypted JSON from the server's multi-line output.
        # The server prints json.dumps(data, indent=2) which spans multiple
        # lines. Extract the JSON block between the first '{' and last '}'.
        lines = output.splitlines()
        json_lines = []
        in_json = False
        for line in lines:
            if "{" in line and not in_json:
                in_json = True
            if in_json:
                json_lines.append(line)
        json_text = "\n".join(json_lines)
        received_data = json.loads(json_text)

        original_parsed = json.loads(sensor_json)
        self.assertEqual(received_data["reading_count"], 3)
        self.assertEqual(
            received_data["readings"], original_parsed["readings"],
            "Decrypted sensor data must match the original",
        )

    # ------------------------------------------------------------------
    # test_tampered_message_rejected
    # ------------------------------------------------------------------

    def test_tampered_message_rejected(self) -> None:
        """
        Simulate a client sending a frame where the ciphertext has been
        modified in transit. The server must reject the message.
        """
        sensor_json = generate_batch(1)

        server = _TestServer((self.host, 0), self.priv)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        original_stdout = sys.stdout
        capture = io.StringIO()

        try:
            sys.stdout = capture
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(5.0)
                client_sock.connect((self.host, server.server_address[1]))
                _pack_and_send(client_sock, sensor_json, self.priv,
                               tamper_ciphertext=True)

                # Read the server's response (ACCEPT or REJECT)
                response = client_sock.recv(4096)

            server.shutdown()
            server_thread.join(timeout=5)
        finally:
            sys.stdout = original_stdout
            server.server_close()

        output = capture.getvalue()

        # Verify the server rejected the tampered data
        self.assertIn("[FAIL]", output,
                      "Server should have printed [FAIL] for tampered data")
        self.assertIn("HMAC verification failed", output,
                      "Server should report HMAC verification failure")
        self.assertEqual(response, b"REJECT",
                         "Server should have sent REJECT response")

    # ------------------------------------------------------------------
    # test_invalid_hmac_rejected
    # ------------------------------------------------------------------

    def test_invalid_hmac_rejected(self) -> None:
        """
        Simulate a client sending a frame with an HMAC tag that was
        computed over wrong data. The server must reject the message.
        """
        sensor_json = generate_batch(1)

        server = _TestServer((self.host, 0), self.priv)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        original_stdout = sys.stdout
        capture = io.StringIO()

        try:
            sys.stdout = capture
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(5.0)
                client_sock.connect((self.host, server.server_address[1]))
                _pack_and_send(client_sock, sensor_json, self.priv,
                               tamper_hmac=True)

                # Read the server's response (ACCEPT or REJECT)
                response = client_sock.recv(4096)

            server.shutdown()
            server_thread.join(timeout=5)
        finally:
            sys.stdout = original_stdout
            server.server_close()

        output = capture.getvalue()

        # Verify the server rejected the invalid HMAC
        self.assertIn("[FAIL]", output,
                      "Server should have printed [FAIL] for invalid HMAC")
        self.assertIn("HMAC verification failed", output,
                      "Server should report HMAC verification failure")
        self.assertEqual(response, b"REJECT",
                         "Server should have sent REJECT response")

    # ------------------------------------------------------------------
    # test_multiple_readings
    # ------------------------------------------------------------------

    def test_multiple_readings(self) -> None:
        """
        Send a batch with 10 sensor readings. Verify the server receives
        and decrypts all readings correctly.
        """
        sensor_json = generate_batch(10)

        server = _TestServer((self.host, 0), self.priv)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.2)

        original_stdout = sys.stdout
        capture = io.StringIO()

        try:
            sys.stdout = capture
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(5.0)
                client_sock.connect((self.host, server.server_address[1]))
                _pack_and_send(client_sock, sensor_json, self.priv)

                # Read the server's response (ACCEPT or REJECT)
                response = client_sock.recv(4096)

            server.shutdown()
            server_thread.join(timeout=5)
        finally:
            sys.stdout = original_stdout
            server.server_close()

        output = capture.getvalue()

        # Verify the server accepted the multi-reading batch
        self.assertIn("[OK]", output,
                      "Server should have printed [OK] for valid data")
        self.assertEqual(response, b"ACCEPT",
                         "Server should have sent ACCEPT response")

        # Parse the decrypted JSON and verify reading count.
        # The server prints json.dumps(data, indent=2) which spans multiple
        # lines. Extract the JSON block between the first '{' and last '}'.
        json_lines = []
        in_json = False
        for line in output.splitlines():
            if "{" in line and not in_json:
                in_json = True
            if in_json:
                json_lines.append(line)
        json_text = "\n".join(json_lines)
        received_data = json.loads(json_text)

        original_parsed = json.loads(sensor_json)
        self.assertEqual(received_data["reading_count"], 10,
                         "Server should have received 10 readings")
        self.assertEqual(
            received_data["readings"], original_parsed["readings"],
            "All 10 readings must match the original",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
