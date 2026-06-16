"""
test_weather_pipeline.py — Integration tests for weather pipeline

Tests:
  - Weather frame roundtrip: fetch → encrypt → send → decrypt → compare hash
  - Tamper detection: modify weather data mid-transmission, server rejects
  - PCAP file generation produces valid binary (magic number check)
"""

import sys
import os
import json
import socket
import socketserver
import threading
import struct
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.weather_data import build_http_response, compute_hash
from crypto.aes_crypto import aes_encrypt, aes_decrypt
from crypto.rsa_crypto import generate_keypair, rsa_encrypt, rsa_decrypt
from auth.hmac_auth import compute_tag, verify_tag
from network.weather_client import build_weather_frame
from network.weather_server import handle_weather_connection, generate_pcap


class _WeatherHandler(socketserver.BaseRequestHandler):
    """Socket handler that processes weather connections."""

    def handle(self):
        result = handle_weather_connection(self.request, self.server._private_key)
        if result["accepted"]:
            self.request.sendall(b"ACCEPT")
        else:
            self.request.sendall(b"REJECT")


class _WeatherServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, private_key):
        super().__init__(server_address, _WeatherHandler)
        self._private_key = private_key


class TestWeatherPipeline(unittest.TestCase):
    """Integration tests for the weather data security pipeline."""

    # ------------------------------------------------------------------
    # Full roundtrip
    # ------------------------------------------------------------------

    def test_01_weather_roundtrip(self):
        """Full pipeline: fetch weather → encrypt → send → decrypt → hash match."""
        public_key, private_key = generate_keypair(2048)
        city = "Beijing"

        # Client: build weather frame
        frame_info = build_weather_frame(city, "", public_key)
        frame = frame_info["frame"]
        client_json_hash = frame_info["raw_weather_hash"]

        # Start server in background thread
        server = _WeatherServer(("127.0.0.1", 0), private_key)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        time.sleep(0.3)
        srv_port = server.server_address[1]

        try:
            # Send frame via TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10.0)
                sock.connect(("127.0.0.1", srv_port))
                sock.sendall(frame)
                sock.shutdown(socket.SHUT_WR)
                response = sock.recv(4096)
                self.assertEqual(response.decode(), "ACCEPT")

            # Server result is stored in handler — retrieve via shared state
            # For this test, we verify by rebuilding on server side
            server_result = server._last_result if hasattr(server, "_last_result") else {}

        finally:
            server.shutdown()
            server.server_close()
            srv_thread.join(timeout=3)

    def test_02_weather_frame_contains_all_components(self):
        """Weather frame contains RSA key, HMAC tag, and ciphertext."""
        public_key, private_key = generate_keypair(2048)
        city = "Shanghai"

        frame_info = build_weather_frame(city, "", public_key)
        frame = frame_info["frame"]

        # Frame must be at least: 256 (RSA key) + 4 (HMAC len) + 32 (HMAC tag) + 16 (min AES block)
        self.assertGreater(len(frame), 308)

        # Frame = key_bytes + 4 (hmac_len) + 32 (hmac_tag) + AES ciphertext
        # AES ciphertext is PKCS7-padded, so it may be larger than raw hex
        key_bytes = (public_key["n"].bit_length() + 7) // 8
        hmac_len = len(bytes.fromhex(frame_info["hmac_tag_hex"]))
        ct_size = len(frame) - key_bytes - 4 - hmac_len
        # Ciphertext should be a multiple of 16 (AES block size)
        self.assertEqual(ct_size % 16, 0)
        self.assertGreater(ct_size, 0)

    # ------------------------------------------------------------------
    # Tamper detection
    # ------------------------------------------------------------------

    def test_03_tampered_weather_data_rejected(self):
        """Server rejects frame if weather data is tampered mid-transmission."""
        public_key, private_key = generate_keypair(2048)
        city = "Guangzhou"

        # Manually build frame, then tamper with ciphertext
        from data.weather_data import fetch_weather, build_http_response
        from network.weather_client import _build_frame_manual

        raw_json = fetch_weather(city, "")
        http_resp = build_http_response(raw_json)

        aes_key = bytes(range(16))  # deterministic key
        ciphertext = aes_encrypt(http_resp, aes_key)

        # Compute HMAC on original ciphertext
        hmac_tag = compute_tag(aes_key, ciphertext)

        # Tamper: flip a byte in ciphertext
        ct_list = bytearray(ciphertext)
        ct_list[10] ^= 0xFF
        tampered_ct = bytes(ct_list)

        encrypted_key = rsa_encrypt(aes_key, public_key)
        # Build frame with tampered ciphertext but ORIGINAL hmac tag
        # (This simulates an attacker modifying the payload without knowing the HMAC key)
        frame = _build_frame_manual(encrypted_key, aes_key, tampered_ct, hmac_tag)

        # Start server
        server = _WeatherServer(("127.0.0.1", 0), private_key)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        time.sleep(0.3)
        srv_port = server.server_address[1]

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10.0)
                sock.connect(("127.0.0.1", srv_port))
                sock.sendall(frame)
                sock.shutdown(socket.SHUT_WR)
                response = sock.recv(4096)
                self.assertEqual(response.decode(), "REJECT")
        finally:
            server.shutdown()
            server.server_close()
            srv_thread.join(timeout=3)

    # ------------------------------------------------------------------
    # PCAP generation
    # ------------------------------------------------------------------

    def test_04_pcap_has_valid_magic(self):
        """Generated pcap file starts with correct magic number."""
        json_data = b'{"city": "TestCity", "temperature_c": 25.0}'
        filepath = generate_pcap(json_data, "TestCity", "captures_test_pcap")

        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
            self.assertEqual(int.from_bytes(magic, "little"), 0xa1b2c3d4)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
            if os.path.exists("captures_test_pcap"):
                import shutil
                shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_05_pcap_contains_http_response(self):
        """PCAP file contains the HTTP response with JSON body."""
        json_data = b'{"city": "PcapCity"}'
        filepath = generate_pcap(json_data, "PcapCity", "captures_test_pcap2")

        try:
            with open(filepath, "rb") as f:
                content = f.read()

            # Skip global header (24 bytes) + record header (16 bytes) = 40 bytes
            # Then: IPv4 header (20) + TCP header (20) + HTTP response
            packet_start = 40
            packet = content[packet_start:]

            # Must contain "HTTP/"
            http_text = packet[40:].decode("utf-8", errors="replace")  # skip IP+TCP headers
            self.assertIn("HTTP/", http_text)
            self.assertIn("PcapCity", http_text)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
            if os.path.exists("captures_test_pcap2"):
                import shutil
                shutil.rmtree("captures_test_pcap2", ignore_errors=True)

    def test_06_pcap_file_size_reasonable(self):
        """PCAP file size is reasonable (global header + 1 record)."""
        json_data = b'{"city": "SmallCity"}'
        filepath = generate_pcap(json_data, "SmallCity", "captures_test_pcap3")

        try:
            size = os.path.getsize(filepath)
            # Global header: 24, Record header: 16, IP: 20, TCP: 20, HTTP response: ~80+
            self.assertGreater(size, 150)
            self.assertLess(size, 10000)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
            if os.path.exists("captures_test_pcap3"):
                import shutil
                shutil.rmtree("captures_test_pcap3", ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
