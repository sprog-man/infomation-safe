"""
main.py - Entry point for the Information Safety Experiment

Runs the complete end-to-end pipeline:
  1. Simulate sensor data collection
  2. Encrypt data with AES-128
  3. Encrypt AES session key with RSA-2048
  4. Compute HMAC-SHA256 authentication tag
  5. Send encrypted frame via TCP (client)
  6. Server receives, verifies, decrypts, and outputs original data

All components run locally with no external dependencies.
Requires a server running on 127.0.0.1:9999.

Usage: python main.py
"""

import sys
import os
import time
import json
import threading
import socket
import socketserver

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.sensor_data import generate_batch
from crypto.aes_crypto import aes_encrypt, aes_decrypt
from crypto.rsa_crypto import generate_keypair, rsa_encrypt, rsa_decrypt
from auth.hmac_auth import compute_tag, verify_tag
from network.client import build_frame, send_frame, load_or_generate_keys
from network.server import (
    load_private_key,
    receive_frame,
    handle_client,
)


# ---------------------------------------------------------------------------
# Minimal socket handler for local E2E — reuses server logic
# ---------------------------------------------------------------------------

class _E2EHandler(socketserver.BaseRequestHandler):
    """
    A socketserver handler that processes one client connection using the
    server's handle_client function. The private key is stored on the server
    instance via an attribute set before calling serve_forever.
    """

    def handle(self) -> None:
        """Process one client: receive, verify, decrypt, output."""
        handle_client(self.request, self.server._private_key)  # type: ignore[attr-defined]


class _E2EServer(socketserver.TCPServer):
    """A TCP server that accepts exactly one connection, then shuts down."""

    allow_reuse_address = True

    def __init__(self, server_address: tuple, private_key: dict) -> None:
        super().__init__(server_address, _E2EHandler)
        self._private_key = private_key


def run_client_in_thread(host: str, port: int,
                         public_key: dict, reading_count: int = 3) -> str:
    """
    Build and send an encrypted frame from the client side.

    Parameters
    ----------
    host : str
        Server hostname.
    port : int
        Server port.
    public_key : dict
        RSA public key {n, e}.
    reading_count : int
        Number of sensor readings to include.

    Returns
    -------
    str
        Server response: "ACCEPT" or "REJECT".
    """
    print(f"\n{'=' * 60}")
    print("[CLIENT] Step 1: Generating sensor data...")
    sensor_json = generate_batch(reading_count)
    print(f"[CLIENT] Sensor data: {reading_count} readings, "
          f"{len(sensor_json)} bytes")

    print(f"[CLIENT] Step 2: Encrypting with AES-128...")
    # Use a deterministic key for demonstration consistency
    aes_key = b"MySessKey1234567"
    ciphertext = aes_encrypt(sensor_json.encode("utf-8"), aes_key)
    print(f"[CLIENT] Ciphertext: {len(ciphertext)} bytes")

    print(f"[CLIENT] Step 3: Encrypting AES key with RSA-2048...")
    encrypted_key = rsa_encrypt(aes_key, public_key)
    print(f"[CLIENT] RSA-encrypted key: {len(encrypted_key)} bytes")

    print(f"[CLIENT] Step 4: Computing HMAC-SHA256 tag...")
    hmac_tag_hex = compute_tag(aes_key, ciphertext)
    print(f"[CLIENT] HMAC tag: {hmac_tag_hex[:32]}...")

    print(f"[CLIENT] Step 5: Building wire frame...")
    frame = build_frame(sensor_json, public_key, aes_key)
    print(f"[CLIENT] Frame size: {len(frame)} bytes")

    print(f"[CLIENT] Step 6: Connecting to server at {host}:{port}...")
    response = send_frame(host, port, frame)
    print(f"[CLIENT] Server response: {response}")

    return response


def run_local_e2e(reading_count: int = 3) -> bool:
    """
    Run a complete local end-to-end test: generate keys, encrypt data,
    send via TCP client, receive and verify via server.

    This demonstrates the full pipeline without requiring separate
    client and server processes.

    Parameters
    ----------
    reading_count : int
        Number of sensor readings to generate.

    Returns
    -------
    bool
        True if the roundtrip was successful.
    """
    print(f"\n{'#':>60}")
    print("#" + " Information Safety Experiment - End-to-End Pipeline ".center(58) + "#")
    print(f"{'#':>60}")
    print()

    # --- Phase 1: Key Generation ---
    print("[*] Phase 1: Generating RSA-2048 key pair...")
    start = time.monotonic()
    public_key, private_key = generate_keypair(2048)
    elapsed = time.monotonic() - start
    print(f"  [OK] Key pair generated in {elapsed:.1f}s")
    print(f"       Modulus: {public_key['n'].bit_length()} bits")
    print(f"       Public exponent: {public_key['e']}")
    print()

    # --- Phase 2: Sensor Data Simulation ---
    print("[*] Phase 2: Sensor data simulation...")
    sensor_json = generate_batch(reading_count)
    sensor_data = json.loads(sensor_json)
    print(f"  [OK] Generated {reading_count} readings")
    print(f"       Batch ID: {sensor_data['batch_id']}")
    print(f"       Generated at: {sensor_data['generated_at']}")
    print()

    # --- Phase 3: AES-128 Encryption ---
    print("[*] Phase 3: AES-128 encryption...")
    aes_key = b"MySessKey1234567"
    ciphertext = aes_encrypt(sensor_json.encode("utf-8"), aes_key)
    print(f"  [OK] Encrypted {len(sensor_json)} -> {len(ciphertext)} bytes")
    print()

    # --- Phase 4: RSA Key Encryption ---
    print("[*] Phase 4: RSA-2048 session key encryption...")
    encrypted_key = rsa_encrypt(aes_key, public_key)
    print(f"  [OK] AES key encrypted: 16 -> {len(encrypted_key)} bytes")
    print()

    # --- Phase 5: HMAC-SHA256 Authentication ---
    print("[*] Phase 5: HMAC-SHA256 authentication tag...")
    hmac_tag_hex = compute_tag(aes_key, ciphertext)
    print(f"  [OK] Tag: {hmac_tag_hex}")
    print()

    # --- Phase 6: TCP Client-Server Transmission ---
    print("[*] Phase 6: TCP transmission...")

    # Start server in a background thread
    server = _E2EServer(("127.0.0.1", 0), private_key)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)
    server_port = server.server_address[1]

    try:
        response = run_client_in_thread("127.0.0.1", server_port, public_key, reading_count)
    finally:
        server.shutdown()
        server_thread.join(timeout=5)
        server.server_close()

    if response == "ACCEPT":
        print()
        print("[OK] End-to-end pipeline completed successfully!")
        return True
    else:
        print()
        print("[FAIL] Server rejected the frame!")
        return False


def run_standalone_demo() -> None:
    """
    Run a standalone demo of the full pipeline without a server.

    Demonstrates: generate → encrypt → decrypt → verify → output.
    """
    print(f"\n{'=' * 60}")
    print(" Standalone Demo (no server required)")
    print(f"{'=' * 60}")

    # Generate keys
    print("\n[1] Generating RSA-2048 key pair...")
    public_key, private_key = generate_keypair(2048)

    # Generate sensor data
    print("[2] Generating sensor data...")
    sensor_json = generate_batch(3)
    print(f"    Original JSON: {sensor_json[:80]}...")

    # Encrypt
    print("[3] Encrypting with AES-128...")
    aes_key = b"MySessKey1234567"
    ciphertext = aes_encrypt(sensor_json.encode("utf-8"), aes_key)
    print(f"    Ciphertext: {len(ciphertext)} bytes")

    # Encrypt session key
    print("[4] Encrypting AES key with RSA-2048...")
    encrypted_key = rsa_encrypt(aes_key, public_key)
    print(f"    Encrypted key: {len(encrypted_key)} bytes")

    # Authenticate
    print("[5] Computing HMAC-SHA256...")
    hmac_tag = compute_tag(aes_key, ciphertext)
    print(f"    Tag: {hmac_tag[:32]}...")

    # Verify HMAC
    print("[6] Verifying HMAC...")
    valid = verify_tag(aes_key, ciphertext, hmac_tag)
    print(f"    Valid: {valid}")

    # Decrypt session key
    print("[7] Decrypting AES key with RSA...")
    decrypted_key = rsa_decrypt(encrypted_key, private_key)
    assert decrypted_key == aes_key, "RSA decryption failed!"
    print(f"    Key restored: {decrypted_key == aes_key}")

    # Decrypt data
    print("[8] Decrypting sensor data...")
    plaintext = aes_decrypt(ciphertext, decrypted_key)
    decrypted_json = plaintext.decode("utf-8")
    print(f"    Decrypted: {decrypted_json[:80]}...")

    # Verify roundtrip
    print("[9] Verifying roundtrip...")
    original = json.loads(sensor_json)
    restored = json.loads(decrypted_json)
    assert original == restored, "Roundtrip failed!"
    print("    [OK] Roundtrip verified!")


def main() -> None:
    """
    Main entry point. Runs both standalone demo and E2E pipeline.

    The standalone demo works without a server (pure crypto verification).
    The E2E pipeline requires a server listening on 127.0.0.1:9999.

    Usage:
        python main.py             # Run full pipeline
        python main.py --demo      # Run standalone demo only
        python main.py --e2e       # Run E2E pipeline only
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Information Safety Experiment - End-to-End Pipeline",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run standalone demo (no server required)",
    )
    parser.add_argument(
        "--e2e", action="store_true",
        help="Run end-to-end pipeline (requires server)",
    )
    parser.add_argument(
        "--readings", type=int, default=3,
        help="Number of sensor readings (default: 3)",
    )
    args = parser.parse_args()

    if args.demo or args.e2e:
        if args.demo:
            run_standalone_demo()
        if args.e2e:
            success = run_local_e2e(args.readings)
            sys.exit(0 if success else 1)
    else:
        # Default: run both
        run_standalone_demo()
        run_local_e2e(args.readings)


if __name__ == "__main__":
    main()
