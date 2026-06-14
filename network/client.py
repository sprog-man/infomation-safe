"""
network/client.py - TCP Client for Secure Sensor Data Transmission

Generates sensor data, encrypts with AES-128, encrypts the AES session key
with RSA, computes an HMAC-SHA256 authentication tag, and sends the complete
frame to the server.

Client workflow:
  1. Generate or load RSA public key (for encrypting AES session key)
  2. Generate sensor data (JSON string)
  3. Generate a random 16-byte AES session key
  4. Encrypt sensor data with AES-128
  5. Encrypt AES session key with RSA public key
  6. Compute HMAC-SHA256 tag over the ciphertext
  7. Pack frame: [rsa_encrypted_key (256B)] + [hmac_len (4B)] + [hmac_tag (32B)] + [ciphertext]
  8. Send frame to server over TCP
  9. Wait for server response (ACCEPT/REJECT)

This client can be used standalone or invoked as part of the end-to-end pipeline.
"""

import socket
import json
import sys
import os
import time
import random

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.aes_crypto import aes_encrypt, pkcs7_pad
from crypto.rsa_crypto import (
    generate_keypair,
    rsa_encrypt,
    serialize_public_key,
    serialize_private_key,
    deserialize_private_key,
)
from auth.hmac_auth import compute_tag
from data.sensor_data import generate_batch


def load_or_generate_keys(key_path: str = "client_public.key") -> tuple:
    """
    Load the RSA public key from a file, or generate a new key pair.

    In production, the public key would be distributed to the client beforehand
    and the private key kept only on the server.

    Parameters
    ----------
    key_path : str
        Path to the serialized public key file.

    Returns
    -------
    tuple
        (public_key, private_key) dicts. Private key is None if only the
        public key file exists.
    """
    if os.path.isfile(key_path):
        with open(key_path, "rb") as f:
            public_key = deserialize_public_key(f.read())
        return public_key, None
    else:
        # Generate a fresh key pair for development/testing
        public_key, private_key = generate_keypair(2048)
        with open(key_path, "wb") as f:
            f.write(serialize_public_key(public_key))
        with open(key_path.replace("_public.key", "_private.key"), "wb") as f:
            f.write(serialize_private_key(private_key))
        print(f"  Generated new RSA key pair, saved public key to {key_path}")
        return public_key, private_key


def pack_frame(
    encrypted_key: bytes,
    aes_key: bytes,
    ciphertext: bytes,
    hmac_key: bytes = None,
) -> bytes:
    """
    Pack the complete wire frame from its components.

    Frame format:
      [256 bytes] RSA-encrypted AES session key
      [4 bytes]   HMAC tag length (big-endian uint32)
      [32 bytes]  HMAC-SHA256 tag over ciphertext
      [variable]  AES ciphertext

    Parameters
    ----------
    encrypted_key : bytes
        RSA-encrypted AES session key (256 bytes for 2048-bit key).
    aes_key : bytes
        The 16-byte AES session key used to compute the HMAC tag.
    ciphertext : bytes
        AES-encrypted sensor data.
    hmac_key : bytes
        Key used for HMAC computation (defaults to aes_key).

    Returns
    -------
    bytes
        The complete wire frame ready to send over TCP.
    """
    if hmac_key is None:
        hmac_key = aes_key

    # Compute HMAC tag over the ciphertext
    hmac_tag_hex = compute_tag(aes_key, ciphertext)
    hmac_tag_bytes = bytes.fromhex(hmac_tag_hex)

    # Pack: [key][hmac_len][hmac_tag][ciphertext]
    frame = encrypted_key
    frame += len(hmac_tag_bytes).to_bytes(4, "big")
    frame += hmac_tag_bytes
    frame += ciphertext

    return frame


def build_frame(
    sensor_json: str,
    public_key: dict,
    aes_key: bytes = None,
) -> bytes:
    """
    Build the complete encrypted and authenticated frame from sensor data.

    Parameters
    ----------
    sensor_json : str
        JSON string of sensor readings (plaintext).
    public_key : dict
        RSA public key with 'n' and 'e'.
    aes_key : bytes, optional
        16-byte AES key. If None, a random key is generated.

    Returns
    -------
    bytes
        The complete wire frame ready to send over TCP.
    """
    if aes_key is None:
        # Generate a random 16-byte AES session key
        aes_key = bytes(random.getrandbits(8) for _ in range(16))

    # Step 1: Encrypt sensor data with AES-128
    ciphertext = aes_encrypt(sensor_json.encode("utf-8"), aes_key)

    # Step 2: Encrypt the AES session key with RSA public key
    encrypted_key = rsa_encrypt(aes_key, public_key)

    # Step 3: Pack everything into the wire frame
    frame = pack_frame(encrypted_key, aes_key, ciphertext)

    return frame


def send_frame(
    host: str,
    port: int,
    frame: bytes,
    timeout: float = 5.0,
) -> str:
    """
    Send a complete frame to the server and receive the response.

    Parameters
    ----------
    host : str
        Server hostname or IP address.
    port : int
        Server port number.
    frame : bytes
        The complete wire frame to send.
    timeout : float
        Connection timeout in seconds.

    Returns
    -------
    str
        Server response: "ACCEPT" or "REJECT".

    Raises
    ------
    ConnectionError
        If the server cannot be reached or the response is invalid.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        client_sock.settimeout(timeout)
        client_sock.connect((host, port))
        client_sock.sendall(frame)
        # Signal end of transmission
        client_sock.shutdown(socket.SHUT_WR)

        # Read server response
        response = client_sock.recv(4096)
        return response.decode("utf-8", errors="replace")


def run_client(
    host: str = "127.0.0.1",
    port: int = 9999,
    reading_count: int = 5,
    public_key_path: str = "client_public.key",
) -> str:
    """
    Full client workflow: generate data, encrypt, send, get response.

    Parameters
    ----------
    host : str
        Server hostname or IP address.
    port : int
        Server port number.
    reading_count : int
        Number of sensor readings to include in the batch.
    public_key_path : str
        Path to the RSA public key file.

    Returns
    -------
    str
        Server response: "ACCEPT" or "REJECT".
    """
    print(f"[*] Connecting to server at {host}:{port}...")

    # Step 1: Load or generate public key
    print(f"[*] Loading RSA public key from {public_key_path}...")
    public_key, _ = load_or_generate_keys(public_key_path)
    print(f"[*] Public key loaded (modulus: {public_key['n'].bit_length()} bits)")

    # Step 2: Generate sensor data
    print(f"[*] Generating {reading_count} sensor readings...")
    sensor_json = generate_batch(reading_count)
    print(f"[*] Sensor data size: {len(sensor_json)} bytes")

    # Step 3: Build the encrypted+authenticated frame
    print(f"[*] Encrypting data (AES-128 + RSA + HMAC-SHA256)...")
    frame = build_frame(sensor_json, public_key)
    print(f"[*] Frame size: {len(frame)} bytes")

    # Step 4: Send to server
    print(f"[*] Sending frame to server...")
    response = send_frame(host, port, frame)
    print(f"[*] Server response: {response}")

    return response


if __name__ == "__main__":
    # Quick demo: send to a local server
    response = run_client(
        host="127.0.0.1",
        port=9999,
        reading_count=3,
    )
    print(f"\nResult: {response}")
    sys.exit(0 if response == "ACCEPT" else 1)
