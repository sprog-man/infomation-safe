"""
weather_client.py — Weather Data Client Module

Fetches weather data, wraps in HTTP response, and builds encrypted
+ authenticated wire frame using the existing crypto pipeline.

Client workflow:
  1. Fetch weather data via HTTP (OpenWeatherMap API or mock)
  2. Wrap raw weather JSON in HTTP response format
  3. Encrypt entire HTTP response with AES-128
  4. Encrypt AES key with RSA public key
  5. Compute HMAC-SHA256 over ciphertext
  6. Pack wire frame via existing client.build_frame
  7. Return frame + metadata (captured bytes, hashes)
"""

import hashlib
import sys
import os
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.weather_data import fetch_weather, build_http_response, compute_hash
from network.client import build_frame as _build_crypto_frame
from crypto.aes_crypto import aes_encrypt, pkcs7_pad
from crypto.rsa_crypto import rsa_encrypt
from auth.hmac_auth import compute_tag


def build_weather_frame(
    city: str,
    api_key: str,
    public_key: dict,
    aes_key: bytes = None,
) -> dict:
    """
    Build a complete encrypted weather data frame.

    Steps:
      1. Fetch raw weather JSON via HTTP request
      2. Wrap in HTTP response format
      3. AES-128 encrypt entire HTTP response
      4. RSA-2048 encrypt AES key
      5. HMAC-SHA256 tag over ciphertext
      6. Pack into wire frame

    Parameters
    ----------
    city : str
        City name for weather data.
    api_key : str
        OpenWeatherMap API key.
    public_key : dict
        RSA public key {n, e}.
    aes_key : bytes, optional
        16-byte AES key. Auto-generated if None.

    Returns
    -------
    dict
        {
            "frame": bytes,
            "raw_weather_json": str,
            "raw_weather_hex": str,
            "raw_weather_hash": {"md5": str, "sha256": str},
            "http_response_bytes": bytes,
            "http_response_hex": str,
            "http_response_hash": {"md5": str, "sha256": str},
            "aes_key_hex": str,
            "frame_size": int,
            "city": str,
        }
    """
    # Step 1: Fetch weather data (raw JSON)
    raw_json_bytes = fetch_weather(city, api_key)
    raw_json_str = raw_json_bytes.decode("utf-8")

    # Hash of raw weather JSON
    raw_hash = compute_hash(raw_json_bytes)

    # Step 2: Wrap in HTTP response
    http_response_bytes = build_http_response(raw_json_bytes)
    http_response_hex = http_response_bytes.hex()
    http_response_hash = compute_hash(http_response_bytes)

    # Step 3: AES encrypt entire HTTP response
    if aes_key is None:
        aes_key = bytes(random.getrandbits(8) for _ in range(16))
    aes_key_hex = aes_key.hex()
    ciphertext = aes_encrypt(http_response_bytes, aes_key)

    # Step 4: RSA encrypt AES key
    encrypted_key = rsa_encrypt(aes_key, public_key)

    # Step 5: HMAC tag
    hmac_tag_hex = compute_tag(aes_key, ciphertext)

    # Step 6: Pack wire frame using existing build_frame logic
    frame = _build_crypto_frame(raw_json_str, public_key, aes_key)

    # But build_frame encrypts the sensor_json itself. We need to encrypt
    # the HTTP response instead. So we build manually:
    frame = _build_frame_manual(encrypted_key, aes_key, ciphertext, hmac_tag_hex)

    return {
        "frame": frame,
        "raw_weather_json": raw_json_str,
        "raw_weather_hex": raw_json_bytes.hex(),
        "raw_weather_hash": raw_hash,
        "http_response_bytes": http_response_bytes,
        "http_response_hex": http_response_hex,
        "http_response_hash": http_response_hash,
        "aes_key_hex": aes_key_hex,
        "hmac_tag_hex": hmac_tag_hex,
        "encrypted_key_hex": encrypted_key.hex(),
        "frame_size": len(frame),
        "city": city,
    }


def _build_frame_manual(
    encrypted_key: bytes,
    aes_key: bytes,
    ciphertext: bytes,
    hmac_tag_hex: str,
) -> bytes:
    """
    Pack wire frame: [rsa_encrypted_key] + [hmac_len] + [hmac_tag] + [ciphertext]

    Mirrors network.client.pack_frame logic directly to avoid double encryption.
    """
    hmac_tag_bytes = bytes.fromhex(hmac_tag_hex)

    frame = encrypted_key
    frame += len(hmac_tag_bytes).to_bytes(4, "big")
    frame += hmac_tag_bytes
    frame += ciphertext

    return frame


def capture_frame_info(frame: bytes) -> dict:
    """
    Capture metadata about a wire frame for display.

    Parameters
    ----------
    frame : bytes
        The complete wire frame.

    Returns
    -------
    dict
        {
            "frame_size": int,
            "hex_preview": str,
            "md5": str,
            "sha256": str,
        }
    """
    return {
        "frame_size": len(frame),
        "hex_preview": frame.hex()[:200],
        **compute_hash(frame),
    }
