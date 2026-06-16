"""
weather_server.py — Weather Data Server Module

Receives encrypted weather frames, verifies HMAC, decrypts AES key
with RSA, decrypts ciphertext, extracts HTTP response + JSON body,
and generates Wireshark-compatible .pcap files.

Server workflow:
  1. Receive wire frame from TCP
  2. RSA decrypt AES session key
  3. Verify HMAC tag
  4. AES decrypt ciphertext
  5. Parse HTTP response to extract JSON body
  6. Generate .pcap file with HTTP response payload
  7. Return structured result
"""

import socket
import json
import os
import struct
import time

from crypto.rsa_crypto import rsa_decrypt
from crypto.aes_crypto import aes_decrypt
from auth.hmac_auth import verify_tag


def handle_weather_connection(conn, private_key):
    """
    Handle one weather data connection: receive frame, verify, decrypt, parse.

    Parameters
    ----------
    conn : socket.socket
        Connected client socket.
    private_key : dict
        RSA private key {n, d}.

    Returns
    -------
    dict
        {
            "accepted": bool,
            "http_response_bytes": bytes,
            "http_response_hex": str,
            "json_data": dict | None,
            "json_hex": str,
            "hash": {"md5": str, "sha256": str},
            "capture_hex": str,
            "frame_size": int,
            "error": str | None,
        }
    """
    result = {
        "accepted": False,
        "http_response_bytes": None,
        "http_response_hex": None,
        "json_data": None,
        "json_hex": None,
        "hash": None,
        "capture_hex": None,
        "frame_size": 0,
        "error": None,
        "decryption_steps": [],
    }

    try:
        # Receive wire frame
        key_bytes = (private_key["n"].bit_length() + 7) // 8
        encrypted_key, hmac_tag, ciphertext, raw_frame = _receive_frame(conn, key_bytes)
        result["frame_size"] = len(raw_frame)
        result["capture_hex"] = raw_frame.hex()
        result["decryption_steps"].append({
            "step": "TCP Frame Received",
            "status": "success",
            "details": {
                "frame_size_bytes": len(raw_frame),
                "encrypted_key_size": len(encrypted_key),
                "hmac_tag_size": len(hmac_tag),
                "ciphertext_size": len(ciphertext),
            },
        })

        # Decrypt AES session key
        session_key = rsa_decrypt(encrypted_key, private_key)
        result["decryption_steps"].append({
            "step": "RSA-2048 Key Decryption",
            "status": "success",
            "details": {
                "encrypted_key_hex": encrypted_key.hex()[:64] + "...",
                "session_key_hex": session_key.hex(),
                "key_size_bits": private_key["n"].bit_length(),
            },
        })

        # Verify HMAC
        tag_valid = verify_tag(session_key, ciphertext, hmac_tag.hex())
        result["decryption_steps"].append({
            "step": "HMAC-SHA256 Verification",
            "status": "success" if tag_valid else "fail",
            "details": {
                "received_tag_hex": hmac_tag.hex()[:32] + "...",
                "computed_valid": tag_valid,
            },
        })
        if not tag_valid:
            result["error"] = "HMAC verification failed"
            return result

        # Decrypt AES ciphertext
        plaintext = aes_decrypt(ciphertext, session_key)
        result["http_response_bytes"] = plaintext
        result["http_response_hex"] = plaintext.hex()
        result["decryption_steps"].append({
            "step": "AES-128 Decryption",
            "status": "success",
            "details": {
                "ciphertext_hex": ciphertext.hex()[:64] + "...",
                "plaintext_size_bytes": len(plaintext),
                "plaintext_preview": (plaintext[:120].decode("utf-8", errors="replace") + "...") if len(plaintext) > 120 else plaintext.decode("utf-8", errors="replace"),
            },
        })

        # Parse HTTP response to extract JSON
        http_str = plaintext.decode("utf-8", errors="replace")
        json_body = _parse_http_response(http_str)

        if json_body is None:
            result["error"] = "Failed to parse HTTP response body"
            return result

        json_bytes = json.dumps(json_body, ensure_ascii=False, indent=2).encode("utf-8")
        result["json_data"] = json_body
        result["json_hex"] = json_bytes.hex()
        result["hash"] = _compute_hash(json_bytes)
        result["accepted"] = True
        result["decryption_steps"].append({
            "step": "HTTP Response Parsing",
            "status": "success",
            "details": {
                "http_response_text": http_str[:200] + ("..." if len(http_str) > 200 else ""),
                "json_size_bytes": len(json_bytes),
                "hash": result["hash"],
            },
        })

    except Exception as e:
        result["error"] = str(e)

    return result


def _receive_frame(conn, key_bytes):
    """
    Receive wire frame from TCP connection.
    Same logic as network.server.receive_frame.
    """
    raw_frame = b""

    # Receive RSA-encrypted AES key
    remaining = key_bytes
    encrypted_key = b""
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while receiving encrypted key")
        raw_frame += chunk
        encrypted_key += chunk
        remaining -= len(chunk)

    # Receive HMAC tag length
    remaining = 4
    hmac_len_bytes = b""
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while receiving HMAC length")
        raw_frame += chunk
        hmac_len_bytes += chunk
        remaining -= len(chunk)
    hmac_len = int.from_bytes(hmac_len_bytes, "big")

    # Receive HMAC tag
    remaining = hmac_len
    hmac_tag = b""
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while receiving HMAC tag")
        raw_frame += chunk
        hmac_tag += chunk
        remaining -= len(chunk)

    # Receive ciphertext
    ciphertext = b""
    conn.settimeout(5.0)
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw_frame += chunk
            ciphertext += chunk
    except socket.timeout:
        pass
    conn.settimeout(None)

    return encrypted_key, hmac_tag, ciphertext, raw_frame


def _parse_http_response(http_str):
    """
    Parse HTTP response string to extract JSON body.

    Parameters
    ----------
    http_str : str
        Full HTTP response text.

    Returns
    -------
    dict or None
        Parsed JSON body, or None if parsing fails.
    """
    # Split headers and body at blank line
    parts = http_str.split("\r\n\r\n", 1)
    if len(parts) != 2:
        return None

    body = parts[1]
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _compute_hash(data):
    """Compute MD5 and SHA-256 hashes."""
    import hashlib
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def generate_pcap(json_data, city, pcap_dir="captures"):
    """
    Generate a Wireshark-compatible .pcap file containing the JSON data
    wrapped as an HTTP response.

    PCAP format:
      - Global header: 24 bytes
      - Per record: 16-byte record header + packet data
      - Packet: IPv4 header (20B) + TCP header (20B) + HTTP response

    Parameters
    ----------
    json_data : bytes
        Raw JSON weather data.
    city : str
        City name (used in filename).
    pcap_dir : str
        Directory to save pcap file.

    Returns
    -------
    str
        Path to generated pcap file.
    """
    os.makedirs(pcap_dir, exist_ok=True)
    filename = f"weather_{city.replace('/', '_')}.pcap"
    filepath = os.path.join(pcap_dir, filename)

    # Build HTTP response
    from data.weather_data import build_http_response
    http_response = build_http_response(json_data)

    # PCAP global header (magic, version 2.4, snaplen 65535, LINKTYPE_IPV4=228)
    global_header = struct.pack(
        "<IHHiIII",
        0xa1b2c3d4,   # magic number
        2, 4,          # version
        0,             # thiszone
        0,             # sigfigs
        65535,         # snaplen
        228,           # LINKTYPE_IPV4 (IPv4 no link layer)
    )

    # Packet: IPv4 + TCP + HTTP response
    src_ip = b"\x7f\x00\x00\x01"    # 127.0.0.1
    dst_ip = b"\x7f\x00\x00\x01"    # 127.0.0.1
    src_port = 80
    dst_port = 12345
    seq_num = 1
    ack_num = 1
    data_offset = 0x50               # 5 * 4 = 20 bytes header, no options
    flags = 0x18                     # ACK + PSH

    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
        65535,  # window
        0,      # checksum (zero = not computed)
        0,      # urgent pointer
    )

    # IPv4 header (LINKTYPE_IPV4: no link-layer, starts at IP)
    version_ihl = 0x45               # IPv4, IHL=5 (20 bytes)
    tos = 0
    total_length = 20 + 20 + len(http_response)
    identification = 0
    flags_fragment = 0x4000          # DF flag
    ttl = 64
    protocol = 6                     # TCP
    checksum = 0

    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip,
    )

    packet_data = ip_header + tcp_header + http_response

    # Record header: ts_sec, ts_usec, incl_len, orig_len
    ts_sec = int(time.time())
    ts_usec = 0
    incl_len = len(packet_data)
    orig_len = len(packet_data)

    record_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)

    with open(filepath, "wb") as f:
        f.write(global_header)
        f.write(record_header)
        f.write(packet_data)

    return filepath
