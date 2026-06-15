"""
server_api.py — HTTP API server for the Information Safety Experiment

Provides a web frontend (via static file serving) and a JSON API
that wraps all existing pipeline modules.  Zero external dependencies.

Usage:
    python server_api.py              # start on localhost:8080
    python server_api.py --port 9090  # custom port

API endpoints (all POST /api/*):
    /api/sensor-data    Generate sensor data
    /api/aes-encrypt    AES-128 encrypt
    /api/aes-decrypt    AES-128 decrypt
    /api/keys           Generate RSA keypair
    /api/encrypt-key    RSA encrypt a key
    /api/hmac           Compute HMAC-SHA256 tag
    /api/verify-hmac    Verify HMAC-SHA256 tag
    /api/send           TCP client send (with embedded server)
    /api/e2e-full       Full E2E pipeline (embedded server)

GET routes:
    /                   Serve web/index.html
    /css/*              Serve CSS files
    /js/*               Serve JS files
"""

import sys
import os
import json
import time
import socket
import socketserver
import threading
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.sensor_data import generate_batch, SENSOR_IDS
from crypto.aes_crypto import aes_encrypt, aes_decrypt
from crypto.rsa_crypto import generate_keypair, rsa_encrypt, rsa_decrypt, serialize_public_key, serialize_private_key, deserialize_public_key, deserialize_private_key
from auth.hmac_auth import compute_tag, verify_tag
from network.client import build_frame, send_frame, pack_frame, load_or_generate_keys


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_to_hex(val: int) -> str:
    """Convert int to hex string for JSON transport."""
    return format(val, "x")


def _hex_to_int(hex_str: str) -> int:
    """Convert hex string to int."""
    return int(hex_str, 16)


def _int_to_hex_padded(val: int, width: int = 64) -> str:
    """Convert int to zero-padded hex string."""
    return format(val, f"0{width}x")


def _hex_padded_to_int(hex_str: str) -> int:
    """Convert zero-padded hex string to int."""
    return int(hex_str, 16)


# ---------------------------------------------------------------------------
# API handlers
# ---------------------------------------------------------------------------

def handle_sensor_data(body: dict) -> dict:
    """Generate sensor data batch."""
    count = body.get("count", 5)
    if not isinstance(count, int) or count < 1 or count > 100:
        return {"error": "count must be an integer between 1 and 100"}
    sensor_json = generate_batch(count)
    return {
        "json": sensor_json,
        "count": count,
        "size_bytes": len(sensor_json.encode("utf-8")),
    }


def handle_aes_encrypt(body: dict) -> dict:
    """AES-128 encrypt plaintext."""
    plaintext = body.get("plaintext", "")
    key_hex = body.get("key_hex", "")
    if not plaintext:
        return {"error": "plaintext is required"}
    if not key_hex:
        return {"error": "key_hex is required"}
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return {"error": "key_hex must be valid hexadecimal"}
    if len(key) != 16:
        return {"error": "AES key must be exactly 16 bytes (32 hex chars)"}
    ciphertext = aes_encrypt(plaintext.encode("utf-8"), key)
    return {"ciphertext_hex": ciphertext.hex()}


def handle_aes_decrypt(body: dict) -> dict:
    """AES-128 decrypt ciphertext."""
    ciphertext_hex = body.get("ciphertext_hex", "")
    key_hex = body.get("key_hex", "")
    if not ciphertext_hex:
        return {"error": "ciphertext_hex is required"}
    if not key_hex:
        return {"error": "key_hex is required"}
    try:
        key = bytes.fromhex(key_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return {"error": "Invalid hex encoding"}
    if len(key) != 16:
        return {"error": "AES key must be exactly 16 bytes (32 hex chars)"}
    try:
        plaintext = aes_decrypt(ciphertext, key)
        return {"plaintext": plaintext.decode("utf-8")}
    except Exception as e:
        return {"error": f"Decryption failed: {e}"}


def handle_keys(body: dict) -> dict:
    """Generate RSA keypair."""
    bits = body.get("bits", 2048)
    if bits not in (512, 1024, 2048):
        return {"error": "bits must be 512, 1024, or 2048"}
    pub, priv = generate_keypair(bits)
    return {
        "bits": bits,
        "public_key": {
            "n": _int_to_hex_padded(pub["n"]),
            "e": pub["e"],
        },
        "private_key": {
            "n": _int_to_hex_padded(priv["n"]),
            "d": _int_to_hex_padded(priv["d"]),
        },
    }


def handle_encrypt_key(body: dict) -> dict:
    """RSA encrypt an AES session key."""
    public_key = body.get("public_key")
    aes_key_hex = body.get("aes_key_hex", "")
    if not public_key:
        return {"error": "public_key is required"}
    if not aes_key_hex:
        return {"error": "aes_key_hex is required"}
    try:
        pub = {
            "n": _hex_padded_to_int(public_key["n"]),
            "e": public_key["e"],
        }
        aes_key = bytes.fromhex(aes_key_hex)
    except (ValueError, KeyError):
        return {"error": "Invalid key encoding"}
    if len(aes_key) != 16:
        return {"error": "AES key must be exactly 16 bytes (32 hex chars)"}
    encrypted = rsa_encrypt(aes_key, pub)
    return {"encrypted_key_hex": encrypted.hex()}


def handle_hmac(body: dict) -> dict:
    """Compute HMAC-SHA256 tag."""
    key_hex = body.get("key_hex", "")
    message_hex = body.get("message_hex", "")
    if not key_hex:
        return {"error": "key_hex is required"}
    if not message_hex:
        return {"error": "message_hex is required"}
    try:
        key = bytes.fromhex(key_hex)
        message = bytes.fromhex(message_hex)
    except ValueError:
        return {"error": "Invalid hex encoding"}
    tag = compute_tag(key, message)
    return {"tag_hex": tag}


def handle_verify_hmac(body: dict) -> dict:
    """Verify HMAC-SHA256 tag."""
    key_hex = body.get("key_hex", "")
    message_hex = body.get("message_hex", "")
    tag_hex = body.get("tag_hex", "")
    if not key_hex or not message_hex or not tag_hex:
        return {"error": "key_hex, message_hex, and tag_hex are required"}
    try:
        key = bytes.fromhex(key_hex)
        message = bytes.fromhex(message_hex)
    except ValueError:
        return {"error": "Invalid hex encoding"}
    valid = verify_tag(key, message, tag_hex)
    return {"valid": valid}


def handle_send(body: dict) -> dict:
    """Build and send frame via TCP (with embedded server for demo)."""
    host = body.get("host", "127.0.0.1")
    port = body.get("port", 9999)
    reading_count = body.get("reading_count", 3)

    # We need the server running. For the API, we use the full E2E
    # approach: start embedded server, send frame, collect result.
    return {
        "error": "Use /api/e2e-full for a complete send operation with embedded server. "
                 "For direct TCP send, ensure a server is already running on {host}:{port}".format(
                    host=host, port=port
                ),
    }


def handle_e2e_full(body: dict) -> dict:
    """Run the full E2E pipeline with embedded server."""
    reading_count = body.get("reading_count", 3)
    if not isinstance(reading_count, int) or reading_count < 1 or reading_count > 100:
        return {"error": "reading_count must be an integer between 1 and 100"}

    phases = []
    t0 = time.monotonic()

    # Phase 1: Key generation
    try:
        t = time.monotonic()
        public_key, private_key = generate_keypair(2048)
        phases.append({
            "phase": "Key Generation (RSA-2048)",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "modulus_bits": public_key["n"].bit_length(),
                "public_exponent": public_key["e"],
            },
        })
    except Exception as e:
        phases.append({"phase": "Key Generation", "status": "fail", "error": str(e)})
        return {"phases": phases, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 2: Sensor data
    try:
        t = time.monotonic()
        sensor_json = generate_batch(reading_count)
        sensor_data = json.loads(sensor_json)
        phases.append({
            "phase": "Sensor Data Generation",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "batch_id": sensor_data["batch_id"],
                "reading_count": reading_count,
                "size_bytes": len(sensor_json),
            },
        })
    except Exception as e:
        phases.append({"phase": "Sensor Data Generation", "status": "fail", "error": str(e)})
        return {"phases": phases, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 3: AES encryption
    try:
        t = time.monotonic()
        aes_key = b"MySessKey1234567"
        ciphertext = aes_encrypt(sensor_json.encode("utf-8"), aes_key)
        phases.append({
            "phase": "AES-128 Encryption",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "plaintext_bytes": len(sensor_json),
                "ciphertext_bytes": len(ciphertext),
                "mode": "ECB",
                "padding": "PKCS7",
            },
        })
    except Exception as e:
        phases.append({"phase": "AES-128 Encryption", "status": "fail", "error": str(e)})
        return {"phases": phases, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 4: RSA key encryption
    try:
        t = time.monotonic()
        encrypted_key = rsa_encrypt(aes_key, public_key)
        phases.append({
            "phase": "RSA Key Encryption",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "aes_key_bytes": 16,
                "encrypted_key_bytes": len(encrypted_key),
            },
        })
    except Exception as e:
        phases.append({"phase": "RSA Key Encryption", "status": "fail", "error": str(e)})
        return {"phases": phases, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 5: HMAC authentication
    try:
        t = time.monotonic()
        hmac_tag = compute_tag(aes_key, ciphertext)
        hmac_valid = verify_tag(aes_key, ciphertext, hmac_tag)
        phases.append({
            "phase": "HMAC-SHA256 Authentication",
            "status": "success" if hmac_valid else "fail",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "tag": hmac_tag[:32] + "...",
                "verified": hmac_valid,
            },
        })
    except Exception as e:
        phases.append({"phase": "HMAC-SHA256 Authentication", "status": "fail", "error": str(e)})
        return {"phases": phases, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 6: TCP transmission
    try:
        t = time.monotonic()

        _e2e_result = {}  # Shared dict populated by handler thread
        _e2e_result_lock = threading.Lock()

        class _E2EHandler(socketserver.BaseRequestHandler):
            """Handles one connection: receive frame, verify, decrypt, respond."""
            def handle(self):
                try:
                    result = _handle_e2e_connection(self.request, private_key)
                    with _e2e_result_lock:
                        _e2e_result.clear()
                        _e2e_result.update(result)
                    if result["accepted"]:
                        self.request.sendall(b"ACCEPT")
                    else:
                        self.request.sendall(b"REJECT")
                except Exception:
                    try:
                        self.request.sendall(b"REJECT")
                    except Exception:
                        pass

        class _ThreadedServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        server = _ThreadedServer(("127.0.0.1", 0), _E2EHandler)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        time.sleep(0.2)
        srv_port = server.server_address[1]

        # Build and send frame
        frame = build_frame(sensor_json, public_key)
        try:
            response = send_frame("127.0.0.1", srv_port, frame, timeout=10.0)
            phases[-1]["details"]["server_response"] = response
            phases[-1]["status"] = "success" if response == "ACCEPT" else "fail"

            # Capture result from handler thread
            with _e2e_result_lock:
                cap = dict(_e2e_result)
        except Exception as e:
            phases[-1]["status"] = "fail"
            phases[-1]["error"] = str(e)
            cap = {}
        finally:
            server.shutdown()
            server.server_close()
            srv_thread.join(timeout=3)

        # Add capture and decrypted data to response
        if cap:
            phases[-1]["details"]["capture_hex"] = cap.get("capture_hex", "")
            phases[-1]["details"]["frame_size"] = cap.get("frame_size", 0)
            if cap.get("sensor_data"):
                phases[-1]["decrypted_sensor_data"] = cap["sensor_data"]

    except Exception as e:
        phases.append({"phase": "TCP Transmission", "status": "fail", "error": str(e)})
        return {"phases": phases, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    success = all(p["status"] == "success" for p in phases)
    return {
        "phases": phases,
        "success": success,
        "total_time_s": round(time.monotonic() - t0, 3),
    }


def receive_frame_from_conn(conn, private_key, key_bytes=256):
    """Minimal frame receiver — mirrors network.server.receive_frame logic."""
    # Receive RSA-encrypted key
    remaining = key_bytes
    enc_key = b""
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            return None, None, None
        enc_key += chunk
        remaining -= len(chunk)

    # Receive HMAC tag length
    remaining = 4
    hmac_len_bytes = b""
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            return None, None, None
        hmac_len_bytes += chunk
        remaining -= len(chunk)
    hmac_len = int.from_bytes(hmac_len_bytes, "big")

    # Receive HMAC tag
    remaining = hmac_len
    hmac_tag = b""
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            return None, None, None
        hmac_tag += chunk
        remaining -= len(chunk)

    # Receive ciphertext
    conn.settimeout(5.0)
    ct = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            ct += chunk
    except socket.timeout:
        pass
    conn.settimeout(None)
    return enc_key, hmac_tag, ct


def _handle_e2e_connection(conn, private_key):
    """
    Handle one E2E connection: receive frame, verify, decrypt.
    Returns a dict with accepted, sensor_data, capture_hex, frame_size, error.
    """
    result = {"accepted": False, "sensor_data": None, "capture_hex": None,
              "frame_size": 0, "error": None}
    try:
        # Collect raw bytes for capture
        raw_frame = b""

        # Receive RSA-encrypted key
        key_bytes = (private_key["n"].bit_length() + 7) // 8
        remaining = key_bytes
        enc_key = b""
        while remaining > 0:
            chunk = conn.recv(remaining)
            if not chunk:
                return result
            raw_frame += chunk
            enc_key += chunk
            remaining -= len(chunk)

        # Receive HMAC len
        remaining = 4
        hmac_len_bytes = b""
        while remaining > 0:
            chunk = conn.recv(remaining)
            if not chunk:
                return result
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
                return result
            raw_frame += chunk
            hmac_tag += chunk
            remaining -= len(chunk)

        # Receive ciphertext
        conn.settimeout(5.0)
        ct = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw_frame += chunk
                ct += chunk
        except socket.timeout:
            pass
        conn.settimeout(None)

        result["capture_hex"] = raw_frame.hex()
        result["frame_size"] = len(raw_frame)

        # Decrypt session key
        session_key = rsa_decrypt(enc_key, private_key)

        # Verify HMAC
        tag_valid = verify_tag(session_key, ct, hmac_tag.hex())
        if not tag_valid:
            result["error"] = "HMAC verification failed"
            return result

        # Decrypt data
        plaintext = aes_decrypt(ct, session_key)
        data = json.loads(plaintext.decode("utf-8"))
        result["sensor_data"] = data
        result["accepted"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

_API_HANDLERS = {
    "sensor-data": handle_sensor_data,
    "aes-encrypt": handle_aes_encrypt,
    "aes-decrypt": handle_aes_decrypt,
    "keys": handle_keys,
    "encrypt-key": handle_encrypt_key,
    "hmac": handle_hmac,
    "verify-hmac": handle_verify_hmac,
    "send": handle_send,
    "e2e-full": handle_e2e_full,
}

_WEB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

_MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}


class WebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Information Safety Experiment web UI."""

    # Suppress default stderr logging
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        """Serve static files from web/ directory."""
        path = self.path.split("?")[0]  # strip query params

        if path == "/" or path == "/index.html":
            self._serve_file("index.html")
        elif path.startswith("/css/") or path.startswith("/js/") or path.startswith("/images/"):
            self._serve_file(path[1:])  # strip leading /, keep css/js/images prefix
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        """Route API requests to handler functions."""
        path = self.path.split("?")[0]

        if path.startswith("/api/"):
            endpoint = path[len("/api/"):]
            handler = _API_HANDLERS.get(endpoint)
            if handler is None:
                self._send_json(404, {"error": f"Unknown endpoint: {endpoint}"})
                return
            try:
                body = self._read_json_body()
                result = handler(body)
                status = 200 if "error" not in result else 400
                self._send_json(status, result)
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        else:
            self._send_json(404, {"error": "Not found"})

    # -- internal helpers --

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, rel_path: str):
        filepath = os.path.join(_WEB_ROOT, rel_path)
        if not os.path.isfile(filepath):
            self._send_json(404, {"error": "File not found"})
            return
        _, ext = os.path.splitext(rel_path)
        mime = _MIME_TYPES.get(ext, "application/octet-stream")
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTP server that handles each request in a new thread."""
    daemon_threads = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Information Safety Experiment — Web Frontend")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    args = parser.parse_args()

    server = ThreadedHTTPServer((args.host, args.port), WebHandler)
    print(f"Information Safety Experiment — Web UI")
    print(f"Server running at http://{args.host}:{args.port}")
    print(f"Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
