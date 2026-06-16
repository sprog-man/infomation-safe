"""
sender_api.py — Sender HTTP server for the C/S split architecture

Provides a web frontend for weather data fetching, encryption, and TCP transmission
to the receiver. Has RSA public key only (cannot decrypt).

Usage:
    python sender_api.py              # HTTP on 8080
    python sender_api.py --port 9090  # custom port

API endpoints:
    GET /                       -> web/sender.html
    GET /css/*, /js/*           -> static files
    POST /api/weather/fetch     -> fetch weather data for a city
    POST /api/weather/send      -> fetch → encrypt → TCP send → compare hash
    POST /api/weather/cities    -> return list of available cities
"""

import sys
import os
import json
import time
import socket
import http.client
import hashlib
import threading
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.weather_data import fetch_weather, build_http_response, compute_hash, CITIES as WEATHER_CITIES
from crypto.aes_crypto import aes_encrypt
from crypto.rsa_crypto import rsa_encrypt
from auth.hmac_auth import compute_tag
from network.client import send_frame

# ---------------------------------------------------------------------------
# Global config — receiver address
# ---------------------------------------------------------------------------

RECEIVER_HOST = "127.0.0.1"
RECEIVER_TCP_PORT = 9999
RECEIVER_HTTP_PORT = 8081

# ---------------------------------------------------------------------------
# Public key cache (fetched from receiver via HTTP API)
# ---------------------------------------------------------------------------

_public_key_cache = None


def _fetch_public_key():
    """Fetch the receiver's RSA public key via HTTP."""
    global _public_key_cache
    try:
        conn = http.client.HTTPConnection(RECEIVER_HOST, RECEIVER_HTTP_PORT, timeout=5)
        conn.request("GET", "/api/weather/public-key")
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        if "n" in data and "e" in data:
            _public_key_cache = {
                "n": int(data["n"], 16),
                "e": data["e"],
            }
            return _public_key_cache
        raise ValueError("Invalid public key response")
    except Exception as e:
        raise ConnectionError(f"Failed to fetch public key from receiver: {e}")


def _get_public_key():
    """Get cached public key, fetching if needed."""
    if _public_key_cache is None:
        return _fetch_public_key()
    return _public_key_cache


# ---------------------------------------------------------------------------
# Latest hash store — for receiver to fetch and compare
# ---------------------------------------------------------------------------

_latest_sender_hash = None

def handle_latest_hash(body: dict) -> dict:
    """Return the hash of the most recently sent data."""
    global _latest_sender_hash
    if _latest_sender_hash:
        return {"hash": _latest_sender_hash, "available": True}
    return {"available": False, "error": "No data sent yet"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_to_hex_padded(val: int, width: int = 64) -> str:
    """Convert int to zero-padded hex string."""
    return format(val, f"0{width}x")


def _hex_padded_to_int(hex_str: str) -> int:
    """Convert zero-padded hex string to int."""
    return int(hex_str, 16)


def _query_receiver_latest():
    """HTTP GET the receiver's /api/weather/latest endpoint."""
    try:
        conn = http.client.HTTPConnection(RECEIVER_HOST, RECEIVER_HTTP_PORT, timeout=5)
        conn.request("GET", "/api/weather/latest")
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return data
    except Exception as e:
        return {"available": False, "error": str(e)}


# ---------------------------------------------------------------------------
# API handlers
# ---------------------------------------------------------------------------

def handle_weather_fetch(body: dict) -> dict:
    """Fetch weather data for a city and return raw JSON + HTTP response + hash."""
    city = body.get("city", "Beijing")
    api_key = body.get("api_key", "")

    if not city:
        return {"error": "city is required"}

    raw_json_bytes = fetch_weather(city, api_key)  # api_key is ignored, uses Open-Meteo
    raw_json_str = raw_json_bytes.decode("utf-8")
    raw_hash = compute_hash(raw_json_bytes)

    http_response_bytes = build_http_response(raw_json_bytes)
    http_response_hash = compute_hash(http_response_bytes)

    return {
        "city": city,
        "raw_json": raw_json_str,
        "raw_json_hex": raw_json_bytes.hex(),
        "raw_json_hash": raw_hash,
        "http_response_hex": http_response_bytes.hex(),
        "http_response_hash": http_response_hash,
    }


def handle_weather_send(body: dict) -> dict:
    """
    Full sender pipeline: fetch → encrypt → TCP send.

    1. Fetch real weather data from Open-Meteo (free, no API key)
    2. Wrap in HTTP response
    3. AES-128 encrypt HTTP response
    4. RSA public key encrypt AES session key
    5. HMAC-SHA256 tag over ciphertext
    6. Pack wire frame
    7. TCP send to receiver
    8. Query receiver's /api/weather/latest for server hash
    9. Return client + server hashes for comparison
    """
    city = body.get("city", "Beijing")
    api_key = body.get("api_key", "")

    if not city:
        return {"error": "city is required"}

    # Fetch RSA public key from receiver
    try:
        public_key = _get_public_key()
    except ConnectionError as e:
        return {"error": str(e)}

    steps = []
    t0 = time.monotonic()

    # Phase 1: Fetch weather
    try:
        t = time.monotonic()
        raw_json_bytes = fetch_weather(city, api_key)
        raw_json_str = raw_json_bytes.decode("utf-8")
        raw_hash = compute_hash(raw_json_bytes)
        client_hash = raw_hash
        steps.append({
            "step": "Weather Data Fetch",
            "icon": "🌤",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {"city": city, "size_bytes": len(raw_json_bytes), "hash": raw_hash},
            "data": {"raw_json": raw_json_str[:300] + ("..." if len(raw_json_str) > 300 else "")},
        })
    except Exception as e:
        steps.append({"step": "Weather Data Fetch", "status": "fail", "error": str(e)})
        return {"steps": steps, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 2: Build HTTP response
    try:
        t = time.monotonic()
        http_response_bytes = build_http_response(raw_json_bytes)
        http_hex = http_response_bytes.hex()
        steps.append({
            "step": "HTTP Response Wrapper",
            "icon": "📦",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {"http_size_bytes": len(http_response_bytes)},
            "data": {"http_response": http_response_bytes.decode("utf-8", errors="replace")[:200] + ("..." if len(http_response_bytes) > 200 else "")},
        })
    except Exception as e:
        steps.append({"step": "HTTP Response Wrapper", "status": "fail", "error": str(e)})
        return {"steps": steps, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 3: AES-128 encrypt
    try:
        t = time.monotonic()
        import random as _random
        aes_key = bytes(_random.getrandbits(8) for _ in range(16))
        ciphertext = aes_encrypt(http_response_bytes, aes_key)
        steps.append({
            "step": "AES-128 Encryption",
            "icon": "🔐",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "aes_key_hex": aes_key.hex(),
                "plaintext_bytes": len(http_response_bytes),
                "ciphertext_bytes": len(ciphertext),
            },
            "data": {
                "plaintext_hex_preview": http_response_bytes.hex()[:64] + "...",
                "ciphertext_hex_preview": ciphertext.hex()[:64] + "...",
            },
        })
    except Exception as e:
        steps.append({"step": "AES-128 Encryption", "status": "fail", "error": str(e)})
        return {"steps": steps, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 4: RSA encrypt AES key
    try:
        t = time.monotonic()
        encrypted_key = rsa_encrypt(aes_key, public_key)
        steps.append({
            "step": "RSA-2048 Key Encryption",
            "icon": "🔑",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "aes_key_hex": aes_key.hex(),
                "public_key_n_bits": public_key["n"].bit_length(),
                "encrypted_key_bytes": len(encrypted_key),
                "encrypted_key_hex": encrypted_key.hex()[:64] + "...",
            },
        })
    except Exception as e:
        steps.append({"step": "RSA-2048 Key Encryption", "status": "fail", "error": str(e)})
        return {"steps": steps, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 5: HMAC-SHA256
    try:
        t = time.monotonic()
        hmac_tag_hex = compute_tag(aes_key, ciphertext)
        steps.append({
            "step": "HMAC-SHA256 Authentication",
            "icon": "🛡",
            "status": "success",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "hmac_key_hex": aes_key.hex(),
                "ciphertext_for_hmac_preview": ciphertext.hex()[:32] + "...",
                "tag_hex": hmac_tag_hex,
                "tag_size_bytes": len(bytes.fromhex(hmac_tag_hex)),
            },
        })
    except Exception as e:
        steps.append({"step": "HMAC-SHA256 Authentication", "status": "fail", "error": str(e)})
        return {"steps": steps, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Phase 6: Pack frame + TCP send
    try:
        t = time.monotonic()

        # Pack frame manually (same format as weather_client._build_frame_manual)
        hmac_tag_bytes = bytes.fromhex(hmac_tag_hex)
        frame = encrypted_key
        frame += len(hmac_tag_bytes).to_bytes(4, "big")
        frame += hmac_tag_bytes
        frame += ciphertext
        frame_size = len(frame)

        # TCP send to receiver
        response = send_frame(RECEIVER_HOST, RECEIVER_TCP_PORT, frame, timeout=10.0)
        steps.append({
            "step": "TCP Transmission",
            "icon": "📡",
            "status": "success" if response == "ACCEPT" else "fail",
            "time_s": round(time.monotonic() - t, 3),
            "details": {
                "receiver": f"{RECEIVER_HOST}:{RECEIVER_TCP_PORT}",
                "frame_size_bytes": frame_size,
                "server_response": response,
            },
            "data": {
                "frame_hex_preview": frame.hex()[:256],
                "wire_format": "RSA Encrypted Key(256B) + HMAC Length(4B) + HMAC Tag(32B) + Ciphertext(variable)",
            },
        })
    except Exception as e:
        steps.append({"step": "TCP Transmission", "status": "fail", "error": str(e)})
        return {"steps": steps, "success": False, "total_time_s": round(time.monotonic() - t0, 3)}

    # Build final result — sender only shows its own hash, no comparison
    global _latest_sender_hash
    _latest_sender_hash = client_hash
    success = all(p["status"] == "success" for p in steps)

    result = {
        "steps": steps,
        "success": success,
        "total_time_s": round(time.monotonic() - t0, 3),
        "raw_json": raw_json_str,
        "raw_json_hex": raw_json_bytes.hex(),
        "client_hash": client_hash,
        "http_response_hex": http_hex,
        "frame_size": frame_size,
    }

    return result


def handle_weather_cities(body: dict) -> dict:
    """Return list of available cities."""
    return {"cities": WEATHER_CITIES}


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

_API_HANDLERS = {
    "weather/fetch": handle_weather_fetch,
    "weather/send": handle_weather_send,
    "weather/cities": handle_weather_cities,
}

_GET_HANDLERS = {
    "weather/latest-hash": handle_latest_hash,
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


class SenderHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Sender web UI."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/" or path == "/sender.html":
            self._serve_file("sender.html")
        elif path.startswith("/css/") or path.startswith("/js/"):
            self._serve_file(path[1:])
        elif path.startswith("/api/"):
            endpoint = path[len("/api/"):]
            handler = _GET_HANDLERS.get(endpoint)
            if handler:
                self._send_json(200, handler({}))
            else:
                self._send_json(404, {"error": "Not found"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
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
    daemon_threads = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Sender — Weather fetch + encrypt + TCP transmit")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP bind port (default: 8080)")
    parser.add_argument("--receiver-host", default="127.0.0.1", help="Receiver TCP host")
    parser.add_argument("--receiver-port", type=int, default=9999, help="Receiver TCP port")
    parser.add_argument("--receiver-http-port", type=int, default=8081, help="Receiver HTTP port")
    args = parser.parse_args()

    global RECEIVER_HOST, RECEIVER_TCP_PORT, RECEIVER_HTTP_PORT
    RECEIVER_HOST = args.receiver_host
    RECEIVER_TCP_PORT = args.receiver_port
    RECEIVER_HTTP_PORT = args.receiver_http_port

    # Fetch RSA public key from receiver
    print(f"[Sender] Fetching RSA public key from receiver at http://{RECEIVER_HOST}:{RECEIVER_HTTP_PORT}...")
    try:
        pk = _fetch_public_key()
        print(f"[Sender] Received public key: {pk['n'].bit_length()}-bit RSA")
    except ConnectionError as e:
        print(f"[ERROR] {e}")
        print("Make sure the receiver is running first!")
        sys.exit(1)

    print(f"[Sender] Receiver TCP: {RECEIVER_HOST}:{RECEIVER_TCP_PORT}")
    print(f"[Sender] Receiver HTTP: http://{RECEIVER_HOST}:{RECEIVER_HTTP_PORT}")

    server = ThreadedHTTPServer((args.host, args.port), SenderHTTPHandler)
    print(f"[Sender] Web UI at http://{args.host}:{args.port}")
    print(f"[Sender] Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
