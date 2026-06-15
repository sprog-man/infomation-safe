"""
network/server.py - TCP Server for Secure Sensor Data Reception

Receives encrypted+authenticated data from the client, verifies the HMAC tag,
decrypts the AES session key with RSA, decrypts the payload, and outputs
the original sensor data.

Server workflow:
  1. Generate or load RSA key pair (for decrypting AES session key)
  2. Listen on a TCP port for incoming connections
  3. Receive frame: [rsa_encrypted_aes_key (256 bytes)] + [hmac_tag (32 bytes)] + [aes_ciphertext]
  4. Decrypt AES session key using RSA private key
  5. Verify HMAC tag over ciphertext
  6. Decrypt AES ciphertext
  7. Decode JSON and output original sensor data

This server runs in a loop, handling one connection at a time.
"""

import socket
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.rsa_crypto import deserialize_private_key, rsa_decrypt
from crypto.aes_crypto import aes_decrypt
from auth.hmac_auth import verify_tag, hmac_sha256


def load_private_key(key_path: str = "server_private.key") -> dict:
    """
    Load the RSA private key from a file.

    If the file doesn't exist, generate a new 2048-bit key pair and save both.
    In production, these keys would be pre-generated and distributed securely.

    Parameters
    ----------
    key_path : str
        Path to the serialized private key file.

    Returns
    -------
    dict
        RSA private key dict with 'n' and 'd'.
    """
    if os.path.isfile(key_path):
        with open(key_path, "rb") as f:
            return deserialize_private_key(f.read())
    else:
        from crypto.rsa_crypto import generate_keypair, serialize_public_key, serialize_private_key
        pub, priv = generate_keypair(2048)
        with open(key_path, "wb") as f:
            f.write(serialize_private_key(priv))
        with open(key_path.replace(".key", "_public.key"), "wb") as f:
            f.write(serialize_public_key(pub))
        print(f"  Generated new RSA key pair, saved to {key_path}")
        return priv


def receive_frame(conn: socket.socket, key_bytes: int = 256) -> tuple:
    """
    Receive a complete frame from the TCP connection.

    Frame format:
      [key_bytes] RSA-encrypted AES session key
      [4 bytes]   HMAC tag length (big-endian uint32)
      [HMAC bytes] HMAC-SHA256 tag (32 bytes)
      [variable]  AES ciphertext (remaining data)

    Parameters
    ----------
    conn : socket.socket
        Connected socket.
    key_bytes : int
        Expected RSA key size in bytes (256 for 2048-bit).

    Returns
    -------
    tuple
        (encrypted_aes_key, hmac_tag, ciphertext, raw_frame)
        raw_frame is the complete captured byte stream (for packet capture).
    """
    # Capture raw bytes for packet capture
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

    # Receive AES ciphertext (remaining data)
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


def handle_client(conn: socket.socket, private_key: dict) -> dict:
    """
    Handle a single client connection: receive, verify, decrypt, output.

    Parameters
    ----------
    conn : socket.socket
        Connected client socket.
    private_key : dict
        RSA private key for decrypting the AES session key.

    Returns
    -------
    dict
        Result with keys: accepted (bool), sensor_data (dict|None),
        capture_hex (str|None), frame_size (int|None), error (str|None)
    """
    result = {
        "accepted": False,
        "sensor_data": None,
        "capture_hex": None,
        "frame_size": 0,
        "error": None,
    }
    try:
        # Step 1: Receive the frame
        encrypted_key, hmac_tag, ciphertext, raw_frame = receive_frame(conn)
        result["frame_size"] = len(raw_frame)
        result["capture_hex"] = raw_frame.hex()
        key_bytes = (private_key["n"].bit_length() + 7) // 8

        # Step 2: Decrypt AES session key with RSA
        session_key = rsa_decrypt(encrypted_key, private_key)

        # Step 3: Verify HMAC tag over ciphertext
        is_valid = verify_tag(session_key, ciphertext, hmac_tag.hex())

        if not is_valid:
            print("  [FAIL] HMAC verification failed — message may be tampered!")
            conn.sendall(b"REJECT")
            result["error"] = "HMAC verification failed"
            return result

        # Step 4: Decrypt AES ciphertext
        plaintext = aes_decrypt(ciphertext, session_key)

        # Step 5: Parse and output sensor data
        sensor_data = json.loads(plaintext.decode("utf-8"))
        result["sensor_data"] = sensor_data
        result["accepted"] = True
        print("  [OK] HMAC verified. Decrypted sensor data:")
        print(json.dumps(sensor_data, indent=2, ensure_ascii=False))

        conn.sendall(b"ACCEPT")

    except ConnectionError as e:
        print(f"  [FAIL] Connection error: {e}")
        result["error"] = str(e)
    except Exception as e:
        print(f"  [FAIL] Error handling client: {e}")
        result["error"] = str(e)
    finally:
        conn.close()

    return result


def run_server(host: str = "127.0.0.1", port: int = 9999,
               save_dir: str = "captures") -> None:
    """
    Start the TCP server and listen for incoming connections.

    Parameters
    ----------
    host : str
        Bind address (default: 127.0.0.1).
    port : int
        Bind port (default: 9999).
    save_dir : str
        Directory to save captured packets and sensor data files.
    """
    print(f"[*] Server starting on {host}:{port}")
    print(f"[*] Loading RSA private key...")
    private_key = load_private_key()
    print(f"[*] Private key loaded (modulus: {private_key['n'].bit_length()} bits)")
    print(f"[*] Listening for connections...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)

    # Create save directory
    os.makedirs(save_dir, exist_ok=True)

    try:
        conn_count = 0
        while True:
            conn, addr = server.accept()
            conn_count += 1
            print(f"\n[INFO] Connection #{conn_count} from {addr}")
            result = handle_client(conn, private_key)

            # Save captured packet
            if result["capture_hex"]:
                cap_file = os.path.join(save_dir, f"capture_{conn_count:04d}.hex")
                with open(cap_file, "w") as f:
                    f.write(result["capture_hex"])
                print(f"  [SAVE] Captured packet saved to {cap_file} "
                      f"({result['frame_size']} bytes)")

            # Save sensor data
            if result["sensor_data"]:
                data_file = os.path.join(save_dir, f"sensor_{conn_count:04d}.json")
                with open(data_file, "w") as f:
                    json.dump(result["sensor_data"], f, indent=2, ensure_ascii=False)
                print(f"  [SAVE] Sensor data saved to {data_file}")

            print(f"[INFO] Connection #{conn_count} from {addr} closed\n")
    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    run_server()
