# Architecture

## Layer Model

```
┌─────────────────────────────────────┐
│         main.py (integration)       │
├─────────────────────────────────────┤
│  Network Layer                       │
│  client.py  ◄── TCP ──►  server.py  │
├─────────────────────────────────────┤
│  Application Logic                   │
│  sensor_data.py                     │
├─────────────────────────────────────┤
│  Cryptography Layer                  │
│  aes_crypto.py  (AES-128)           │
│  rsa_crypto.py  (RSA)               │
│  hmac_auth.py   (HMAC-SHA256)       │
└─────────────────────────────────────┘
```

## Dependency Graph

```
sensor_data.py          (no dependencies)
aes_crypto.py           (no dependencies)
rsa_crypto.py           (no dependencies)
hmac_auth.py            (no dependencies)
client.py               → sensor_data, aes_crypto, rsa_crypto, hmac_auth
server.py               → aes_crypto, rsa_crypto, hmac_auth
main.py                 → all modules
```

## Feature Flow

1. **Sensor data** is generated as JSON (temperature, humidity, pressure).
2. **AES-128** encrypts the JSON payload with a randomly generated session key.
3. **RSA** encrypts the AES session key for secure key exchange.
4. **HMAC-SHA256** produces an authentication tag over the ciphertext.
5. **TCP client** sends `[encrypted_payload + hmac_tag]` to the server.
6. **TCP server** verifies HMAC, decrypts AES, outputs original sensor data.

## Wire Frame Format

```
┌────────────────┬──────────────┬──────────────┬──────────────────┐
│ RSA-enc key    │ HMAC tag     │ Ciphertext   │ (optional)       │
│ (256 bytes)    │ (64 bytes)   │ (variable)   │                  │
└────────────────┴──────────────┴──────────────┴──────────────────┘
```

- **RSA-enc key**: AES session key encrypted with RSA-2048 public key
- **HMAC tag**: SHA-256 hex digest (64 chars) computed over ciphertext with AES key
- **Ciphertext**: AES-128-ECB encrypted JSON payload (PKCS7 padded)

## Design Principles

- Flat structure — all modules at root level (no subpackages).
- Each module has a matching `test_*.py` file.
- No external dependencies — only Python standard library.
- All crypto from scratch — no use of `cryptography`, `PyCryptodome`, etc.
