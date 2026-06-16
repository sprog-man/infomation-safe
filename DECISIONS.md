# Architecture Decision Log

Record of important design decisions and their rationale.

---

## 2026-06-15: Web Frontend via stdlib http.server

- **Decision**: Use Python's stdlib `http.server` + `ThreadingHTTPServer` to serve a vanilla HTML/CSS/JS frontend.
- **Reason**: Maintains the project's zero-dependency constraint. No pip install, no build step, no framework.
- **Constraints**: Not production-grade (no TLS, single-process). Acceptable for an educational experiment.
- **When to revisit**: If deploying to production or needing real-time features (WebSocket).

---

## 2026-06-14: AES-128 ECB Mode (Educational)

- **Decision**: Use AES-128 in ECB mode for the encryption layer.
- **Reason**: Educational experiment focused on demonstrating the algorithm mechanics (S-Box, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey). ECB is the simplest mode and makes the algorithm steps explicit.
- **Constraints**: Not suitable for production — identical plaintext blocks produce identical ciphertext blocks. For a real system, switch to CBC or GCM mode.
- **When to revisit**: When deploying to any production or semi-production environment.

---

## 2026-06-14: RSA-2048 for Key Exchange

- **Decision**: Use RSA-2048 to encrypt the AES session key.
- **Reason**: 2048-bit keys provide ~112 bits of security, sufficient for an educational experiment. Larger keys (3072/4096) significantly slow key generation (O(n^3) for trial division).
- **Alternatives considered**:
  - RSA-1024: Too weak by modern standards, but faster. Rejected.
  - ECDH: More efficient key exchange, but requires elliptic curve math implementation (more complex for educational purposes).
- **When to revisit**: If key generation time becomes a bottleneck.

---

## 2026-06-14: HMAC-SHA256 for Message Authentication

- **Decision**: Use HMAC-SHA256 instead of RSA digital signatures.
- **Reason**: HMAC is computationally cheaper than RSA signatures and provides the same integrity + authenticity guarantees for a shared-key scenario. The AES session key serves as the HMAC key.
- **Alternatives considered**:
  - RSA-PSS signature: Would require sender/recipient to share a signing key or use asymmetric keys. Overkill for this use case.
  - Poly1305: Faster but requires AES-CTR/GCM mode. Not compatible with ECB implementation.
- **When to revisit**: If moving to a multi-party trust model.

---

## 2026-06-14: All Crypto From Scratch (Stdlib Only)

- **Decision**: Implement AES, RSA, SHA-256, and HMAC from scratch using only Python standard library.
- **Reason**: The experiment's core requirement is to demonstrate understanding of cryptographic algorithms at the mathematical level. Using `cryptography` or `PyCryptodome` would defeat this purpose.
- **Constraints**: No external dependencies. Must run on any system with Python 3.6+.
- **When to revisit**: Never — this is a fixed experiment requirement.

---

## 2026-06-14: Flat Module Structure (Root Level)

- **Decision**: Place all modules at the project root level, organized into subdirectories only for logical grouping (`data/`, `crypto/`, `auth/`, `network/`).
- **Reason**: Keeps imports simple and avoids `__init__.py` boilerplate. Each module is directly accessible for testing.
- **Alternatives considered**:
  - Fully flat (all files at root): Simpler but harder to navigate for larger projects.
  - Full packages with `__init__.py` re-exports: More overhead, not needed for this scale.
- **When to revisit**: If the project grows beyond 20 modules.

---

## 2026-06-14: TCP Over UDP

- **Decision**: Use TCP for the network transmission layer.
- **Reason**: TCP provides reliable, ordered delivery which simplifies the frame reconstruction logic. The server needs to receive the complete frame (RSA key + HMAC tag + ciphertext) before it can verify and decrypt.
- **Alternatives considered**:
  - UDP: Faster but requires application-level retransmission and ordering logic. Adds complexity not needed for this experiment.
- **When to revisit**: If performance testing shows TCP overhead is significant.

---

## 2026-06-16: C/S Split Architecture — Independent Sender & Receiver

- **Decision**: Replace the single-process embedded-server model with two independent processes: `sender_api.py` (port 8080) and `receiver_api.py` (port 8081 + TCP 9999).
- **Reason**: The experiment requires a true client-server architecture. Previously, the weather pipeline ran an ephemeral TCP server embedded in a single HTTP request handler, which prevented independent operation. The split allows the receiver to run persistently, accept frames from a real TCP sender, and serve its own web UI with decrypted data and PCAP downloads.
- **Key design choices**:
  - `sender_api.py` has RSA **public** key only — can encrypt, cannot decrypt
  - `receiver_api.py` has RSA **private** key only — can decrypt, serves both HTTP (8081) and TCP (9999) in one process
  - Receiver **generates RSA keypair on startup**, sender **fetches public key via HTTP API** (`/api/weather/public-key`). No pre-distributed key files needed.
  - Receiver TCP handler is a daemon thread using `socketserver.ThreadingTCPServer`
  - Receiver stores latest result in a thread-safe global dict, served via `/api/weather/latest`
- **Files added**: `sender_api.py`, `receiver_api.py`, `web/sender.html`, `web/receiver.html`, `web/js/sender.js`, `web/js/receiver.js`
- **Backward compatibility**: `server_api.py` remains unchanged, all 151 existing tests pass
- **When to revisit**: If TCP needs to handle concurrent connections from multiple senders

---

## 2026-06-16: Receiver-Generated RSA Keys (removed pre-generated key files)

- **Decision**: Remove `sender_public.key` and `receiver_private.key` pre-generated key files. Receiver now generates RSA keypair on every startup; sender fetches the public key via HTTP API.
- **Reason**: Pre-generated keys violated the real-world security principle that the private key should never leave the receiver. The new design matches actual C/S key exchange: receiver generates keys → sender requests public key on demand.
- **Impact**: Removed `sender_public.key`, `receiver_private.key`, `crypto-setup` Make target. Sender must be started after receiver (it fails with a clear error if receiver is unreachable).
