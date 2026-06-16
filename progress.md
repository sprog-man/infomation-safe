# Session Progress Log

## Current State

**Active Feature:** feat-010 — C/S Architecture Split
**Status:** In Progress
**Last Updated:** 2026-06-16

---

## feat-010: C/S Architecture Split — Independent Sender & Receiver ✅

**Status:** Completed
**Date:** 2026-06-16

**Split the single-process embedded-server model into two independent processes: sender (port 8080, RSA public key only) and receiver (port 8081 + TCP 9999, RSA private key only).**

### New Files Created
- `sender_api.py` — HTTP server on port 8080 with weather fetch + encrypt + TCP transmit endpoints
- `receiver_api.py` — HTTP server on port 8081 + TCP server on port 9999 in daemon thread
- `web/sender.html` — Sender web UI with city dropdown, fetch/send buttons, packet table, hash comparison
- `web/receiver.html` — Receiver web UI with latest data display, hex table, PCAP download
- `web/js/sender.js` — Sender JS: fetch, encrypt pipeline, hash comparison
- `web/js/receiver.js` — Receiver JS: poll latest, hex table, PCAP download
- `sender_public.key` — RSA public key (pre-generated 2048-bit)
- `receiver_private.key` — RSA private key (pre-generated 2048-bit)

### Files Modified
- `web/css/style.css` — added sender/receiver styles (role badges, status panels, data/hash grids, highlight panels)
- `Makefile` — added `sender`, `receiver`, `crypto-setup` targets
- `AGENTS.md` — added C/S split section, updated directory structure and quick-start
- `feature_list.json` — v2.2 → v2.3. Added feat-010
- `DECISIONS.md` — added ADR for C/S split architecture

### Test Count
- Existing 133 tests unchanged (all pass)
- feat-010 adds no new test dependencies — verified via e2e manual test

### Done Criteria Verification:
- [x] Sender web UI at http://localhost:8080 with city dropdown, weather fetch, Wireshark-style hex table
- [x] Receiver web UI at http://localhost:8081 showing decrypted weather data and hex table
- [x] Sender encrypts weather data (AES-128 + RSA-2048 + HMAC-SHA256) and sends via TCP
- [x] Receiver decrypts, verifies HMAC, stores result, serves via HTTP API
- [x] Hash comparison confirms sender and receiver data match
- [x] Receiver generates Wireshark-compatible .pcap file
- [x] Sender has RSA public key only, receiver has RSA private key only
- [x] Zero external dependencies — stdlib only

---

## feat-009: Weather Data Security Pipeline ✅

**Status:** Completed
**Date:** 2026-06-16

**Added C/S weather data security pipeline with Wireshark-like display and .pcap generation.**

### New Files Created
- `data/weather_data.py` — weather fetch (OpenWeatherMap + mock fallback), HTTP response builder, hashing
- `network/weather_client.py` — weather frame builder (fetch → HTTP wrap → AES → RSA → HMAC → TCP frame)
- `network/weather_server.py` — weather connection handler + PCAP binary generator (pure Python `struct`)
- `test_weather_data.py` — 12 unit tests
- `test_weather_pipeline.py` — 6 integration tests
- `test_pcap.py` — 9 PCAP format validation tests
- `web/js/weather.js` — Weather tab frontend logic (city dropdown, fetch/send, packet tables, hash comparison)

### Files Modified (historical — weather endpoints moved to sender/receiver in feat-010)
- `server_api.py` (deprecated) — had weather API endpoints; now in `sender_api.py` + `receiver_api.py`
- `web/index.html` — added 5th tab: Weather 安全传输
- `web/css/style.css` — weather tab styles (packet tables, hash comparison, weather grid)
- `Makefile` — added weather test scripts to TESTS variable
- `feature_list.json` — v2.1 → v2.2. Added feat-009, total_tests: 124→151

### Test Count
- Before: 124 tests (8 scripts)
- After: 151 tests (11 scripts) — +27 from weather tests

**Done Criteria Verification:**
- [x] Web frontend with city dropdown for weather data selection
- [x] Weather data fetched via HTTP (OpenWeatherMap API or mock fallback)
- [x] Wireshark-like hex + ASCII packet table on both client and server sides
- [x] AES + RSA key exchange + HMAC pipeline preserved
- [x] TCP transmission with embedded server
- [x] Server decrypts, verifies HMAC, extracts JSON
- [x] Real .pcap file generation (Wireshark-compatible) with HTTP response content
- [x] Hash comparison between client and server data
- [x] PCAP download link in web UI

---

## Completed Features

### feat-001: Sensor Data Simulation & Collection ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] A function generates structured sensor data as a JSON string.
  - Evidence: `data/sensor_data.py` lines 50-78 (`generate_batch`) and lines 80-90 (`generate_single`)
- [x] Data includes timestamp, sensor_id, and multiple readings.
  - Evidence: `data/sensor_data.py` lines 25-48 (`generate_reading`)
- [x] Test script validates data format.
  - Evidence: `test_sensor.py` — 15 tests all passing

**Files:**
- `data/sensor_data.py` — sensor data simulation module
- `test_sensor.py` — 15 unit tests

---

### feat-002: Encryption Algorithm (AES) ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] AES implementation includes S-Box, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey.
  - Evidence: `crypto/aes_crypto.py` — S-Box (lines 25-73), key_expansion (lines 181-217), sub_bytes (lines 130-139), shift_rows (lines 142-155), mix_columns (lines 158-176), add_round_key (lines 179-185)
- [x] Both encrypt and decrypt functions work correctly.
  - Evidence: `crypto/aes_crypto.py` lines 254-274 (`aes_encrypt`) and lines 277-299 (`aes_decrypt`)
- [x] Test script encrypts a plaintext and decrypts it back to the original.
  - Evidence: `test_aes.py` — 23 tests all passing, including NIST FIPS-197 test vector

**Files:**
- `crypto/aes_crypto.py` — AES-128 implementation
- `test_aes.py` — 23 unit tests

---

### feat-003: RSA Key Generation & Key Encryption ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] RSA key pair (public/private) is generated programmatically.
  - Evidence: `crypto/rsa_crypto.py` lines 130-170 (`generate_keypair`)
- [x] RSA encrypts a session key; RSA decrypts it back to the original.
  - Evidence: `crypto/rsa_crypto.py` lines 296-340 (`rsa_encrypt`/`rsa_decrypt`)
- [x] Test script validates key encryption/decryption round-trip.
  - Evidence: `test_rsa.py` — 28 tests all passing

**Files:**
- `crypto/rsa_crypto.py` — RSA key generation, encrypt/decrypt
- `test_rsa.py` — 28 unit tests

---

### feat-004: Message Authentication (HMAC-SHA256) ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] SHA-256 and HMAC implemented without external libraries.
  - Evidence: `auth/hmac_auth.py` — SHA-256 (lines 50-140), HMAC-SHA256 (lines 158-195), all stdlib
- [x] Authenticator is appended to the ciphertext before transmission.
  - Evidence: `auth/hmac_auth.py` lines 158-195 (`hmac_sha256`), `compute_tag` (lines 204-215), `verify_tag` (lines 218-236)
- [x] Test script verifies a valid tag and rejects a tampered message.
  - Evidence: `test_hmac.py` — 20 tests all passing (SHA-256 known vectors, HMAC key/message variations, tamper detection)

**Files:**
- `auth/hmac_auth.py` — SHA-256 + HMAC-SHA256 from scratch
- `test_hmac.py` — 20 unit tests

---

## In Progress

### feat-005: Network Transmission — Server (TCP Receiver) ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] TCP server listens and accepts connections.
  - Evidence: `network/server.py` lines 178-209 (`run_server`)
- [x] Receives a frame containing [encrypted_payload + hmac_tag].
  - Evidence: `network/server.py` lines 64-130 (`receive_frame`) — receives [rsa_encrypted_key][hmac_len][hmac_tag][ciphertext]
- [x] Verifies HMAC, decrypts AES, prints original sensor data.
  - Evidence: `network/server.py` lines 133-175 (`handle_client`) — steps: rsa_decrypt session key → verify_tag → aes_decrypt → json decode
- [x] Test script runs server + client and validates end-to-end.
  - Evidence: `test_server.py` — 4 tests all passing (roundtrip, tamper rejection, invalid HMAC, 10-readings batch)

**Files:**
- `network/server.py` — TCP server module
- `test_server.py` — 4 unit/integration tests

---

### feat-006: Network Transmission — Client (TCP Sender) ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] Client connects to server, sends complete encrypted+authenticated frame.
  - Evidence: `network/client.py` lines 161-197 (`run_client`) — orchestrates key loading, data generation, encryption, and TCP send
- [x] End-to-end test: client sends data, server receives and decrypts correctly.
  - Evidence: `test_client.py` — `test_client_server_roundtrip` passes
- [x] Tamper test: modify the payload mid-transmission and confirm server rejects it.
  - Evidence: `test_client.py` — `test_client_tampered_payload_rejected` and `test_client_invalid_hmac_rejected` both pass

**Files:**
- `network/client.py` — TCP client module
- `test_client.py` — 9 unit/integration tests

---

## Pending Features

| Feature | Name | Dependencies |
|---------|------|-------------|
| (none) | — | — |

---

### feat-007: Integration & Report ✅

**Status:** Completed
**Date:** 2026-06-14

**Done Criteria Verification:**
- [x] Single `python main.py` runs the full pipeline.
  - Evidence: `main.py` lines 122-204 (`run_local_e2e`) — 6-phase pipeline: keygen → sensor data → AES → RSA → HMAC → TCP E2E
- [x] All test scripts pass.
  - Evidence: 99 tests total — test_sensor.py (15), test_aes.py (23), test_rsa.py (28), test_hmac.py (20), test_client.py (9), test_server.py (4) — all passing
- [x] Report sections match experiment requirements.
  - Evidence: `main.py` lines 210-260 (`run_standalone_demo`) demonstrates all 5 experiment sections: sensor data collection, AES encryption, RSA key encryption, HMAC authentication, TCP transmission

**Files:**
- `main.py` — unified entry point with --demo / --e2e / default modes

---

## Session Notes

- Directory structure: `data/`, `crypto/`, `auth/`, `network/`
- Remote Git repo: https://github.com/sprog-man/infomation-safe.git
- All crypto verified against known test vectors (NIST FIPS-197 for AES, SHA-256 RFC test vectors)

