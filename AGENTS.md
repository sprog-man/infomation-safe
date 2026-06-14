# Agent Working Rules

## Project Overview

This is an **Information Safety Experiment** project demonstrating end-to-end network data security:
- Sensor data simulation & collection
- AES-128 encryption/decryption (from scratch)
- RSA key generation & key encryption (from scratch)
- HMAC-SHA256 message authentication (from scratch)
- TCP server/client for secure network transmission
- Full integration pipeline

---

## Directory Structure

```
infomation-safety2/
├── AGENTS.md                  # This file — project rules & architecture
├── feature_list.json          # Feature backlog with status tracking
├── progress.md                # Session progress log with evidence
├── session-handoff.md         # Inter-session handoff notes
├── init_check.py              # Project initialization verification script
├── main.py                    # Entry point — runs full end-to-end pipeline
│
├── # Data layer
│   ├── sensor_data.py         # Sensor data simulation (temperature, humidity, pressure)
│   └── test_sensor.py         # Tests for sensor data module
│
├── # Cryptography layer (all from scratch, stdlib only)
│   ├── aes_crypto.py          # AES-128 encryption/decryption (ECB + PKCS7)
│   ├── test_aes.py            # Tests for AES module
│   ├── rsa_crypto.py          # RSA key generation, encrypt, decrypt
│   └── test_rsa.py            # Tests for RSA module
│
├── # Authentication layer
│   ├── hmac_auth.py           # HMAC-SHA256 message authentication
│   └── test_hmac.py           # Tests for HMAC module
│
├── # Network layer
│   ├── client.py              # TCP client — generates, encrypts, authenticates, sends
│   └── server.py              # TCP server — receives, verifies, decrypts, outputs
│
└── # Integration
    └── test_end_to_end.py     # End-to-end test: client sends, server receives & verifies
```

**Design principles:**
- Flat structure — all modules at root level (no subpackages).
- Each module has a matching `test_*.py` file.
- No external dependencies — only Python standard library.

---

## Development Architecture

### Layer Model

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

### Dependency Graph

```
sensor_data.py          (no dependencies)
aes_crypto.py           (no dependencies)
rsa_crypto.py           (no dependencies)
hmac_auth.py            (no dependencies)
client.py               → sensor_data, aes_crypto, rsa_crypto, hmac_auth
server.py               → aes_crypto, rsa_crypto, hmac_auth
main.py                 → all modules
```

### Feature Flow

1. **Sensor data** is generated as JSON (temperature, humidity, pressure).
2. **AES-128** encrypts the JSON payload with a randomly generated session key.
3. **RSA** encrypts the AES session key for secure key exchange.
4. **HMAC-SHA256** produces an authentication tag over the ciphertext.
5. **TCP client** sends `[encrypted_payload + hmac_tag]` to the server.
6. **TCP server** verifies HMAC, decrypts AES, outputs original sensor data.

---

## Git Version Management

### Branch Strategy
- `main` — stable, always passing state.
- Feature branches: `feat/N-feature-name` (e.g., `feat/AES-encryption`).
- Never push broken code to `main`.

### Commit Conventions
```
<type>(<scope>): <subject>

Types: feat, fix, docs, test, refactor, chore
Scope: sensor, aes, rsa, hmac, client, server, e2e
```

Examples:
```
feat(sensor): implement sensor data simulation module
test(aes): add round-trip and padding tests
fix(hmac): correct HMAC tag computation for empty messages
```

### Workflow
1. Create branch from `main`: `git checkout -b feat/N-description`
2. Implement + test locally.
3. Commit frequently with descriptive messages.
4. Push and open PR to `main`.
5. Squash-merge after review.

---

## Coding Standards

### General Rules
- **One feature at a time.** Do not skip ahead. Each feature must pass verification before the next begins.
- **Write evidence, not claims.** Every completed item in `progress.md` must reference actual files that exist.
- **No external crypto libraries.** Encryption and authentication algorithms MUST be implemented from scratch. Only Python standard library imports allowed.
- **Self-contained.** The entire project must be runnable without external services. Simulate sensor data in code.
- **Comments required.** Every algorithm function must have comments explaining its logic.

### Python Style
- Use type hints for all public function signatures.
- Docstrings: Google-style with Parameters, Returns, Raises sections.
- Maximum line length: 100 characters.
- Use `if __name__ == "__main__":` for module-level demos.

---

## Startup Checklist

1. Read `feature_list.json` to find the active feature.
2. Read `progress.md` to understand current state.
3. Run `python init_check.py` to verify the project builds.

---

## Verification

Before claiming any task is done:
1. Run `python init_check.py` to verify all components load.
2. Run the corresponding test script (`python test_*.py`).
3. Update `progress.md` with evidence references.

---

## Done Criteria

- Code is self-contained and runnable (`python main.py`).
- All five experiment sections covered: encryption, decryption, message authentication, network transmission, data collection process.
- Source code includes comments explaining algorithm logic.
- `progress.md` updated with file references for each completed item.

---

## Session Handoff

At session end, write a handoff entry in `session-handoff.md` so the next session can resume.
