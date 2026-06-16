# Agent Working Rules

## Project Overview

**Information Safety Experiment** — End-to-end network data security pipeline:
weather/sensor data simulation → AES-128 encryption → RSA key exchange → HMAC-SHA256 authentication → TCP transmission → full integration → Wireshark-compatible .pcap export.

All crypto implemented from scratch. Zero external dependencies.

---

## Quick Start

```bash
python init_check.py       # Verify project structure & imports
make test                  # Run all 11 core test scripts (151 tests)
make lint                  # Syntax + compilation check (stdlib, zero deps)
make web-test              # Run 18 web API tests
make check                 # Full verification (lint + test + e2e)
make check-web             # Full verification including web
make exit                  # Session exit checklist (5 dimensions)
make demo                  # Standalone crypto demo (no server)
make e2e                   # End-to-end pipeline (embedded server)
make web                   # Start original unified UI at http://localhost:8080
make receiver              # Start receiver → generates RSA keypair, serves on 8081, TCP 9999
make sender                # Start sender → fetches RSA key from receiver, serves on 8080
make done                  # Pre-commit doc sync check (progress.md, DECISIONS.md)
make setup-hooks           # Configure git pre-commit hook (run once per clone)
python main.py             # Default: demo + e2e
```

## C/S Split Architecture

The project supports two modes:

1. **Unified (original)**: `python server_api.py` — single process with embedded TCP server, all features in one port (8080).
2. **C/S Split (recommended)**: Two independent processes:
   - **Sender** (`python sender_api.py`, port 8080) — RSA public key only. Weather fetch → AES encrypt → TCP transmit.
   - **Receiver** (`python receiver_api.py`, port 8081 + TCP 9999) — RSA private key only. TCP receive → HMAC verify → AES decrypt → PCAP.

Usage:
```bash
# Terminal 1: Start receiver
make receiver

# Terminal 2: Start sender
make sender

# Open http://localhost:8080 (sender) and http://localhost:8081 (receiver)
```

---

## Directory Structure

```
infomation-safety2/
├── AGENTS.md              ← You are here (entry point)
├── feature_list.json      ← Machine-readable feature backlog
├── progress.md            ← Session progress log
├── session-handoff.md     ← Inter-session handoff
├── DECISIONS.md           ← Architecture decision log
├── Makefile               ← Standardized commands
├── init_check.py          ← Project initialization verifier
├── main.py                ← Entry point (demo / e2e modes)
├── server_api.py          ← Unified web UI (original, port 8080)
├── sender_api.py          ← Sender web UI (C/S split, port 8080)
├── receiver_api.py        ← Receiver web UI + TCP (C/S split, port 8081)
├── test_server_api.py     ← 18 web API tests
├── web/                   ← Web frontend (vanilla HTML/CSS/JS)
│   ├── index.html         ← Unified UI (original)
│   ├── sender.html        ← Sender UI (C/S split)
│   ├── receiver.html      ← Receiver UI (C/S split)
│   ├── css/style.css
│   └── js/
│       ├── pipeline.js
│       ├── crypto.js
│       ├── app.js
│       ├── weather.js
│       ├── sender.js       ← Sender logic (C/S split)
│       └── receiver.js     ← Receiver logic (C/S split)
│
├── data/                  # Sensor & weather data simulation
│   ├── sensor_data.py
│   └── weather_data.py    # Weather fetch (OpenWeatherMap + mock)
├── crypto/                # Cryptography (stdlib only)
│   ├── aes_crypto.py      # AES-128 ECB + PKCS7
│   └── rsa_crypto.py      # RSA-2048 keygen + encrypt/decrypt
├── auth/                  # Message authentication
│   └── hmac_auth.py       # HMAC-SHA256 (SHA-256 + HMAC from scratch)
├── network/               # TCP transmission
│   ├── client.py          # Generate → encrypt → authenticate → send
│   ├── server.py          # Receive → verify → decrypt → output
│   ├── weather_client.py  # Weather frame builder
│   └── weather_server.py  # Weather handler + PCAP generator
│
└── docs/                  # Topic-specific reference docs
    ├── architecture.md    # Layer model, dependency graph
    ├── git-workflow.md    # Branching strategy, commit conventions
    ├── dev-process.md     # Per-feature development workflow
    └── crypto-algorithms.md  # Algorithm principles (for experiment report)
```

---

## Hard Constraints (Non-Negotiable)

1. **One feature at a time.** WIP=1. No skipping ahead.
2. **Stdlib only.** No external crypto libraries. All algorithms from scratch.
3. **Evidence, not claims.** Every completed item must reference actual files.
4. **Verification before completion.** "Code looks fine" != done. Tests must pass.
5. **No debug artifacts.** Remove console.log, commented code, temp files before session exit.
6. **Clean state on exit.** Build passes, tests pass, progress updated, no leftover files.

---

## Feature Development Workflow

Each feature must complete these steps in order:

1. Implement code + tests + update `progress.md` with evidence references
2. Run `make check` — full verification (test + e2e)
3. Run `make done` — verify docs are synced (progress.md, DECISIONS.md)
4. `git add <files>` + `git commit` — pre-commit hook re-verifies docs
5. Update `session-handoff.md`

Then start next feature.

> **Why this order?** `make done` runs BEFORE `git add`, so you can fix
> any doc gaps and re-stage. The pre-commit hook is a safety net — if
> `make done` passes, the hook should never block.

### Two-Step Pre-Commit Verification

```
make done                    # ① Explicit check — fix issues while unstaged
git add <files>
git commit                   # ② Hook auto-runs done_check.py again — safety net
  → hook fails? Fix, re-stage, commit again
  → hook passes? Commit succeeds.
```

---

## Verification Commands

| Command | Description |
|---------|-------------|
| `make test` | Run all 11 core test scripts (151 tests) |
| **`make lint`** | **Syntax + compilation check (stdlib ast + py_compile)** |
| `make web-test` | Run 18 web API tests |
| `make check-web` | test + e2e + web-test combined (169 tests) |
| `make e2e` | Run end-to-end pipeline (embedded server) |
| `make demo` | Run standalone crypto verification |
| **`make check`** | **lint + test + e2e combined** |
| **`make done`** | **Pre-commit doc sync check (progress.md, DECISIONS.md, feature_list.json)** |
| `make setup-hooks` | **Configure git pre-commit hook (run once per clone)** |
| `make exit` | Session exit checklist (5 dimensions) |
| `python init_check.py` | Verify project structure & imports |
| `python test_weather_data.py` | Test weather data module (12 tests) |
| `python test_weather_pipeline.py` | Test weather pipeline (6 tests) |
| `python test_pcap.py` | Test PCAP format (9 tests) |

---

## Session Workflow

**On startup (上班):**
1. Read `progress.md` → know current state
2. Read `DECISIONS.md` → remember key choices
3. Run `make check` → verify clean state (lint + test + e2e)
4. Continue from `progress.md` next steps

**On exit (下班):**
1. Run `make check` → verify everything passes (lint + test + e2e)
2. Run `make done` → verify docs synced
3. Update `progress.md` → record what was done
4. Clean up temp files, debug code
5. `git add <files> && git commit` — hook enforces doc sync
6. Update `session-handoff.md`

---

## Topic Docs (Read as Needed)

- [Architecture](docs/architecture.md) — layer model, dependency graph
- [Git Workflow](docs/git-workflow.md) — branching, commits, remote
- [Dev Process](docs/dev-process.md) — per-feature checklist
- [Crypto Algorithms](docs/crypto-algorithms.md) — algorithm principles for report
