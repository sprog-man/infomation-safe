# Agent Working Rules

## Project Overview

**Information Safety Experiment** — End-to-end network data security pipeline:
sensor data simulation → AES-128 encryption → RSA key exchange → HMAC-SHA256 authentication → TCP transmission → full integration.

All crypto implemented from scratch. Zero external dependencies.

---

## Quick Start

```bash
python init_check.py    # Verify project structure & imports
make test               # Run all 7 core test scripts (106 tests)
make web-test           # Run 18 web API tests
make check              # Full verification (test + e2e)
make check-web          # Full verification including web
make exit               # Session exit checklist (5 dimensions)
make demo               # Standalone crypto demo (no server)
make e2e                # End-to-end pipeline (embedded server)
make web                # Start web UI at http://localhost:8080
python main.py          # Default: demo + e2e
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
├── server_api.py          ← Web UI server (http://localhost:8080)
├── test_server_api.py     ← 18 web API tests
├── web/                   ← Web frontend (vanilla HTML/CSS/JS)
│   ├── index.html
│   ├── css/style.css
│   └── js/
│
├── data/                  # Sensor data simulation
│   └── sensor_data.py
├── crypto/                # Cryptography (stdlib only)
│   ├── aes_crypto.py      # AES-128 ECB + PKCS7
│   └── rsa_crypto.py      # RSA-2048 keygen + encrypt/decrypt
├── auth/                  # Message authentication
│   └── hmac_auth.py       # HMAC-SHA256 (SHA-256 + HMAC from scratch)
├── network/               # TCP transmission
│   ├── client.py          # Generate → encrypt → authenticate → send
│   └── server.py          # Receive → verify → decrypt → output
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

1. Implement code + tests
2. `python init_check.py` — verify all modules load
3. `python test_*.py` — run corresponding tests
4. `make check` — full verification
5. Update `progress.md` with evidence references
6. `git commit` with `feat:` prefix
7. Update `session-handoff.md`

Then start next feature.

---

## Verification Commands

| Command | Description |
|---------|-------------|
| `make test` | Run all 7 core test scripts (106 tests) |
| `make web-test` | Run 18 web API tests |
| `make check-web` | test + e2e + web-test combined (124 tests) |
| `make e2e` | Run end-to-end pipeline (embedded server) |
| `make demo` | Run standalone crypto verification |
| `make check` | test + e2e combined |
| `make exit` | Session exit checklist (5 dimensions) |
| `python init_check.py` | Verify project structure & imports |

---

## Session Workflow

**On startup (上班):**
1. Read `progress.md` → know current state
2. Read `DECISIONS.md` → remember key choices
3. Run `make check` → verify clean state
4. Continue from `progress.md` next steps

**On exit (下班):**
1. Run `make check` → verify everything passes
2. Update `progress.md` → record what was done
3. Clean up temp files, debug code
4. Commit all completed work
5. Update `session-handoff.md`

---

## Topic Docs (Read as Needed)

- [Architecture](docs/architecture.md) — layer model, dependency graph
- [Git Workflow](docs/git-workflow.md) — branching, commits, remote
- [Dev Process](docs/dev-process.md) — per-feature checklist
- [Crypto Algorithms](docs/crypto-algorithms.md) — algorithm principles for report
