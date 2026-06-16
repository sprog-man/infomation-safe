# Session Handoff Notes

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
## Session: 2026-06-16 — Harness Optimization + feat-009/010 Finalization

### Completed This Session
- **feat-009/010** weather pipeline + C/S split committed and pushed
- **done_check.py** — Pre-commit doc sync verifier (progress.md, feature_list.json, DECISIONS.md, debug artifacts, git state)
- **lint_check.py** — Zero-dependency lint (ast.parse + py_compile, stdlib only)
- **hooks/pre-commit** — Git hook auto-runs done_check.py on every commit
- **exit_check.py** — Synced artifact detection (print(), JS debug patterns)
- **Makefile** — Added `lint`, `done`, `setup-hooks` targets; `check` now = lint+test+e2e
- **init_check.py** — REQUIRED_FILES expanded from 4 to 12
- **.gitignore** — Fixed UTF-16LE corruption, added captures/ and *.key
- **BOM stripping** — Removed UTF-8 BOM from 13 Python files
- **AGENTS.md** — Updated workflow, commands table, session workflow
- **DECISIONS.md** — Added ADR entries for receiver-generated keys
- **.github/workflows/ci.yml** — GitHub Actions CI (Python 3.9-3.12)

### Current Status
- **All 10 features** completed, committed, and pushed to remote
- **40 files** in last commit, 4612 insertions
- **Test count:** 151 core + 18 web = 169 total
- **New harness commands:** `make lint`, `make done`, `make setup-hooks`
- **Git remote:** https://github.com/sprog-man/infomation-safe.git

### What to Do Next
- Project is feature-complete. Future sessions can focus on:
  - Cleaning up 46 debug `print()` calls detected in core modules
  - Experiment report content in `docs/crypto-algorithms.md`
  - Any follow-up tasks

### Known Issues / Notes
- Pre-commit hook requires `make setup-hooks` on fresh clone
- `make check` now runs lint (ast parse + compile) which adds ~2s
- 46 debug `print()` warnings — evaluate which are intentional demo output vs debug residue
- Write tool on this Windows system adds UTF-8 BOM; `lint_check.py` has built-in tolerance

---

## Session: 2026-06-15 — feat-008 (Web Frontend)

### Completed This Session
- **server_api.py** — HTTP server with 9 API endpoints + static file serving
- **test_server_api.py** — 18 tests covering all endpoints, static files, error handling
- **web/index.html** — four-tab SPA: Pipeline Wizard / Crypto Playground / E2E Auto / E2E Manual
- **web/css/style.css** — dark theme, responsive layout
- **web/js/pipeline.js** — 5-step chained pipeline visualizer
- **web/js/crypto.js** — 6 independent crypto operations playground
- **web/js/app.js** — E2E auto (one-click) + manual (step-by-step) modes
- Updated `Makefile`: added `web`, `web-test`, `check-web` targets
- Updated `feature_list.json`: feat-008 entry, total_tests 106→124
- Updated `AGENTS.md`: test count, web commands, directory structure
- Updated `DECISIONS.md`: ADR for web frontend architecture

### Current Status
- **Completed:** feat-001 through feat-008 (all 8 features)
- **Total tests:** 124 (15 + 23 + 28 + 20 + 9 + 4 + 7 + 18)
- **Web UI:** http://localhost:8080
- **Experiment requirements met:** packet capture, file save, frontend display of decrypted data

### What to Do Next
1. Run `make check-web` to verify all tests pass
2. Open http://localhost:8080 in browser and test each tab
3. No pending features — project is complete

### Known Issues / Notes
- Web server uses stdlib `http.server` — not production-grade (no TLS)
- Browser cannot do raw TCP sockets — manual E2E mode uses API fallback
- RSA 2048-bit key generation in browser takes ~10s (pure Python)
- Git remote: https://github.com/sprog-man/infomation-safe.git

---

## Session: 2026-06-15 — Harness Engineering Upgrade

### Completed This Session
- **AGENTS.md** rewritten: 210 lines → 110 lines. Moved低频信息 to `docs/`
- **docs/** created with 4 topic documents:
  - `architecture.md` — layer model, dependency graph, wire frame format
  - `git-workflow.md` — branching strategy, commit conventions, ACID principles
  - `dev-process.md` — per-feature checklist, quality gates
  - `crypto-algorithms.md` — algorithm principles for experiment report
- **Makefile** created: `setup`, `test`, `e2e`, `demo`, `check`, `clean` commands
- **DECISIONS.md** created: 6 architecture decisions with rationale and alternatives
- **feature_list.json** upgraded v1.0 → v2.0:
  - Added `verification` command to each feature
  - Added `verification_suite` top-level object
  - Changed status from `completed` to `passing` (harness-controlled semantics)
  - Set `active_feature` to `null` (all done)
  - Added `all_completed: true` flag
- **session-handoff.md** rewritten: added session workflow, replaced stale entries

### Current State
- All 7 features passing (99/99 tests)
- Harness infrastructure complete (5 subsystems operational)
- Experiment report structure in place (`docs/crypto-algorithms.md`)

### Next Steps
1. Run `make check` to verify full harness works
2. Add `test_end_to_end.py` (referenced in AGENTS.md but missing)
3. Clean up untracked files (`test_sensor_prefix.py`)
4. Add session exit checklist mechanism

### Known Issues / Notes
- AES ECB mode (educational purpose only)
- RSA 2048-bit default key, PKCS#1 v1.5 padding
- All crypto stdlib only — no external dependencies
- Git remote: https://github.com/sprog-man/infomation-safe.git
- Makefile requires `make` (Git Bash / MSYS2 on Windows)

---

## Session: 2026-06-14 (feat-007 complete — ALL FEATURES DONE)

### Completed This Session
- feat-007: main.py — unified entry point with 3 modes (--demo / --e2e / default)
  - `run_standalone_demo()` — 9-step crypto verification without server
  - `run_local_e2e()` — 6-phase pipeline with embedded server thread
  - `main()` — argparse entry point
  - All 99 tests passing across 6 test scripts
- Updated feature_list.json (all features completed)
- Updated progress.md with full feat-007 evidence

### Current Status
- **Completed:** feat-001 through feat-007 (all 7 features)
- **Total tests:** 99 (15 + 23 + 28 + 20 + 9 + 4)
- **Pipeline verified:** standalone demo + E2E both produce correct output

### AGENTS.md Compliance Checklist
1. ✅ One feature at a time — feat-006 then feat-007 sequentially
2. ✅ `python init_check.py` — 7/7 modules, all imports OK
3. ✅ `python test_*.py` — all 6 test scripts pass (99/99)
4. ✅ Updated `progress.md` with evidence references
5. ✅ `git commit` + `git push origin main`
6. ✅ Updated `session-handoff.md`

### Known Issues / Notes
- AES ECB mode (educational purpose)
- RSA 2048-bit default key, PKCS#1 v1.5 padding (probabilistic encryption)
- All crypto stdlib only — no external dependencies
- Git remote: https://github.com/sprog-man/infomation-safe.git
- All features complete; no pending work in feature_list.json

---

## Session: 2026-06-14 (feat-006 complete)

### Completed This Session
- feat-004: auth/hmac_auth.py (20 tests) + test_hmac.py
- feat-005: network/server.py + test_server.py (4 tests)
- feat-006: network/client.py + test_client.py (9 tests)
  - `build_frame()` — AES encrypt + RSA key encrypt + HMAC + pack wire frame
  - `send_frame()` — TCP connect, sendall, receive ACCEPT/REJECT
  - `run_client()` — full pipeline orchestrator
  - Tests: frame format/size/HMAC validity checks + E2E roundtrip + tamper rejection + invalid HMAC + multi-batch
- Updated feature_list.json (active_feature → feat-007)
- Updated progress.md with feat-006 evidence

### Current Status
- **Completed:** feat-001 through feat-006
- **Next:** feat-007 (Integration & Report)

### What to Do Next
1. Create `main.py` — single entry point running full pipeline (client → server E2E)
2. Consider experiment report structure matching AGENTS.md done criteria
3. Ensure `python main.py` runs the complete end-to-end flow
4. Final verification: `python init_check.py`, all test scripts pass

### Known Issues / Notes
- AES ECB mode (educational purpose)
- RSA 2048-bit default key, PKCS#1 v1.5 padding (probabilistic encryption)
- All crypto stdlib only — no external dependencies
- Git remote: https://github.com/sprog-man/infomation-safe.git
- `main.py` does not yet exist — needed for feat-007 and init_check.py 7/7

---

## Session: 2026-06-14 (feat-003 complete)

### Completed This Session
- feat-001: sensor_data.py + test_sensor.py (15 tests)
- feat-002: aes_crypto.py + test_aes.py (23 tests, NIST FIPS-197 vector)
- feat-003: rsa_crypto.py + test_rsa.py (28 tests)
- Created directory structure: data/, crypto/, auth/, network/
- Rewrote AGENTS.md with full architecture, git strategy, 6-step process
- Fixed init_check.py to work with partial project state
- Initialized Git repo with remote origin

### Current Status
- **Completed:** feat-001, feat-002, feat-003
- **Next:** feat-004 (HMAC-SHA256 authentication)

### What to Do Next
1. Implement `auth/hmac_auth.py` — SHA-256 + HMAC from scratch
2. Create `test_hmac.py` — validate tag computation and tamper detection
3. Run `python init_check.py`, `python test_hmac.py`
4. Update progress.md, git commit, push

### Known Issues / Notes
- AES ECB mode (educational purpose)
- RSA 2048-bit default key, PKCS#1 v1.5 padding
- All crypto stdlib only
- Git remote: https://github.com/sprog-man/infomation-safe.git
