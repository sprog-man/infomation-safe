# Session Handoff Notes

## Session: 2026-06-14

### Completed This Session
- Rewrote AGENTS.md with full project structure, architecture, git strategy, and 6-step feature development process
- Created `sensor_data.py` — sensor data simulation (temperature, humidity, pressure)
- Created `test_sensor.py` — 15 tests, all passing
- Created `aes_crypto.py` — AES-128 from scratch (S-Box, key expansion, encrypt/decrypt, PKCS7)
- Created `test_aes.py` — 23 tests, all passing (includes NIST FIPS-197 test vector)
- Fixed `init_check.py` — now adapts to partial project state (only checks existing modules)
- Initialized Git repo, added remote origin
- Updated `progress.md` with evidence for feat-001 and feat-002

### Current Status
- **Completed:** feat-001, feat-002
- **In Progress:** feat-003 (RSA)
- **Pending:** feat-004 (HMAC), feat-005 (Server), feat-006 (Client), feat-007 (Integration)

### What to Do Next
1. Implement `rsa_crypto.py` — RSA key generation, encrypt, decrypt (from scratch, stdlib only)
2. Create `test_rsa.py` — validate key pair generation and encrypt/decrypt round-trip
3. Run `python init_check.py`
4. Run `python test_rsa.py`
5. Update `progress.md` with evidence
6. Git commit with `feat:` prefix
7. Update this file

### Known Issues / Notes
- `gmul(0xFE, 0x02)` returns `0xE7` (correct per GF(2^8) math with polynomial 0x11B)
- AES ECB mode only (suitable for this educational experiment)
- All crypto implemented from scratch — no external libraries
- Git remote: https://github.com/sprog-man/infomation-safe.git

