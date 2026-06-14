# Session Handoff Notes

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

