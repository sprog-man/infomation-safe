# Dev Process

## Per-Feature Checklist

Every feature must follow this exact sequence. Do not skip or reorder.

### 1. Implementation
- [ ] Write module code with type hints and Google-style docstrings
- [ ] Every algorithm function must have comments explaining its logic
- [ ] Write matching `test_*.py` file

### 2. Verification
- [ ] `python init_check.py` — all modules load
- [ ] `python test_*.py` — all tests pass
- [ ] `make check` — full verification suite

### 3. Documentation
- [ ] Update `progress.md` with evidence references (file paths, line numbers)
- [ ] Update `feature_list.json` status if applicable

### 4. Commit
- [ ] `git commit -m "feat: <description>"`
- [ ] Include only files that changed for this feature

### 5. Handoff
- [ ] Update `session-handoff.md` with what was done
- [ ] Note any known issues or decisions made

## Quality Gates

| Gate | Condition | Action if Failed |
|------|-----------|------------------|
| init_check | All modules importable | Fix import errors before proceeding |
| unit tests | 100% pass rate | Debug and fix, do not skip |
| e2e pipeline | Full roundtrip succeeds | Check interface mismatches between layers |
| clean state | No temp files, no debug code | Clean up before session exit |

## Common Failure Modes

See [AGENTS.md](../AGENTS.md) Hard Constraints and [心得总结.md](../../Harness-Engineering/心得总结.md) Chapter 1 for root cause analysis patterns.
