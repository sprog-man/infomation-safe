# Git Workflow

## Initialization

```bash
git init
echo "__pycache__/" > .gitignore
echo "*.pyc" >> .gitignore
echo ".env" >> .gitignore
echo "data/" >> .gitignore
```

## Branch Strategy

```
main          # Stable version
├── develop   # Development main branch
    ├── phase/1-sensor-data
    ├── phase/2-aes-encryption
    ├── phase/3-rsa-keygen
    ├── phase/4-hmac-auth
    ├── phase/5-client-server
    └── phase/6-integration
```

**Remote repository:** https://github.com/sprog-man/infomation-safe.git

## Commit Conventions

Use `feat:`, `fix:`, `refactor:`, `docs:`, `test:` prefixes.

Examples:
```
feat: implement sensor data simulation module
test(aes): add round-trip and padding tests
fix(hmac): correct HMAC tag computation for empty messages
docs: update AGENTS.md with directory structure
```

## Workflow

1. `git checkout -b phase/N-description` from `main`
2. Implement locally + test, commit frequently
3. Merge to `main`: `git checkout main && git merge --no-ff phase/N-description`
4. Push to remote: `git push origin main`

## ACID Principles for Agent State

- **Atomicity**: Each logical operation (e.g., "add new endpoint + tests") is one git commit. Rollback with `git stash` if interrupted.
- **Consistency**: Define verification predicates (all tests pass, lint clean). Don't commit intermediate inconsistent states.
- **Isolation**: Multiple agents use independent branches to avoid race conditions on state files.
- **Durability**: Critical project knowledge persisted in git-tracked files. Temporary state stays in session memory only.
