"""
done_check.py — Pre-commit documentation sync verifier.

Ensures that when source code changes, the corresponding documentation
(progress.md, DECISIONS.md) is also updated. Designed to be run via
`make done` BEFORE `git commit`.

Usage:
    python done_check.py          # normal mode — fails if docs out of sync
    python done_check.py --git    # pre-commit hook mode — exits cleanly for no-op

Exit codes:
    0 — all checks pass
    1 — one or more checks failed
"""

import os
import sys
import subprocess
import time

REQUIRED_DOCS = ["progress.md"]
CORE_MODULE_PATTERNS = [
    "crypto/", "auth/", "network/", "data/",
    "server_api.py", "sender_api.py", "receiver_api.py",
    "main.py",
]


def _run_git(args: list[str], timeout: int = 10) -> str:
    """Run a git command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _get_all_changed_files() -> set[str]:
    """Get all files that are staged, modified, or untracked."""
    staged = _run_git(["diff", "--cached", "--name-only"])
    modified = _run_git(["diff", "--name-only"])
    untracked = _run_git(["ls-files", "--others", "--exclude-standard"])

    result: set[str] = set()
    for group in [staged, modified, untracked]:
        if group:
            result.update(group.split("\n"))
    return result


def _get_source_files(changed: set[str]) -> set[str]:
    """Filter changed files to core source files (not test files or docs)."""
    return {
        f for f in changed
        if f.endswith(".py") and not f.startswith("test_")
        and f not in ("done_check.py", "init_check.py", "exit_check.py")
    }


def _get_core_module_changes(changed: set[str]) -> set[str]:
    """Filter to files in core module directories (architecture-significant)."""
    core_changed: set[str] = set()
    for f in changed:
        for pat in CORE_MODULE_PATTERNS:
            if f.startswith(pat) and f.endswith(".py"):
                core_changed.add(f)
                break
    return core_changed


def check_progress_md(all_changed: set[str]) -> bool:
    """progress.md must be updated if source files changed."""
    source_files = _get_source_files(all_changed)

    if not source_files:
        print("  [SKIP] No source changes detected")
        return True

    if "progress.md" not in all_changed:
        # Check file timestamps as a fallback (staged files may be old)
        src_mtime = 0.0
        for f in source_files:
            try:
                mtime = os.path.getmtime(f)
                if mtime > src_mtime:
                    src_mtime = mtime
            except OSError:
                pass

        doc_mtime = 0.0
        try:
            doc_mtime = os.path.getmtime("progress.md")
        except OSError:
            pass

        if doc_mtime < src_mtime - 5:
            print("  [FAIL] progress.md is out of date")
            print(f"         Source files modified:")
            for sf in sorted(source_files):
                print(f"           {sf}")
            print("         Update progress.md with evidence references first")
            print(f"         Then: git add progress.md")
            return False

    print(f"  [OK] progress.md updated alongside source changes")
    return True


def check_decisions_md(all_changed: set[str]) -> bool:
    """Warn if core modules changed but DECISIONS.md wasn't updated."""
    core_changes = _get_core_module_changes(all_changed)

    if not core_changes:
        return True

    if "DECISIONS.md" not in all_changed:
        print("  [WARN] Core modules changed but DECISIONS.md not updated")
        print(f"         Files changed: {', '.join(sorted(core_changes))}")
        print("         Did you make an architectural decision?")
        print("         If yes: add an ADR entry to DECISIONS.md")
        return True  # warn only, not fail

    print("  [OK] DECISIONS.md is current")
    return True


def check_feature_list_json(all_changed: set[str]) -> bool:
    """Warn if progress.md changed but feature_list.json wasn't updated.

    progress.md changing often means a feature was completed, which
    should also be reflected in feature_list.json (status, evidence).
    """
    if "progress.md" not in all_changed:
        return True  # no feature-status change expected

    if "feature_list.json" not in all_changed:
        print("  [WARN] progress.md changed but feature_list.json was not")
        print("         If a feature was completed, update its status and evidence")
        print("         in feature_list.json, then bump the version field.")
        return True  # warn only — some progress.md edits aren't feature-complete

    print("  [OK] feature_list.json updated alongside progress.md")
    return True


def check_session_handoff(all_changed: set[str]) -> bool:
    """Remind about session-handoff.md if source changed."""
    source_files = _get_source_files(all_changed)
    if not source_files:
        return True

    if "session-handoff.md" not in all_changed:
        print("  [HINT] session-handoff.md wasn't updated")
        print("         Update it at session exit for next-session handoff")
        return True

    return True


def check_git_state() -> bool:
    """Show current git state summary."""
    status = _run_git(["status", "--short"])
    if status:
        lines = status.split("\n")
        staged_count = sum(1 for l in lines if l and l[0] != "?" and l[0] != " ")
        unstaged_count = sum(1 for l in lines if l and l[0] == " ")
        untracked_count = sum(1 for l in lines if l and l[0] == "?")
        parts = []
        if staged_count:
            parts.append(f"{staged_count} staged")
        if unstaged_count:
            parts.append(f"{unstaged_count} unstaged")
        if untracked_count:
            parts.append(f"{untracked_count} untracked")
        print(f"  [INFO] {', '.join(parts)} changes — run 'git status' for details")
    else:
        print("  [OK] Working tree clean")
    return True


def check_no_debug_artifacts() -> bool:
    """Quick scan for common debug artifacts in core modules."""
    debug_patterns = [
        ("breakpoint()", "breakpoint"),
        ("pdb.set_trace()", "pdb"),
        ("print(", "debug print"),
    ]
    source_dirs = ["data", "crypto", "auth", "network"]
    found = False

    for src_dir in source_dirs:
        if not os.path.isdir(src_dir):
            continue
        for root, _dirs, files in os.walk(src_dir):
            for pyfile in files:
                if not pyfile.endswith(".py"):
                    continue
                path = os.path.join(root, pyfile)
                with open(path, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        stripped = line.strip()
                        for pattern, label in debug_patterns:
                            if stripped.startswith(pattern):
                                print(f"  [WARN] {path}:{i} contains {label}")
                                found = True
                                break
    if not found:
        print("  [OK] No debug artifacts in core modules")
    return True


def main() -> None:
    is_git_hook = "--git" in sys.argv

    all_changed = _get_all_changed_files()

    print("=" * 55)
    print(" Pre-Commit Done Checklist")
    print("=" * 55)
    print()

    checks = [
        ("1. progress.md | code sync", lambda: check_progress_md(all_changed)),
        ("2. feature_list.json | feature status", lambda: check_feature_list_json(all_changed)),
        ("3. DECISIONS.md | ADR logged", lambda: check_decisions_md(all_changed)),
        ("4. session-handoff.md", lambda: check_session_handoff(all_changed)),
        ("5. git state", check_git_state),
        ("6. debug artifacts", check_no_debug_artifacts),
    ]

    all_pass = True
    for name, check_fn in checks:
        print(f"  [{name}]")
        ok = check_fn()
        if not ok:
            all_pass = False
        print()

    print("-" * 55)
    if all_pass:
        print("  All checks passed.")
        print()
        print("  Next steps:")
        print("    1. git add <files>  (stage changes)")
        print("    2. git commit -m 'feat: <description>'")
        print("    3. Update session-handoff.md (if this was the last task)")
    else:
        print("  FAILED — fix issues above before committing.")
        sys.exit(1)


if __name__ == "__main__":
    main()
