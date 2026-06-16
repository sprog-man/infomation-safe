"""
exit_check.py — Session exit checklist verifier.

Ensures the repository is in a clean state before a session ends.
Checks all 5 dimensions from harness engineering best practices:
  1. Build passes (imports work)
  2. Tests pass
  3. Progress is recorded
  4. No debug artifacts remain
  5. Standard startup path is usable

Usage: python exit_check.py
"""

import sys
import os
import subprocess
import glob


def check_imports() -> bool:
    """Dimension 1: All modules can be imported."""
    modules = [
        "data.sensor_data",
        "crypto.aes_crypto",
        "crypto.rsa_crypto",
        "auth.hmac_auth",
        "network.client",
        "network.server",
        "main",
    ]
    ok = True
    for mod in modules:
        try:
            __import__(mod)
        except ImportError as e:
            print(f"  [FAIL] Cannot import {mod}: {e}")
            ok = False
    if ok:
        print("  [OK] All modules importable")
    return ok


def check_tests() -> bool:
    """Dimension 2: All test scripts pass."""
    test_files = sorted(glob.glob("test_*.py"))
    if not test_files:
        print("  [WARN] No test files found")
        return True

    all_passed = True
    for tf in test_files:
        try:
            result = subprocess.run(
                [sys.executable, tf],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print(f"  [OK] {tf}")
            else:
                print(f"  [FAIL] {tf}")
                all_passed = False
        except subprocess.TimeoutExpired:
            print(f"  [FAIL] {tf} (timeout)")
            all_passed = False
        except Exception as e:
            print(f"  [FAIL] {tf}: {e}")
            all_passed = False

    if all_passed:
        print("  [OK] All tests pass")
    return all_passed


def check_progress_updated() -> bool:
    """Dimension 3: progress.md exists and is non-empty."""
    if os.path.isfile("progress.md") and os.path.getsize("progress.md") > 0:
        print("  [OK] progress.md exists and is non-empty")
        return True
    print("  [FAIL] progress.md missing or empty")
    return False


def check_no_debug_artifacts() -> bool:
    """Dimension 4: No debug code left behind in source files."""

    # Python debug patterns (checked in .py files)
    py_debug_patterns = [
        ("breakpoint()", "breakpoint"),
        ("pdb.set_trace()", "pdb"),
    ]

    # Debug print — flagged separately (some prints are intentional in CLI tools)
    print_pattern = ("print(", "debug print")

    # JS debug patterns (checked in web/js/ files)
    js_debug_patterns = [
        ("console.log", "console.log"),
        ("debugger;", "debugger"),
    ]

    scan_targets = {
        "data": {"ext": ".py", "patterns": py_debug_patterns + [print_pattern]},
        "crypto": {"ext": ".py", "patterns": py_debug_patterns + [print_pattern]},
        "auth": {"ext": ".py", "patterns": py_debug_patterns + [print_pattern]},
        "network": {"ext": ".py", "patterns": py_debug_patterns + [print_pattern]},
        "web/js": {"ext": ".js", "patterns": js_debug_patterns},
    }

    found = False
    for src_dir, config in scan_targets.items():
        if not os.path.isdir(src_dir):
            continue
        for root, _dirs, files in os.walk(src_dir):
            for fname in files:
                if not fname.endswith(config["ext"]):
                    continue
                path = os.path.join(root, fname)
                with open(path, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        stripped = line.strip()
                        for pattern, label in config["patterns"]:
                            if stripped.startswith(pattern):
                                print(f"  [WARN] {path}:{i} contains {label}")
                                found = True
                                break

    if not found:
        print("  [OK] No debug artifacts found")
    return not found


def check_startup_path() -> bool:
    """Dimension 5: python main.py --demo works."""
    try:
        result = subprocess.run(
            [sys.executable, "main.py", "--demo"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print("  [OK] python main.py --demo succeeds")
            return True
        else:
            print(f"  [FAIL] main.py --demo returned {result.returncode}")
            return False
    except subprocess.TimeoutExpired:
        print("  [FAIL] main.py --demo timed out")
        return False
    except FileNotFoundError:
        print("  [FAIL] main.py not found")
        return False


def main() -> None:
    print("=" * 55)
    print(" Session Exit Checklist")
    print("=" * 55)
    print()

    checks = [
        ("1. Build (imports)", check_imports),
        ("2. Tests", check_tests),
        ("3. Progress recorded", check_progress_updated),
        ("4. No debug artifacts", check_no_debug_artifacts),
        ("5. Startup path", check_startup_path),
    ]

    results = []
    for name, check_fn in checks:
        print(f"  [{name}]")
        results.append(check_fn())
        print()

    print("-" * 55)
    passed = sum(results)
    total = len(results)

    if all(results):
        print(f"  All {total}/{total} checks passed. Clean exit confirmed.")
        print()
        print("  Ready to commit and close session.")
    else:
        print(f"  {passed}/{total} checks passed. {total - passed} FAILED.")
        print()
        print("  FIX the failing checks before exiting the session.")
        print("  Do NOT commit with a dirty state.")
        sys.exit(1)


if __name__ == "__main__":
    main()
