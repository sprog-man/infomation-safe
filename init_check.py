"""
init_check.py - Project initialization and verification script.

Run this before starting work to verify the project structure and
that all Python modules can be imported without errors.

Usage: python init_check.py
"""

import sys
import os


REQUIRED_FILES = [
    "AGENTS.md",
    "feature_list.json",
    "progress.md",
    "init_check.py",
]

MODULE_FILES = [
    "sensor_data.py",
    "aes_crypto.py",
    "rsa_crypto.py",
    "hmac_auth.py",
    "client.py",
    "server.py",
    "main.py",
]


def check_python_version():
    """Verify Python 3.6+ is available."""
    if sys.version_info >= (3, 6):
        print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        return True
    else:
        print(f"[FAIL] Python 3.6+ required, found {sys.version_info.major}.{sys.version_info.minor}")
        return False


def check_project_structure():
    """Verify all required baseline files exist."""
    missing = [f for f in REQUIRED_FILES if not os.path.isfile(f)]
    if missing:
        print("[FAIL] Missing required files:")
        for f in missing:
            print(f"  - {f}")
        return False
    print("[OK] All required files present.")

    # Check already-created modules
    existing = [f for f in MODULE_FILES if os.path.isfile(f)]
    if existing:
        print(f"[OK] {len(existing)}/{len(MODULE_FILES)} modules created.")
    else:
        print("[OK] No modules created yet. Ready for feat-001.")
    return True


def check_imports():
    """Verify all created Python modules can be imported."""
    modules = []
    for mod_name in ["sensor_data", "aes_crypto", "rsa_crypto", "hmac_auth", "client", "server"]:
        if os.path.isfile(f"{mod_name}.py"):
            modules.append(mod_name)

    if not modules:
        print("[OK] No modules to import yet.")
        return True

    ok = True
    for mod_name in modules:
        try:
            __import__(mod_name)
            print(f"[OK] Import {mod_name}")
        except ImportError as e:
            print(f"[FAIL] Import {mod_name}: {e}")
            ok = False
    return ok


def main():
    print("=" * 50)
    print("Project Initialization Check")
    print("=" * 50)
    print()

    results = []
    results.append(check_python_version())
    results.append(check_project_structure())
    results.append(check_imports())

    print()
    if all(results):
        print("All checks passed. Ready to work.")
    else:
        print("Some checks failed. Please fix before proceeding.")
        sys.exit(1)


if __name__ == "__main__":
    main()
