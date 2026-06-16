"""
lint_check.py — Zero-dependency Python linter.

Uses only stdlib modules (ast, py_compile) to check:
  1. Syntax validity — every .py file must parse without errors
  2. Module compilation — every .py file must compile cleanly
  3. (reserved for future checks)

Usage:
    python lint_check.py              # full scan
    python lint_check.py path/to.py   # single file
"""

import ast
import os
import py_compile
import sys
import traceback
from io import StringIO

EXCLUDE_DIRS = {"__pycache__", ".git", "hooks", ".claude", ".venv", "venv", "env"}
EXCLUDE_FILES: set[str] = set()


def _find_py_files(rootdir: str = ".") -> list[str]:
    """Recursively find all .py files, respecting EXCLUDE_DIRS."""
    files: list[str] = []
    for root, dirs, names in os.walk(rootdir):
        # Prune excluded dirs in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in names:
            if name in EXCLUDE_FILES:
                continue
            if name.endswith(".py"):
                files.append(os.path.join(root, name))
    return sorted(files)


def _strip_bom(source: str) -> str:
    """Remove UTF-8 BOM if present."""
    return source.lstrip("﻿")


def check_syntax(files: list[str]) -> list[str]:
    """Parse each .py file with ast.parse — catches syntax errors."""
    errors: list[str] = []
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                source = f.read()
            source = _strip_bom(source)
            ast.parse(source, filename=fpath)
        except SyntaxError:
            errors.append(f"[SYNTAX] {fpath}")
            # Print the traceback so the user can see the exact error
            traceback.print_exc()
        except Exception as e:
            errors.append(f"[ERROR] {fpath}: {e}")
    return errors


def check_compile(files: list[str]) -> list[str]:
    """Compile each .py file with py_compile — catches deeper errors."""
    errors: list[str] = []
    for fpath in files:
        try:
            # Capture compile output to avoid cluttering stdout
            old_stderr = sys.stderr
            sys.stderr = StringIO()
            py_compile.compile(fpath, doraise=True)
            sys.stderr = old_stderr
        except py_compile.PyCompileError as e:
            sys.stderr = old_stderr
            errors.append(f"[COMPILE] {fpath}: {e}")
        except Exception as e:
            errors.append(f"[COMPILE] {fpath}: {e}")
    return errors


def main() -> None:
    if len(sys.argv) > 1:
        files = [f for f in sys.argv[1:] if f.endswith(".py")]
    else:
        files = _find_py_files()

    if not files:
        print("No .py files to check.")
        sys.exit(0)

    print(f"Checking {len(files)} Python files...")
    print()

    all_errors: list[str] = []

    # 1. Syntax check
    print("  [ast.parse]")
    syntax_errs = check_syntax(files)
    for err in syntax_errs:
        print(f"    {err}")
    if not syntax_errs:
        print("    OK — all files parse correctly")
    all_errors.extend(syntax_errs)
    print()

    # 2. Compile check
    print("  [py_compile]")
    compile_errs = check_compile(files)
    for err in compile_errs:
        print(f"    {err}")
    if not compile_errs:
        print("    OK — all files compile cleanly")
    all_errors.extend(compile_errs)
    print()

    # Summary
    print("-" * 55)
    if not all_errors:
        print("  No lint issues found.")
    else:
        print(f"  {len(all_errors)} issue(s) found.")
        sys.exit(1)


if __name__ == "__main__":
    main()
