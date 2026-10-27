#!/usr/bin/env bash
# Install on macOS/Linux (or Git Bash with native Windows Python).
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for arg in "$@"; do
    if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
        cat <<'EOF'
Usage: bash install.sh [--verbose] [--lab] [--reinstall]
Creates .venv, installs dependencies, initializes the catalog, checks egress,
runs the MCP smoke test, and prints client configuration.
Set ANTICELLS_RED_MCP_PYTHON to select a Python >= 3.10 interpreter.
On Windows PowerShell, use: .\install.ps1
EOF
        exit 0
    fi
done

candidates=()
if [[ -n "${ANTICELLS_RED_MCP_PYTHON:-}" ]]; then
    candidates+=("$ANTICELLS_RED_MCP_PYTHON")
else
    candidates+=(python3.15 python3.14 python3.13 python3.12 python3.11 python3.10 python3 python)
fi
for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1 && \
        PY=$("$candidate" -c 'import sys; sys.exit(10) if sys.version_info < (3, 10) else sys.stdout.write(getattr(sys, "_base_executable", sys.executable))' 2>/dev/null); then
        # Start the base interpreter so --reinstall can replace an active venv.
        if command -v cygpath >/dev/null 2>&1; then PY=$(cygpath -u "$PY"); fi
        exec "$PY" "$PROJECT_ROOT/scripts/install.py" "$@"
    fi
done
printf '[FAIL] No Python >= 3.10 found. Install one or set ANTICELLS_RED_MCP_PYTHON.\n' >&2
exit 10
