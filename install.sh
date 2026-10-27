#!/usr/bin/env bash
#
# anticells_red_mcp installer.
#
# Zero-flag install:   bash install.sh
# Verbose install:     bash install.sh --verbose
# Opt-in lab mode:     bash install.sh --lab
# Pick an interpreter: ANTICELLS_RED_MCP_PYTHON=/path/to/python3.12 bash install.sh
#
# What it does, in order (each step prints its own OK/FAIL marker):
#   1. find a Python >= 3.10 interpreter
#   2. create a project-local .venv (fresh if --reinstall)
#   3. install the package and its runtime dependencies
#   4. initialize the SQLite catalog (365 techniques + 131 resources)
#   5. run the egress self-test (default policy must reject 127.0.0.1)
#   6. run a stdio smoke test (12 tools listed, local mutation returns)
#   7. print a copy-paste MCP client configuration block
#
# Exit codes are stable:
#   0  success
#   10 python interpreter missing or < 3.10
#   11 venv creation failed
#   12 pip install failed
#   13 catalog initialization failed
#   14 egress self-test failed
#   15 stdio smoke test failed
#
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="$PROJECT_ROOT/.venv"
VERBOSE=0
LAB=0
REINSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose|-v) VERBOSE=1 ;;
        --lab)        LAB=1 ;;
        --reinstall)  REINSTALL=1 ;;
        --venv)       : ;; # historical no-op; venv is always created
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            exit 2 ;;
    esac
    shift
done

# ---------- helpers ----------

RED=''; GREEN=''; YELLOW=''; DIM=''; BOLD=''; RESET=''
if [[ -t 2 ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    DIM=$'\033[2m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
fi

say()   { printf '%s%s%s\n' "$DIM" "$*" "$RESET" >&2; }
step()  { printf '%s==> %s%s\n' "$BOLD" "$*" "$RESET" >&2; }
ok()    { printf '  %s[ok]%s %s\n' "$GREEN" "$RESET" "$*" >&2; }
warn()  { printf '  %s[!!]%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()   { local code="$1"; shift; printf '  %s[FAIL]%s %s\n' "$RED" "$RESET" "$*" >&2; exit "$code"; }

run_quiet() {
    if (( VERBOSE )); then
        "$@" >&2
    else
        local output
        if ! output=$("$@" 2>&1); then
            printf '%s\n' "$output" >&2
            return 1
        fi
    fi
}

# ---------- 1. python ----------

step "1/7  Finding a Python >= 3.10 interpreter"
candidates=()
if [[ -n "${ANTICELLS_RED_MCP_PYTHON:-}" ]]; then candidates+=("$ANTICELLS_RED_MCP_PYTHON"); fi
candidates+=(python3.13 python3.12 python3.11 python3.10 python3 python)
PY=""
for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
            PY="$(command -v "$candidate")"
            break
        fi
    fi
done
[[ -n "$PY" ]] || die 10 "no Python >= 3.10 found (tried: ${candidates[*]}). Install one or set ANTICELLS_RED_MCP_PYTHON."
PY_VERSION=$("$PY" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
ok "using $PY (Python $PY_VERSION)"

# ---------- 2. venv ----------

step "2/7  Creating project-local virtual environment"
if (( REINSTALL )) && [[ -d "$VENV" ]]; then
    say "    (--reinstall) removing existing $VENV"
    rm -rf "$VENV"
fi
if [[ -x "$VENV/bin/python" ]]; then
    ok "re-using existing $VENV"
else
    run_quiet "$PY" -m venv "$VENV" || die 11 "venv creation failed; try: $PY -m ensurepip && rerun"
    ok "created $VENV"
fi

# ---------- 3. pip install ----------

step "3/7  Installing dependencies and the anticells_red_mcp package"
run_quiet "$VENV/bin/python" -m pip install --upgrade --disable-pip-version-check pip wheel setuptools \
    || die 12 "failed to upgrade pip/wheel/setuptools"
run_quiet "$VENV/bin/python" -m pip install --disable-pip-version-check "$PROJECT_ROOT" \
    || die 12 "pip install failed; rerun with --verbose to see the full log"
ok "package and runtime deps installed"

# ---------- 4. catalog ----------

step "4/7  Initializing SQLite catalog (365 techniques + 131 resources)"
CATALOG_OUTPUT=""
if ! CATALOG_OUTPUT=$("$VENV/bin/python" -m anticells_red_mcp.catalog.cli setup 2>&1); then
    printf '%s\n' "$CATALOG_OUTPUT" >&2
    die 13 "catalog initialization failed"
fi
# catalog.cli prints one JSON object across multiple lines (indent=2).
CATALOG_SUMMARY=$(printf '%s' "$CATALOG_OUTPUT" | "$VENV/bin/python" -c '
import json, sys
try:
    doc = json.loads(sys.stdin.read())
    if doc.get("schema_version") != 1:
        raise ValueError("unexpected schema_version")
    print("revision={} changed={}".format(doc.get("revision"), doc.get("changed")))
except Exception as exc:
    print("PARSE_ERROR:" + repr(exc), file=sys.stderr)
    sys.exit(2)
' 2>&1) || { printf '%s\n' "$CATALOG_OUTPUT" >&2; die 13 "catalog returned an unexpected initialization response ($CATALOG_SUMMARY)"; }
ok "catalog ready ($CATALOG_SUMMARY)"

# ---------- 5. egress self-test ----------

step "5/7  Running egress policy self-test"
SELFTEST=$("$VENV/bin/python" -c '
from anticells_red_mcp.mcp_server.endpoint_safety import self_test
ok, reason = self_test()
print("OK" if ok else "FAIL:" + reason)
' 2>&1) || die 14 "egress self-test crashed: $SELFTEST"
if [[ "$SELFTEST" != "OK" ]]; then
    die 14 "egress self-test refused the default policy: $SELFTEST"
fi
ok "default policy rejects loopback / private / link-local / multicast / reserved"

# ---------- 6. stdio smoke test ----------

step "6/7  Launching the real MCP server and listing tools"
SMOKE_OUTPUT=$(ANTICELLS_RED_MCP_PYTHON="$VENV/bin/python" \
    "$VENV/bin/python" "$PROJECT_ROOT/scripts/post_install_smoke.py" "$PROJECT_ROOT" 2>&1) \
    || { printf '%s\n' "$SMOKE_OUTPUT" >&2; die 15 "stdio smoke test failed"; }
printf '%s\n' "$SMOKE_OUTPUT" | sed 's/^/    /' >&2
ok "stdio server up, 12 tools visible, local mutation works"

# ---------- 7. client config ----------

step "7/7  Ready. Copy this entry into your MCP client's config:"
CONFIGS=$("$VENV/bin/python" - <<PY
import json
root = "$PROJECT_ROOT"
venv = "$VENV"
lab = $LAB
env = {"ANTICELLS_RED_MCP_PYTHON": venv + "/bin/python"}
if lab:
    env["ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS"] = "true"
opencode = {"mcp": {"anticells_red_mcp": {
    "type": "local",
    "command": ["bash", root + "/run.sh"],
    "enabled": True,
    "environment": env,
}}}
claude = {"mcpServers": {"anticells_red_mcp": {
    "command": "bash",
    "args": [root + "/run.sh"],
    "env": env,
}}}
print("---OPENCODE---")
print(json.dumps(opencode, indent=2))
print("---CLAUDE---")
print(json.dumps(claude, indent=2))
PY
)
OPENCODE_CFG=$(printf '%s' "$CONFIGS" | awk '/^---OPENCODE---$/{f=1;next}/^---CLAUDE---$/{f=0}f')
CLAUDE_CFG=$(printf '%s' "$CONFIGS" | awk '/^---CLAUDE---$/{f=1;next}f')

if (( LAB )); then LAB_LINE="    (lab mode active — ALLOW_PRIVATE_TARGETS=true is included above.)"
else LAB_LINE="    (lab mode off — add ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS=true if you need to probe a target on your own network.)"
fi

cat >&2 <<EOF

${BOLD}# opencode (~/.config/opencode/opencode.json) — merge the "mcp" key:${RESET}
$OPENCODE_CFG

${BOLD}# Claude Desktop (~/.config/Claude/claude_desktop_config.json) — merge "mcpServers":${RESET}
$CLAUDE_CFG

${DIM}# Direct launch (for CI or debugging):
#     bash "$PROJECT_ROOT/run.sh"${RESET}

${BOLD}What's next${RESET}
  * See ${BOLD}SECURITY.md${RESET} for the 1.1.0 trust model (egress policy, env whitelist, request caps).
$LAB_LINE
  * Re-run this self-check anytime:          bash "$PROJECT_ROOT/install.sh"
  * Deeper diagnostic any time:              "$VENV/bin/anticells_red_mcp-doctor"
EOF
ok "install complete"
