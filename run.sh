#!/usr/bin/env bash
set -euo pipefail
# Resolve the checkout independently of the MCP client's working directory.
anticells_red_mcp_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
anticells_red_mcp_python="${ANTICELLS_RED_MCP_PYTHON:-python3}"
if [[ -z "${ANTICELLS_RED_MCP_PYTHON:-}" ]]; then
    if [[ -x "$anticells_red_mcp_root/.venv/bin/python" ]]; then
        anticells_red_mcp_python="$anticells_red_mcp_root/.venv/bin/python"
    elif [[ -x "$anticells_red_mcp_root/venv/bin/python" ]]; then
        anticells_red_mcp_python="$anticells_red_mcp_root/venv/bin/python"
    fi
fi
export PYTHONPATH="$anticells_red_mcp_root/src${PYTHONPATH:+:$PYTHONPATH}"
exec "$anticells_red_mcp_python" -m anticells_red_mcp.mcp_server.server "$@"
