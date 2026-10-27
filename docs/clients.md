# Connect an MCP client

Anticells Red MCP uses stdio. The client starts the server as a child process with these settings:

| Setting | Value |
| :--- | :--- |
| Command | Absolute path to `.venv/bin/python` (Windows: `.venv\Scripts\python.exe`) |
| Arguments | `-m`, `anticells_red_mcp.mcp_server.server` |
| Working directory | Any directory when configured file paths are absolute; the package is installed in the virtual environment |

Use absolute paths. Merge only this server entry into your existing client configuration. Restart the client after saving, then confirm that 12 tools are available.

## Clients with an mcpServers configuration

```json
{
  "mcpServers": {
    "anticells_red_mcp": {
      "command": "/absolute/path/Anticells_Red_MCP/.venv/bin/python",
      "args": ["-m", "anticells_red_mcp.mcp_server.server"]
    }
  }
}
```

This is the configuration shape used by clients such as Claude Desktop and Cursor. Their file locations and management interfaces vary; consult the current [Cursor MCP guide](https://cursor.com/docs/mcp) or [Claude Desktop guide](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) for client-specific setup.

On native Windows, use the configuration printed by `install.ps1`, for example:

```json
{
  "mcpServers": {
    "anticells_red_mcp": {
      "command": "C:\\path\\Anticells_Red_MCP\\.venv\\Scripts\\python.exe",
      "args": ["-m", "anticells_red_mcp.mcp_server.server"]
    }
  }
}
```

## OpenCode

OpenCode uses `mcp`, `type`, and a command array:

```json
{
  "mcp": {
    "anticells_red_mcp": {
      "type": "local",
      "command": ["/absolute/path/Anticells_Red_MCP/.venv/bin/python", "-m", "anticells_red_mcp.mcp_server.server"],
      "enabled": true
    }
  }
}
```

Add target settings through the entry's `environment` object when needed. To select another Python interpreter, change the first element of `command`; `ANTICELLS_RED_MCP_PYTHON` only selects an interpreter for the installer or optional Bash launcher. See the [OpenCode MCP documentation](https://opencode.ai/docs/mcp-servers/) for configuration locations and management commands.

## Other clients and SDKs

Register a local stdio server using the virtual-environment Python and the module arguments above. Clients may use TOML, JSON, or a CLI to store that registration; do not copy one client's configuration schema into another.

Windows clients can launch native Python directly. If you choose WSL instead, install inside WSL and configure the Windows client to launch that distribution with `wsl.exe`; Linux paths belong to that environment. The macOS/Linux `run.sh` helper remains available and respects `ANTICELLS_RED_MCP_PYTHON`.

## Configure credentials

Keep credentials outside the README and shared client examples. Set only the required environment variables in your local client configuration, or select an explicit private environment file with `ANTICELLS_RED_MCP_ENV_FILE`.

For authenticated legacy calls, configure both `ANTICELLS_RED_MCP_TARGET_API_URL` and `ANTICELLS_RED_MCP_TARGET_API_KEY`. The bearer credential is bound to that configured origin. Saved profiles have their own authentication headers and environment restrictions; see [targets](targets.md) and [security](../SECURITY.md).

If startup fails, run the [installation checks](installation.md#verify-the-mcp-connection) before changing client settings.
