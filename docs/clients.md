# Connect an MCP client

Anticells Red MCP uses stdio. The client starts the server as a child process with these settings:

| Setting | Value |
| :--- | :--- |
| Command | `bash` |
| Argument | Absolute path to the checkout's `run.sh` |
| Python | The launcher selects `.venv/bin/python` automatically |
| Optional override | `ANTICELLS_RED_MCP_PYTHON` selects another installed interpreter |

Use absolute paths. Merge only this server entry into your existing client configuration. Restart the client after saving, then confirm that 12 tools are available.

## Clients with an mcpServers configuration

```json
{
  "mcpServers": {
    "anticells_red_mcp": {
      "command": "bash",
      "args": ["/absolute/path/Anticells_Red_MCP/run.sh"]
    }
  }
}
```

This is the configuration shape used by clients such as Claude Desktop and Cursor. Their file locations and management interfaces vary; consult the current [Cursor MCP guide](https://cursor.com/docs/mcp) or [Claude Desktop guide](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) for client-specific setup.

An explicit interpreter can be supplied through the server's `env` object:

```json
{
  "ANTICELLS_RED_MCP_PYTHON": "/absolute/path/Anticells_Red_MCP/.venv/bin/python"
}
```

## OpenCode

OpenCode uses `mcp`, `type`, and a command array:

```json
{
  "mcp": {
    "anticells_red_mcp": {
      "type": "local",
      "command": ["bash", "/absolute/path/Anticells_Red_MCP/run.sh"],
      "enabled": true
    }
  }
}
```

Add interpreter or target settings through the entry's `environment` object when needed. See the [OpenCode MCP documentation](https://opencode.ai/docs/mcp-servers/) for configuration locations and management commands.

## Other clients and SDKs

Register a local stdio server using `bash` and the absolute `run.sh` path. Clients may use TOML, JSON, or a CLI to store that registration; do not copy one client's configuration schema into another.

For Windows clients, run the server inside WSL and configure the client to launch that WSL environment. Native PowerShell paths cannot be used as Linux paths inside Bash.

## Configure credentials

Keep credentials outside the README and shared client examples. Set only the required environment variables in your local client configuration, or select an explicit private environment file with `ANTICELLS_RED_MCP_ENV_FILE`.

For authenticated legacy calls, configure both `ANTICELLS_RED_MCP_TARGET_API_URL` and `ANTICELLS_RED_MCP_TARGET_API_KEY`. The bearer credential is bound to that configured origin. Saved profiles have their own authentication headers and environment restrictions; see [targets](targets.md) and [security](../SECURITY.md).

If startup fails, run the [installation checks](installation.md#verify-the-mcp-connection) before changing client settings.
