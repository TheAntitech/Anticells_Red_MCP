# Glama build configuration

The repository [Dockerfile](../Dockerfile) runs the MCP server directly over stdio. Glama's **Admin → Dockerfile** form generates its own Dockerfile from the fields below. A successful local build of the repository Dockerfile does not verify those separate settings.

Open the [Glama configuration page](https://glama.ai/mcp/servers/TheAntitech/Anticells_Red_MCP/admin/dockerfile) and use:

| Field | Value |
| :--- | :--- |
| Base image | `debian:trixie-slim` |
| Node.js version | Keep the default; Glama uses Node.js for `mcp-proxy` |
| Python version | `3.12` |
| Placeholder parameters | `{}` |
| Diagnostic files | Leave empty |
| Pinned commit SHA | Leave empty to build the latest synced commit |

**Build steps**:

```json
[
  "uv venv --python 3.12 /app/.venv",
  "uv pip install --python /app/.venv/bin/python ."
]
```

These commands create an isolated Python environment and install the package, its dependencies, catalog data, SQL migrations, and console entry points. See [uv's environment documentation](https://docs.astral.sh/uv/pip/environments/).

**CMD arguments** (complete command, extending the `mcp-proxy --` prefix shown in the form):

```json
[
  "mcp-proxy",
  "--",
  "/app/.venv/bin/python",
  "-u",
  "-m",
  "anticells_red_mcp.mcp_server.server"
]
```

Check the generated Dockerfile preview: the final command must contain exactly one `mcp-proxy --` prefix followed by the Python command above. If the form adds that prefix automatically, enter only the arguments starting with `/app/.venv/bin/python`. The `-u` flag keeps Python output unbuffered, as recommended by the [proxy's Python troubleshooting guide](https://github.com/punkpeye/mcp-proxy#troubleshooting-python-stdio-servers).

**Environment variables JSON schema**:

```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

Initialization and discovery need no credentials or target configuration. The server initializes SQLite in the container's per-user application data directory. The `/app/data` environment settings in the repository Dockerfile apply only when that Dockerfile is used.

Sync the [repository in Glama](https://glama.ai/mcp/servers/TheAntitech/Anticells_Red_MCP/admin/repository), verify its displayed head matches the intended GitHub commit, and clear an outdated pinned SHA. Then deploy the updated build specification. Once its build test passes, create a release following [Glama's release instructions](https://glama.ai/blog/2026-03-15-how-to-make-a-release).

A build log that only clones the repository and exports an image has not installed the application. Look for the `uv venv` and `uv pip install` steps in the new build log. Runtime discovery should report 12 MCP tools. `mcp-proxy --` on its own is incomplete: it needs the server command after the separator.

The root `glama.json` declares maintainers. Build steps and startup arguments belong in Glama's build configuration; see the [Glama schema](https://glama.ai/mcp/schemas/server.json).
