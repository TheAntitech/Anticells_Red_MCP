<p align="center">
  <img src="assets/anticells_red_mcp-banner.png" alt="Anticells Red MCP: observe the boundary" width="100%">
</p>

<h1 align="center">Anticells Red MCP</h1>
<p align="center"><strong>Observe the boundary. Understand the response.</strong><br>Focused LLM security research, connected through MCP.</p>

<p align="center">
  <code>v1.1.0</code> &nbsp; <code>Python 3.10+</code> &nbsp; <a href="#tools"><code>12&nbsp;MCP&nbsp;tools</code></a> &nbsp; <a href="docs/catalogs.md"><code>194&nbsp;templates</code></a> &nbsp; <a href="SECURITY.md"><code>Default-deny&nbsp;egress</code></a>
</p>

<p align="center"><strong>by Wael Rdifi for Antitech</strong></p>
<p align="center"><a href="#quick-start">Quick start</a> · <a href="#connect">Connect</a> · <a href="#tools">Tools</a> · <a href="SECURITY.md">Security</a> · <a href="#documentation">Documentation</a></p>

---

**Anticells Red MCP** gives MCP-compatible agents a structured workspace for LLM security research: inspect model responses, run selected test templates, explore tool-call behavior, and export evidence. Use it with targets you own or are authorized to assess.

| Research stage | What you get |
| :--- | :--- |
| **Explore** | 194 public templates across five modules, 171 auxiliary techniques, and 131 supporting resources |
| **Evaluate** | Single-template execution, fingerprint hints, and bounded research loops |
| **Document** | Local SQLite evidence with JSON, Markdown, and escaped HTML exports |

> Results are research evidence. Success scores and model identities are heuristic; proposed tool calls do not establish an executed external effect.

<a id="quick-start"></a>
## <img src="assets/icons/install.svg" width="20" height="20" alt=""> Quick start

**Requires:** Python 3.10+ and Git. Use PowerShell on Windows or Bash on macOS/Linux. SQLite is included with Python.

On macOS/Linux:

```bash
git clone https://github.com/TheAntitech/Anticells_Red_MCP.git
cd Anticells_Red_MCP
bash install.sh
```

On native Windows:

```powershell
git clone https://github.com/TheAntitech/Anticells_Red_MCP.git
cd Anticells_Red_MCP
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

This execution-policy setting applies only to that process.

The installer creates `.venv`, installs the package, initializes the catalog, checks the default egress policy, and runs an MCP smoke test. It then prints client configuration.

Check your installation at any time:

```bash
.venv/bin/anticells_red_mcp-doctor
```

On Windows, use `.venv\Scripts\anticells_red_mcp-doctor.exe`.

For manual installation, updates, and installer options, see the [installation guide](docs/installation.md).

<a id="connect"></a>
## <img src="assets/icons/connect.svg" width="20" height="20" alt=""> Connect your agent

The server uses **stdio**. Use the configuration printed by the installer: it launches the project's virtual-environment Python directly on every platform.

For clients that use an `mcpServers` configuration:

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

Replace the example path with your checkout. On Windows, the command ends in `.venv\\Scripts\\python.exe`; use the escaped path printed by the installer. Merge the entry into your existing configuration, then restart the client and check for **12 tools**. OpenCode uses a different configuration shape; see [client setup](docs/clients.md).

<a id="tools"></a>
## <img src="assets/icons/toolkit.svg" width="20" height="20" alt=""> Research toolkit

| Tool | Purpose |
| :--- | :--- |
| `list_attack_templates` | Browse the catalog by module, category, search, or stable ID |
| `get_compatible_templates` | Check template compatibility locally, without contacting a target |
| `execute_attack_template` | Run one enabled public template by stable ID |
| `fingerprint_llm` | Collect response-based model and provider hints |
| `get_fingerprint_profile` | Save a structured profile from selected probes |
| `jailbreak_attack` | Evaluate selected jailbreak template categories |
| `prompt_injection` | Submit injection templates or a custom test payload |
| `tool_abuse_exploit` | Assess proposed tool calls against supplied schemas |
| `creative_mutation` | Generate and score local template variations |
| `endless_attack_loop` | Schedule a strategy with an explicit iteration bound |
| `stop_attack_loop` | Cancel the active loop and wait for shutdown |
| `get_attack_report` | View statistics, browse saved runs, and export evidence |

**Catalog:** fingerprint **30** · jailbreak **53** · injection **53** · tool abuse **35** · mutation **23**.

### Start with discovery

Call `list_attack_templates` with:

```json
{"module": "injection", "limit": 5, "include_content": true}
```

Use a returned stable ID with `execute_attack_template`. Configure a target through `target_url`, a saved profile, or an inline HTTP definition. [Target profiles](docs/targets.md) explain authentication, variable rendering, and response mapping.

For saved evidence, call `get_attack_report` with:

```json
{"action": "list", "limit": 10}
```

Exports support JSON, Markdown, and HTML. [Report workflows](docs/reports.md) cover run selection and chunked reads.

## <img src="assets/icons/shield.svg" width="20" height="20" alt=""> Security by default

| Boundary | Default behavior |
| :--- | :--- |
| Network | Private and metadata destinations blocked; approved IP pinned at connection time |
| HTTP transport | TLS verification enabled; automatic redirects and inherited proxies disabled |
| Credentials | Inline targets cannot read environment variables; saved-profile credentials are origin-bound |
| Request budget | 20 outbound requests per invocation; 500 per session per minute |
| Local evidence | Configured secrets redacted; report listings scoped to the current session |

Operator overrides are documented in the [security policy](SECURITY.md). Keep credentials in private local configuration and review scope before enabling private-network access.

The [verification record](docs/security-review.md) covers the publication security review and subsequent native Windows validation, including **405 passing tests** and a real MCP smoke test. Secret scans and dependency advisory checks apply to the dated publication snapshot; these results do not guarantee zero vulnerabilities.

<a id="documentation"></a>
## <img src="assets/icons/docs.svg" width="20" height="20" alt=""> Documentation

| Guide | Read it for |
| :--- | :--- |
| [Installation](docs/installation.md) | Manual setup, verification, updates, and installer options |
| [MCP clients](docs/clients.md) | Standard stdio configuration and OpenCode setup |
| [Targets](docs/targets.md) | Saved profiles, authentication, variables, and response mappings |
| [Catalog](docs/catalogs.md) | Stable IDs, discovery, compatibility, and SQLite maintenance |
| [Fingerprinting](docs/fingerprints.md) | Profile fields, probe selection, and interpretation |
| [Reports](docs/reports.md) | Evidence storage and exports |
| [Architecture](docs/architecture.md) | Components and execution flow |
| [Troubleshooting](docs/troubleshooting.md) | Startup, transport, and configuration errors |
| [Security review](docs/security-review.md) | Findings, fixes, verification, and operating boundaries |

## <img src="assets/icons/license.svg" width="20" height="20" alt=""> License

See [LICENSE](LICENSE) for the Apache License 2.0 terms included with this repository.

---

<p align="center"><strong>Antitech, Your AI’s Immune System.</strong></p>
