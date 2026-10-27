<p align="center">
  <img src="assets/anticells_red_mcp-banner.png" alt="Anticells Red MCP: observe the boundary" width="100%">
</p>

<h1 align="center">Anticells Red MCP</h1>
<p align="center"><strong>Observe the boundary. Understand the response.</strong><br>Focused LLM security research, connected through MCP.</p>

<p align="center">
  <code>v1.1.0</code> &nbsp; <code>Python 3.10+</code> &nbsp; <a href="#tools"><code>12&nbsp;MCP&nbsp;tools</code></a> &nbsp; <a href="docs/catalogs.md"><code>194&nbsp;templates</code></a> &nbsp; <a href="SECURITY.md"><code>Default-deny&nbsp;egress</code></a>
</p>

<p align="center"><strong>♢ 𝓜𝖗𝚇₀𝚛𝚍 ⚡🖤</strong></p>
<p align="center"><a href="#quick-start">Quick start</a> · <a href="#connect">Connect</a> · <a href="#tools">Tools</a> · <a href="SECURITY.md">Security</a> · <a href="#documentation">Documentation</a></p>

---

**Anticells Red MCP** gives MCP-compatible agents a structured workspace for LLM security research: inspect model responses, run selected test templates, explore tool-call behavior, and export evidence. Use it with targets you own or are authorized to assess.

| Research stage | What you get |
| :--- | :--- |
| **Explore** | 194 public templates across five modules, with 302 supporting resources |
| **Evaluate** | Single-template execution, fingerprint hints, and bounded research loops |
| **Document** | Local SQLite evidence with JSON, Markdown, and escaped HTML exports |

> Results are research evidence. Success scores and model identities are heuristic; proposed tool calls do not establish an executed external effect.

<a id="quick-start"></a>
## <img src="assets/icons/install.svg" width="20" height="20" alt=""> Quick start

**Requires:** Python 3.10+, Git, and Bash. On Windows, use WSL. SQLite is included with Python.

```bash
git clone git@github.com:Wael-Rd/Anticells_Red_MCP-1.0.0.git Anticells_Red_MCP
cd Anticells_Red_MCP
bash install.sh
```

The installer creates `.venv`, installs the package, initializes the catalog, checks the default egress policy, and runs an MCP smoke test. It then prints client configuration.

Check your installation at any time:

```bash
.venv/bin/anticells_red_mcp-doctor
```

For manual installation, updates, and installer options, see the [installation guide](docs/installation.md).

<a id="connect"></a>
## <img src="assets/icons/connect.svg" width="20" height="20" alt=""> Connect your agent

The server uses **stdio**. Your client launches `bash` with the absolute path to `run.sh`; the launcher selects the project's `.venv` automatically.

For clients that use an `mcpServers` configuration:

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

Replace the example path with your checkout. Merge the entry into your existing configuration, then restart the client and check for **12 tools**. OpenCode uses a different configuration shape; see [client setup](docs/clients.md).

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

The [publication review](docs/security-review.md) records **404 passing tests**, a built-wheel MCP smoke test, secret scans, and dependency advisory checks for the reviewed revision. These are version-specific verification results, not a guarantee of zero vulnerabilities.

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

No open-source license is currently granted. See [LICENSE.md](LICENSE.md) for the repository's licensing status and third-party notice.

---

<p align="center"><strong>♢ 𝓜𝖗𝚇₀𝚛𝚍 ⚡🖤</strong><br><sub>Anticells Red MCP · Observe. Evaluate. Document.</sub></p>
