# <img src="assets/icons/shield.svg" width="24" height="24" alt=""> Security policy

Anticells Red MCP sends research requests to configured model endpoints and stores local evidence. Use it within an authorized scope and keep operator configuration private.

## Trust boundaries

| Actor | Boundary |
| :--- | :--- |
| Operator | Controls environment settings, saved profiles, catalog edits, and local storage |
| MCP client or agent | Supplies runtime arguments; may be influenced by untrusted content |
| Target endpoint | Returns untrusted evidence, including text and proposed tool calls |

Target responses are data. Proposed functions are not executed by this server, and heuristic success labels are not independently verified vulnerabilities.

## Network controls

- Default policy rejects loopback, link-local and metadata destinations, private ranges, multicast, reserved, and unspecified addresses. IPv4-mapped IPv6 and 6to4 embedded addresses are checked as well.
- The connection backend resolves and validates a destination, then connects to an approved numeric IP. HTTP Host and TLS certificate/SNI identity retain the original hostname.
- Primary and auxiliary HTTP clients share the policy transport. TLS verification is enabled; automatic redirects and inherited HTTP proxies are disabled.
- Startup checks that the default policy rejects loopback.

### Operator overrides

| Setting | Effect |
| :--- | :--- |
| `ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS` | Exempts matching hosts from the default private-address restriction |
| `ANTICELLS_RED_MCP_TARGET_DENY_HOSTS` | Denies matching hosts before allow-list evaluation |
| `ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS=true` | Allows private, loopback, and link-local destinations for controlled labs |
| `ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION=true` | Disables hostname address validation and DNS pinning; intended for mocked or isolated labs |

Host lists accept exact names and `*.example` patterns. Prefer narrow host exceptions over the global private-network override. Leave the DNS bypass unset for normal operation. Overrides do not remove the unconditional multicast/unspecified/reserved checks described in the implementation.

## Credentials and configuration

- Inline target definitions cannot read `${env.*}` references.
- Saved profiles can use values from an explicitly selected environment file, profile `env_files`, or process variables named in `ANTICELLS_RED_MCP_TEMPLATE_ENV`.
- Environment-backed saved profiles must match the origin configured in `ANTICELLS_RED_MCP_TARGET_API_URL`.
- Legacy bearer credentials are bound to the configured target origin.
- Environment files are loaded only when explicitly selected. `.env.example` is a reference, not a source of credentials.

Store credentials in private local files or client settings. Do not commit real environment files, private keys, target registrations, or captured evidence. If a credential is exposed, revoke or rotate it and remove the leak path.

## Request and evidence controls

| Setting or control | Default |
| :--- | :--- |
| Requests per tool invocation | `20` |
| Requests per session per minute | `500` |
| In-memory history limit | `2000` records for the configured history buffers |
| Background loop | One iteration unless explicitly changed |
| Report listings | Current session; explicit selectors enable cross-session access |
| Report rendering | Escaped HTML with restrictive CSP; literal Markdown evidence |

Request/history settings are operator-configurable. Setting a cap to `0` disables it. These limits are not a complete CPU, memory, disk, or network sandbox.

Configured secrets are redacted from saved evidence, but target content can still contain sensitive data. Treat local databases and exports as private. Session identifiers and explicit report selectors are not a separate authentication system.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Wael-Rd/Anticells_Red_MCP-1.0.0/security/advisories/new) when it is enabled. If unavailable, [open an issue requesting a private contact](https://github.com/Wael-Rd/Anticells_Red_MCP-1.0.0/issues/new) without posting the exploit or sensitive data.

Include the affected version, impacted boundary, a minimal reproduction with synthetic values, expected behavior, and observed behavior. Never include live tokens, personal data, or private target responses. Reports are handled on a best-effort basis; no response deadline is promised.

## Verification and deployment

The [publication review](docs/security-review.md) records findings, fixes, test results, secret scans, and dependency checks for the reviewed revision. These results do not guarantee zero vulnerabilities or cover every future dependency version.

The stdio process runs with the operator's permissions. Use a dedicated account or container when stronger isolation is required. Keep Python, installer tools, and dependencies updated, and repeat checks after changes.

<p align="center"><sub>Maintained by <strong>♢ 𝓜𝖗𝚇₀𝚛𝚍 ⚡🖤</strong></sub></p>
