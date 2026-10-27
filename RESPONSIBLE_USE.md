# Responsible use

Anticells Red MCP supports authorized security research, education, and defensive evaluation. Use findings to improve AI safeguards and protect users.

This document provides responsible-use guidance. It does not modify the [Apache License 2.0](LICENSE), add license conditions, or introduce field-of-use restrictions. The positions below describe responsible-use expectations; they do not grant permission to assess a third-party system.

## Ethical-use matrix

| Use | Position |
| --- | --- |
| Owned systems and isolated labs | Permitted |
| Third-party systems with written authorization | Permitted within scope |
| Hosted APIs | Only when provider terms and authorization permit adversarial testing |
| Production testing | Requires explicit scope, limits, and a rollback plan |
| Unauthorized probing or credential extraction | Not acceptable |
| Real secrets, personal data, or captured private responses | Must not be included in test prompts, repository contributions, or publicly shared evidence |

Where multiple rows apply, satisfy each condition. For hosted services, provider terms and the authorized scope apply even when you own the account or API key. Agree on endpoints, methods, request and spending limits, stopping conditions, and data handling before testing. Stop if testing affects other users, disrupts availability, or creates unexpected costs.

## Choose the initial test environment

Prefer an isolated, self-hosted open-weight model for initial adversarial testing when its license permits the intended use and you can operate it securely.

Testing through a hosted API may disclose sensitive prompts to a third party, trigger abuse-detection systems, violate provider policies, or result in account restrictions. When using a hosted service, obtain authorization, review its terms and retention policy, use a dedicated project and key, avoid real secrets, and begin with conservative request limits. Confirm that the authorization covers adversarial testing and the specific service you will assess.

Self-hosting does not inherently provide safety, confidentiality, or anonymity. Operating the environment creates responsibilities:

- **Patching and provenance:** maintain the operating system, inference server, dependencies, and model-loading components, and review the sources of model artifacts.
- **Isolation and access:** separate the lab from production, limit network access and permissions, and keep model responses from automatically executing commands or tool calls.
- **Logging and data protection:** control access to prompts, responses, local reports, and logs; define retention and cleanup procedures. Review telemetry and external integrations rather than assuming the deployment is offline.
- **Model licensing:** review the model's own license and any applicable use conditions before selecting it for the intended tests. Availability of weights does not establish permission for every use.

## Local models and network controls

Anticells Red MCP blocks local, loopback, and private destinations by default, so a self-hosted server may need an explicit operator exception. Follow the [operator overrides in SECURITY.md](SECURITY.md#operator-overrides) for an authorized lab.

- Prefer an exact host exception through `ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS`, such as `127.0.0.1` for a loopback-only model server. Use only hosts within the agreed scope.
- `ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS=true` enables broader private-network access; reserve it for a controlled lab when that broader access is needed.
- Set these values in the server's process environment, through the shell or the MCP client's `env` / `environment` settings. Values placed only in an explicitly loaded `.env` file do not apply these overrides.
- Leave `ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION` unset for normal operation so hostname validation and DNS pinning remain active. Keep request and iteration limits bounded.

A network exception is a technical configuration change, not authorization to test a target. Keep the model server bound to the intended interface and restrict who can access it. See [target configuration](docs/targets.md) for endpoint and authentication setup and [request controls](SECURITY.md#request-and-evidence-controls) for the available budgets.

## Protect data and share findings responsibly

Use synthetic prompts, identities, and credentials for adversarial test cases. Keep the service credentials needed for authentication in private configuration, separate from prompts and committed fixtures.

The application can save prompts and responses in local SQLite reports. Treat those databases, exports, and logs as private evidence. Review and sanitize material before sharing it; automatic credential redaction is not a guarantee that all sensitive content has been removed. Keep real secrets, personal data, and captured private responses out of commits, public issues, pull requests, and published reports. Share synthetic or appropriately redacted reproductions instead.

Validate heuristic findings and distinguish proposed actions from observed effects. Report vulnerabilities privately through [SECURITY.md](SECURITY.md#report-a-vulnerability); do not publish security reports or exploit details in public issues. Contributions should also follow [CONTRIBUTING.md](CONTRIBUTING.md).
