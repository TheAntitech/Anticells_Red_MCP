# Changelog

## Unreleased - Responsible-use guidance

- Add an ethical-use matrix, guidance for isolated self-hosted/open-weight testing and hosted APIs, operator-override links, and data-handling responsibilities. Link the guide from the README, security policy, and contributor guide while keeping the Apache license unchanged.

## Unreleased - Contributor guide

- Add public contribution guidance covering development setup, the six-job compatibility matrix, pull-request review, catalog/template rules, documentation updates, and private security reporting. Link the guide from the README.

## Unreleased - Windows SQLite path compatibility

- Convert Windows extended drive paths (`\\?\C:\...`) to standard file URIs before opening SQLite. This fixes catalog initialization when concurrent path resolution retains the extended prefix and SQLite rejects the URI authority.
- Apply the same conversion to report storage while preserving read-only connection modes and filename escaping.
- Cover ordinary and extended paths in the existing concurrent initialization/edit-preservation test, and add report-store and URI regression checks.

## Unreleased - Documentation alignment

- Point HTTPS clone instructions, package metadata, and security-reporting links to `TheAntitech/Anticells_Red_MCP`.
- Align the project guide with version 1.1.0, native Windows setup, current dependencies, request limits, saved-profile credentials, and session-scoped report listings.
- Repair deleted-module and license links, describe the included Apache 2.0 license, and distinguish the dated publication review from subsequent Windows verification.

## Unreleased - Native Windows installation

- Add `install.ps1` and shared Python installation steps with platform-specific virtual-environment paths. Preserve the seven setup checks and exit codes 10-15.
- Print client configurations that launch the installed Python module directly, without Bash, and report the correct macOS/Windows Claude configuration locations.
- Use the Windows Proactor event loop for native MCP pipes, subprocesses, and worker-thread wakeups; retain the Unix self-pipe workaround.
- Make the post-install smoke test launch native Python and add Windows/macOS/Linux installer CI plus a thread/subprocess regression check.

## Unreleased — publication security review

- Close the DNS-rebinding window by validating and pinning the destination at
  the TCP connection boundary while preserving the original HTTP Host and TLS
  certificate identity. Apply the transport to all primary and auxiliary clients.
- Disable inherited HTTP proxies and enforce request budgets for auxiliary HTTP
  paths as well as the main JSON transport. Avoid changing global socket timeouts.
- Default the reserved server bind configuration to loopback.
- Strengthen publication exclusions and audit nested Git metadata. Recognize only
  the exact, reviewed dummy database URLs in their original test files.
- Add network-policy and publication-audit regression tests. Give the full-loop
  integration test a bounded two-minute completion window on slower filesystems
  while retaining its completion and result assertions.
- Update repository links and document DNS bypass and verification limits.

## 1.1.0 - Hardening pass (𝓜𝖗𝚇₀𝚛𝚍 audit)

Full security review and remediation. No MCP tool was added or removed;
twelve tools remain. Behavior changes are documented so that an operator
can restore the pre-1.1.0 behavior with explicit opt-in environment
variables where it is safe to do so.

### Egress policy
- New `mcp_server/endpoint_safety.py`. Every outbound target request is now
  gated on a resolve + policy check that denies loopback, private,
  link-local, multicast, reserved and unspecified addresses by default,
  including the IPv4 payloads of IPv4-mapped IPv6 and 6to4 forms.
- Enforced uniformly from `endpoint_origin`, so the legacy `target_url`
  path, saved profiles, and inline target definitions all share one check.
- New opt-ins: `ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS`,
  `ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS`,
  `ANTICELLS_RED_MCP_TARGET_DENY_HOSTS`,
  `ANTICELLS_RED_MCP_RESOLVE_TIMEOUT_SECONDS`.
- Server start now runs `endpoint_safety.self_test()` and aborts if the
  default policy ever stops rejecting `127.0.0.1`.

### Environment visibility
- `MCPConfig.target_environment` no longer defaults to `dict(os.environ)`.
  It defaults to an empty mapping; names listed in
  `ANTICELLS_RED_MCP_TEMPLATE_ENV` and values loaded through
  `ANTICELLS_RED_MCP_ENV_FILE` populate it.
- Inline target definitions supplied by the MCP client cannot read
  `${env.*}` at all; the server returns the stable code
  `inline_environment_reference_forbidden`.
- Saved profiles may still read whitelisted env values but only when they
  resolve to the configured provider's origin
  (`profile_environment_origin_not_authorized` otherwise).

### Request bounds
- New `mcp_server/limits.py`:
  - `ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL` (default 20) caps one tool
    invocation. Over-cap techniques are rejected with
    `per_call_request_cap_exceeded`.
  - `ANTICELLS_RED_MCP_MAX_REQUESTS_PER_SESSION_PER_MIN` (default 500)
    applies a 60-second rolling cap across the whole MCP session.
  - `ANTICELLS_RED_MCP_MAX_HISTORY` (default 2000) ring-buffers in-memory
    record lists (`_history`, `AttackEngine._results`, `Recorder.Run.records`).

### Report isolation
- `get_attack_report action=list` and the MCP resource listing now scope
  to the current session's runs/exports by default. Cross-session reads
  require an explicit `session_id`.
- `ReportRepository.list_exports_for_session` enforces the scope at the
  SQL layer.

### Error surface
- `server._target_config` no longer leaks free-form `ValueError` messages
  about environment variable names. All its failure paths return
  `TargetConfigurationError` with a stable code
  (`invalid_target_url`, `authenticated_calls_require_configured_origin`,
  `authenticated_target_origin_mismatch`).

### Dead code removed
- `mcp_server/reporting.py` (orphan HTML reporter with unescaped
  interpolation and arbitrary-path writes) is deleted. The live export
  path remains `reports/model.render`, which escapes HTML and sets a
  restrictive CSP.

### Tests
- 376 pre-existing tests continue to pass.
- New `tests/test_hardening.py` adds regression coverage for every
  finding (F1 SSRF deny-list, F2 inline env rejection, F3 history cap,
  F4 per-call request cap, F6 report scope, F7 error-code stability).

## Unreleased - Target fingerprint profiles

- Add `get_fingerprint_profile` as the twelfth MCP tool, preserving all existing tool schemas, prompt catalogs, and scanner scoring.
- Generate a bounded fresh scan (six requests by default), optionally selecting stable fingerprint template IDs and guarding the catalog revision.
- Separate reported identities and observed transport/refusal behavior from heuristic model hints and unmeasured candidate-table attributes.
- Save profiles with complete probe evidence and stable result links; retrieve/export them through the existing report tools without probing again.
- Validate the selected requests before HTTP delivery, retain snapshot isolation, and redact credentials before shortening profile excerpts.

## Unreleased - Execute one catalog template

- Add `execute_attack_template` as the eleventh MCP tool, selecting one enabled public entry by stable ID with an optional catalog revision guard.
- Reuse the existing engines, target configuration, compatibility checks, scoring, and full-evidence recorder. Remote entries make one request; mutation entries perform one local mutation.
- Preserve duplicate names, skip incompatible scenarios without a target attempt, and reject disabled/unknown/auxiliary IDs before delivery.
- Save selected template provenance, expose a run ID for export, and include results in current-session statistics. Existing tool schemas and catalog entries remain unchanged.

## Unreleased - Target-compatible template discovery

- Add `get_compatible_templates` as the tenth MCP tool; preserve all existing tool schemas and catalog content.
- Check saved/inline target definitions, rendered requests, response mappings, and available function schemas locally using the same builders and checks as execution.
- Return compatible public entries with filters and pagination, or include incompatible entries with safe reasons. Label local mutation separately.
- Keep discovery free of target requests and saved research runs; retain credential-origin restrictions and lossless template content.

## Unreleased - Attack template discovery

- Add `list_attack_templates` as a ninth MCP tool, preserving the original eight tools and their schemas.
- Browse the published SQLite catalog by module, category membership, search text, or stable ID, with pagination and optional full content.
- Optionally include auxiliary and disabled technique entries; preserve duplicate names and exceptional Unicode.
- Listing never contacts a target or creates a saved research run. New publications appear on the next call; an optional revision guard protects pagination.

## Unreleased - Saved reports and exports

- Automatically archive research runs, full normalized evidence, and provenance in a separate SQLite report database.
- Preserve the eight-tool interface; extend `get_attack_report` with saved views, paginated listing, JSON/Markdown/HTML exports, and bounded file reads.
- Add MCP export resources and an independent `anticells_red_mcp-reports` CLI for inspection, export, and explicit cleanup.
- Retain unsaved records in memory with visible warnings and five-second retries; use process locks to identify interrupted runs.
- Redact configured credentials, exclude transport configuration, and render untrusted evidence literally.
- Keep saved report access available when the prompt catalog is unavailable. Existing current-session report behavior and catalog content remain unchanged.

## Unreleased — SQLite prompt catalogs and automatic setup

- Replace PostgreSQL and managed Docker provisioning with Python's built-in SQLite backend. New users receive a local database, migrations, and all 496 catalog resources automatically on first MCP launch.
- Use a per-user application data file by default; add `ANTICELLS_RED_MCP_DATABASE_PATH` and retain optional state-directory and manual-initialization settings.
- Preserve all prompt content, original 194-entry digest, ordering, duplicate names, memberships, exact legacy Unicode, and the eight MCP tool schemas. Store lossless JSON in SQLite BLOBs.
- Retain async snapshot loading, revision caching, call/loop isolation, atomic publication, stale-update protection, and JSON authoring CLI commands. Close each SQLite connection after its transaction.
- Add full-export `restore` for backup recovery and migration from PostgreSQL, preserving edits, disabled records, ordering, and revisions. Refuse to overwrite an existing catalog or silently abandon legacy configuration.
- Remove the Psycopg dependency and Compose setup. Test real SQLite storage, simultaneous initialization/publication, rollback, outage behavior, backup/restore, and MCP stdio without a database server.
- Keep native Windows launcher/event-loop changes separate.

## Unreleased — Configurable target requests

- Add saved and inline `target` definitions and `target_variables` to the five endpoint tools, including background loops; preserve existing `target_url` calls.
- Load explicitly selected profiles and environment files without automatic discovery or changes to the process environment.
- Render typed JSON placeholders from `env`, `vars`, and generated `request` values; pass the actual injection payload explicitly.
- Support custom HTTP methods, headers, complete JSON bodies, and JSON Pointer text/tool-call response mappings through the shared transport.
- Isolate variable snapshots per call or loop, bind credentials to authorized origins, disable redirects, and keep credentials out of configuration diagnostics.
- Surface configuration failures separately from model attempts and report background configuration errors; skip custom targets without tool-call mappings in tool scenarios.
- Add target examples, setup and migration documentation, mocked transport tests, and MCP protocol coverage. Preserve all eight tools and the original 194 catalog entries.
- Keep the existing native Windows stdio launcher/event-loop issue separate from this change.

## Unreleased — anticells_red_mcp rename

- Use `anticells_red_mcp` for the package, import namespace, console command, MCP server identity, client configuration, logging, HTTP user agents, and documentation.
- Rename and update the banner assets and point project links to this repository.
- Namespace all project environment variables under `ANTICELLS_RED_MCP_`, including `ANTICELLS_RED_MCP_PYTHON` for the scripts.
- Identify exported reports as `anticells_red_mcp_report` and use `~/.local/state/anticells_red_mcp/logs` as the configured default log location.
- Reinstall the package and update client configurations, Python imports, and process environment settings after upgrading. Prior project commands and environment variable names are no longer supported.
- Preserve the eight research tools and all 194 catalog entries.

## 1.0.2 — Execution and result handling

- Preserve all eight MCP tools and the original 194 catalog entries.
- Reject empty, malformed and unsupported replies as successes.
- Honor supplied function schemas without injecting extra tool definitions; skip unavailable tools or incompatible arguments.
- Validate returned tool-call arguments without executing external actions.
- Separate local mutation candidates and skipped records from target-success rates.
- Preserve structured payloads and catalog data during loop mutation, crossover and variant creation.
- Contain individual execution failures and honor the older engine's finite loop cap.
- Add shared basic chat transport, environment-based model selection and private bearer authentication.
- Disable hosted mutation generation by default and fix its configuration lookup.
- Add focused regression checks for request delivery, response handling and report accounting.

## 1.0.1 — anticells_red_mcp

- Introduce anticells_red_mcp artwork, a focused README, architecture notes and portable client examples.
- Keep all eight MCP tools and the original 194 catalog entries.
- Fix the installed console entry point returning an unawaited coroutine.
- Keep launcher and fallback logger diagnostics out of MCP stdout.
- Remove invalid awaits on synchronous technique catalogs.
- Normalize dataclass and dictionary module results without handler crashes.
- Close per-call HTTP clients and isolate configuration between targets.
- Retain single-call and loop results in session reports.
- Honor finite loop limits, default to one iteration, reject overlapping starts, and await cancellation before restart.
- Validate tool arguments and return structured MCP errors without tracebacks.
- Escape original Unicode templates safely for UTF-8 transport.
- Correct the advertised injection categories and documentation counts.
- Consolidate packaging metadata, use a project-local install environment, and add regression and publication checks.
