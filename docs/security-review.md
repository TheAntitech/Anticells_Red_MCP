# Publication security review

Publication review date: 2026-10-25. Project version: 1.1.0. Subsequent native Windows verification is recorded separately below.

This review checks publication contents and selected application trust boundaries.
It does not certify that the project has no vulnerabilities.

## Changes verified during this review

| Finding | Resolution | Verification |
| --- | --- | --- |
| DNS checks did not pin the address used for TCP connections, permitting a DNS-rebinding window | A shared HTTPCore backend checks destination policy and connects to the approved numeric address. HTTP Host and TLS SNI/certificate identity retain the original hostname. | A rebinding fixture changes its answer to loopback on a second resolution; the request makes one resolution, connects only to the first approved address, and retains the hostname for HTTP and TLS. |
| Auxiliary clients bypassed the common network policy and request counter | All project HTTP-client construction uses the shared policy transport and request hook. | Private/metadata address rejection and per-call budget tests exercise the client/backend boundaries. Source inspection confirms one shared AsyncClient constructor. |
| Environment proxy settings could route traffic outside the checked connection path | HTTP clients disable environment proxies and automatic redirects. | Regression checks verify the transport has no proxy mounts and redirects are disabled. |
| DNS policy checks changed the process-wide socket timeout | Resolution no longer changes the global timeout. | A regression test checks the socket timeout before and after resolution. |
| Reserved listener configuration defaulted to all interfaces | Default changed to loopback; the running server uses stdio. | Configuration inspection. |
| Publication audit reported three fixed dummy database URLs | Allow only the exact bytes in the two original test paths; other values and application paths still fail the audit. | Regression tests insert an unexpected credential into the same fixture path and copy a dummy URL into application code; both are reported. |

## Verification

- Full test suite: 404 passed; no failures.
- Real MCP smoke test: passed against the built wheel; stdio handshake, all 12 tools,
  194 public templates, local mutation, reports and stop-loop acknowledgment.
- Gitleaks: exact publication snapshot and every reachable Git-history commit are
  scanned with redaction, decoding and archive inspection enabled.
- Runtime dependency advisory check: 31 resolved third-party distributions checked
  with pip-audit; no known vulnerabilities reported on the review date.
- The isolated environment's initially outdated pip was upgraded, together with
  wheel and setuptools. A separate advisory scan of that environment then reported
  no known vulnerabilities. The installer already upgrades those build tools.
- Tested HTTP stack: httpx 0.28.1, httpcore 1.0.9, mcp 1.30.0, anyio 4.15.1.
- Shell launchers are checked with `bash -n`; staged changes with `git diff --check`.
- Publication excludes local `.env` values, private keys, credential stores, runtime
  databases/evidence, caches, build outputs and nested Git metadata. The tracked
  `.env.example` contains empty settings and descriptive examples.

## Subsequent native Windows verification

On 2026-10-27, the native Windows installer and event-loop changes were checked with Python 3.12.14:

- Full test suite: 405 passed, including the new worker-thread wakeup/subprocess-pipe regression check.
- `install.ps1` completed all seven stages. The real MCP smoke test discovered all 12 tools and 194 public templates and exercised local mutation, report statistics, and stop-loop acknowledgment.
- A fresh installation in a path containing spaces passed. PowerShell and Git Bash reinstall checks preserved the catalog, and interpreter discovery reused the base Python safely.
- The compatibility workflow configures Windows, macOS, and Linux installation/tests with Python 3.10 and 3.12. The local results above cover Windows; consult workflow results for the other platforms.

These installation checks do not refresh the earlier secret scans or dependency advisory results, and they do not assess a live target model.

## Static-analysis triage

Bandit was run over all Python application source. Its remaining candidates were
reviewed rather than silently suppressed:

- Three SQL-construction warnings: the concatenated clauses are fixed strings
  selected by program branches; identifiers, limits and offsets use bound SQLite
  parameters. Client values are not interpolated into SQL.
- Pseudorandom-generator warnings: these calls select and mutate research templates;
  they do not create authentication secrets. Report identifiers use UUIDs.
- Two exception/pass warnings: reviewed in optional cleanup/control-flow paths.

Report HTML escapes evidence and sets a restrictive Content Security Policy;
Markdown exports render evidence as literal indented code. Report export identifiers
are validated and file reads are constrained to generated filenames. Returned tool
proposals are evidence; this server does not execute those proposed functions.

## Operating boundaries

Use a dedicated account or container for stronger filesystem/network isolation.
The operator controls saved profiles, catalog edits, private-network overrides and
cross-session report selectors. The DNS-resolution bypass is intended only for
mocked or isolated labs and disables hostname validation/pinning; leave it unset
for normal operation. Evidence is private operator data and may contain sensitive
target content despite configured-secret redaction. Bound network requests do not
constitute a complete CPU, memory or disk sandbox. Advisory results cover the
resolved versions above and must be refreshed after dependency changes.

See [SECURITY.md](../SECURITY.md) for the trust model and reporting process.
