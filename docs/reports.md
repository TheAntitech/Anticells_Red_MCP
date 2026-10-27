# Saved research reports

Research tools automatically save evidence in a separate SQLite database. Each MCP process creates a session; each assessment, mutation call, or background loop creates a run. Replies include `run_id`, `session_id`, and `persistence`. No database server, browser service, or PDF dependency is needed.

`execute_attack_template` creates one run for one selected template. Its run includes the stable template ID, namespace, record revision, and catalog revision. Execution or a compatibility skip produces one evidence record; a configuration error produces a failed run with no target attempt. Its results also enter current-session history, with local mutation and skipped scenarios excluded from target-attempt totals. Export the returned `run_id` using the same workflow below.

## Storage and setup

`get_fingerprint_profile` saves each probe once and stores the completed profile under the run's `fingerprint_profile`. A saved summary view includes the profile; detailed views and exports additionally include probe evidence. This retrieval needs neither the target nor the catalog. See [profile generation and retrieval](fingerprints.md).

Startup creates `reports.sqlite3`, applies versioned report migrations, and prepares an `exports` directory. The default directory is `<state directory>/reports`, where the state directory is the same directory used for the default catalog. On Windows it defaults to `%USERPROFILE%/AppData/Local/anticells_red_mcp/catalog/reports`; on Linux, `~/.local/share/anticells_red_mcp/catalog/reports`; on macOS, `~/Library/Application Support/anticells_red_mcp/catalog/reports`. Use `ANTICELLS_RED_MCP_STATE_DIR` for an explicit shared state location on any platform.

Set `ANTICELLS_RED_MCP_REPORTS_DIR` to choose a different directory. `ANTICELLS_RED_MCP_STATE_DIR` changes the shared default state directory. Setting `ANTICELLS_RED_MCP_DATABASE_PATH` alone changes only the catalog file. Use a local disk outside a synchronized source checkout. Environment files are loaded only when explicitly selected with `ANTICELLS_RED_MCP_ENV_FILE` or the target profile configuration.

The report database stores complete prompts, generated conversations and tool schemas, normalized reply text, proposed tool calls, outcomes, original result timestamps, execution status, catalog revision, and safe operation settings. Authentication headers, environment snapshots, rendered custom request bodies, and configured credential values are excluded or redacted. Endpoint labels omit query strings. Full target evidence can itself contain sensitive information: files stay local, with no automatic sharing or expiration. Unix directories/files use `0700`/`0600`; Windows inherits permissions from the selected user directory.

## Use through a coding agent

These examples are arguments to `get_attack_report`, not shell commands. The server exposes twelve tools, including read-only template discovery.

List saved runs in the current MCP session:

```json
{"action": "list", "limit": 20, "offset": 0}
```

The result includes `total`, `next_offset`, and `scope`. To list a previous session, supply its explicit ID:

```json
{"action": "list", "session_id": "<session UUID>", "limit": 20}
```

Use the reports CLI's `list` command to discover saved runs across all sessions. An explicit `run_id` can retrieve an older run directly. View a run's statistics and up to 100 evidence records:

```json
{"action": "view", "run_id": "<run UUID>", "format": "detailed"}
```

Use `session_id` instead of `run_id` to combine all runs in a session. `summary` returns statistics/provenance; `json` includes up to 10 evidence records; `detailed` includes up to 100. `evidence_truncated` indicates omitted inline records. Export for complete evidence:

```json
{"action": "export", "run_id": "<run UUID>", "export_format": "markdown"}
```

`export_format` accepts `json`, `markdown`, or `html` and defaults to `json`. With neither selector, export chooses the latest completed run in this MCP session. Explicit IDs can select old sessions or active work. An active export is labeled `partial`; it is an immutable snapshot and does not grow as the run continues. Every export creates a new file with a unique name.

Export replies include `export_id`, filename, absolute local path, MIME type, byte count, SHA-256 checksum, and an MCP resource link. The agent can attach/copy the local file or retrieve the resource. Whether a download button appears depends on the coding agent; MCP does not prescribe that UI.

Resource listings show exports from the current MCP session. Registered export IDs support whole-file reads up to 1 MiB. For larger files, or agents without filesystem access:

```json
{"action": "read", "export_id": "<export UUID>", "offset": 0, "length": 65536}
```

Decode `data` from base64, append the bytes in order, and request `next_offset` until `eof` is true. Check the reconstructed byte count and SHA-256. Each chunk is at most 64 KiB. The server accepts registered export IDs only, never filesystem paths.

Existing calls such as `{"format":"summary"}` keep their original current-session view and accounting. Saved-run/session selections additionally include standalone fingerprint probes and local mutation candidates. Failures and skipped scenarios are archived alongside successes. Local mutation and skipped scenarios do not count as target attempts. Confidence remains a heuristic label and is never converted into a vulnerability severity.

## CLI, backup, and cleanup

The CLI examples below assume the project virtual environment is activated. Otherwise use `.venv/bin/anticells_red_mcp-reports` on macOS/Linux or `.venv\Scripts\anticells_red_mcp-reports.exe` on Windows, from the repository root.

The separate CLI reads reports without loading a prompt catalog or contacting a target:

```bash
anticells_red_mcp-reports list --limit 20
anticells_red_mcp-reports show --run-id <run-uuid>
anticells_red_mcp-reports export --session-id <session-uuid> --format html
anticells_red_mcp-reports export --run-id <run-uuid> --format json --output ./assessment.json
anticells_red_mcp-reports delete --run-id <run-uuid>
anticells_red_mcp-reports delete --session-id <session-uuid>
```

Use `--reports-dir /absolute/private/path` before the command to override the directory. For example, `anticells_red_mcp-reports --reports-dir /absolute/private/path list` inspects that store. CLI storage settings come from `ANTICELLS_RED_MCP_ENV_FILE` and the process environment; the profiles file's `env_files` are not applied to its directory selection. Pass the report directory explicitly if the server selects it there. `python -m anticells_red_mcp.reports.cli` provides the same commands. Explicit output copies refuse to overwrite an existing file. Deletion removes selected evidence and dependent exports, including combined exports containing a deleted run. Active runs and active sessions cannot be deleted. No automatic cleanup occurs.

For a complete portable backup, stop all MCP processes using this directory, then copy the entire report directory, including `reports.sqlite3` and `exports`. Restore it into a private local directory and set `ANTICELLS_RED_MCP_REPORTS_DIR` accordingly. Registered export paths are reconstructed from their IDs and filenames, so moving the directory is supported. Do not copy a live SQLite file directly; use SQLite's backup API if an online database backup is required. For a consistent database-plus-export backup, stopping writers is recommended. The catalog database is backed up separately.

## Recovery and evidence format

Execution statuses are `running`, `completed`, `failed`, `stopped`, and `interrupted`. Failed target attempts do not necessarily make the whole run fail. Configuration errors are run failures with an error label and do not become target attempts. Session lock files use OS locks to distinguish a dead process from another live coding-agent session. Abandoned runs become interrupted and are never automatically resumed.

Saving errors do not stop testing. A persistence warning appears in tool replies and background reports; pending records remain in memory, retry every five seconds, and are retried during orderly shutdown. Stable result IDs prevent duplicate inserts after recovery. If the process exits before recovery, unsaved evidence can be lost. A recovered interrupted run reports that persistence completeness is unknown. Exports disclose incomplete persistence; export failures return `report_error` and do not claim a saved file.

Saved report access remains available when catalog loading fails. Research calls continue to report the catalog error until the catalog is repaired. Report storage errors use static diagnostics that omit database paths, credentials, and evidence.

All formats use the same report document and statistics. HTML escapes target content and contains no scripts or external assets. Markdown displays evidence literally. JSON normally contains a readable report object. For exceptional legacy Unicode that would change during an ordinary JSON round trip, the whole document uses `encoded_content` with encoding `json-utf8-surrogatepass-base64`. Base64-decode its `data`, decode UTF-8 with `surrogatepass`, then parse JSON to recover the exact original Python values.

Previously lost in-memory reports cannot be recovered. Auxiliary Python-only entry points are not automatically archived. PDF and browser download services are not provided. Native Windows setup and the event-loop fix are included in the current installer; see [installation](installation.md).
