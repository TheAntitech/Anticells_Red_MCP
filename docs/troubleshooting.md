# Troubleshooting

## Catalog database errors

By default the server creates a SQLite file and initializes the catalog automatically. No database server is needed. For `database_unavailable`, check that the selected path is on an accessible local disk and that the user can read the file and write its directory during setup/publication. Close external editors holding long write transactions. Diagnostics omit private paths and stored content.

`postgres_migration_required` means old PostgreSQL settings or managed Docker state were detected. Export the old catalog, select a new `ANTICELLS_RED_MCP_DATABASE_PATH`, and restore it before switching the MCP configuration. See [migration instructions](catalogs.md#moving-from-postgresql).

`invalid_database_path` rejects connection URLs, SQLite URI options, and transient `:memory:` databases. `unrecognized_database` means the chosen SQLite file contains unrelated tables; choose a dedicated file. Existing unrelated or corrupt files are never overwritten.

With automatic setup disabled, the file must already be initialized. `schema_not_initialized` requires `anticells_red_mcp-catalog migrate`; an empty or incomplete catalog requires `seed`. `incompatible_schema` requires a compatible package and migration version. `restore_requires_empty_database` requires a new destination file; restore never replaces existing catalog edits.

An unavailable database blocks new content-consuming calls; started operations retain their snapshot, and reports and stop commands remain usable. There is no runtime fallback to packaged seeds.

`stale_update` means another publisher changed the record. Export it again and reconcile edits before importing with `--update`. `invalid_template_inputs` requires the declared placeholder names from the manifest. Failed imports are atomic and do not change the published revision.

## The template listing tool is missing or empty

Restart the MCP connection so the client refreshes tool discovery; the current server exposes twelve tools, including `list_attack_templates`. The default listing includes enabled templates from the five main catalogs. Use `include_auxiliary: true` or `include_disabled: true` for those records, and remove filters to check the full public list. Category matching follows actual engine membership. If pagination returns `catalog_revision_changed`, restart from offset zero using the new revision. Catalog errors must be fixed before templates can be listed; listing never falls back to seed files.

## Compatible templates are missing

Use `get_compatible_templates` with `include_incompatible: true` and inspect each entry's `compatibility.reason`. Custom text-only response mappings exclude tool scenarios; tools-only mappings exclude text-based scenarios. Supply the same nonempty `available_tools` schemas as execution to check function availability and arguments. Omitted or empty lists use synthetic definitions. `target_request_not_renderable` includes a safe error code for missing request fields or invalid substitutions. Disabled records need both `include_disabled` and `include_incompatible` to appear. Auxiliary catalogs are available through listing, not compatibility discovery.

Compatibility is checked locally and does not verify that an endpoint is reachable or that a model will accept the request. The query does not create a report run. See [compatibility examples](catalogs.md#find-compatible-templates).

## A specific template cannot be executed

Call `execute_attack_template` with the stable `id` from discovery, not its name. `template_not_found` means the ID is unknown; `template_disabled` means it is disabled; `template_not_executable` means it is an auxiliary technique or supporting resource. Only the five public catalogs support this operation. For `catalog_revision_changed`, inspect the updated template and use the new revision.

Target templates require exactly one of `target` or `target_url`; local mutation entries accept neither. `available_tools` is only accepted for tool-abuse entries. A skipped result includes its compatibility reason and makes no target request. Rendering errors return `target_configuration_error` without a failed target attempt. A completed call can still contain an unsuccessful heuristic result. See [single-template execution](catalogs.md#execute-one-template).

## A fingerprint profile is unknown or incomplete

`get_fingerprint_profile` runs a fresh scan; use `get_attack_report` with a saved `run_id` to retrieve an earlier profile without probing again. `no_usable_responses` means all probes failed or returned empty/unsupported text. Inspect `profile.probes` and `transport.outcome_counts`; `partial` means only some replies were usable. Unknown identity can also occur with usable replies when no existing signature matches. Reported model names and inferred model hints may differ because the latter come from a limited static candidate table.

The default budget is six requests. Set `intensity` from 1 to 5 for a larger budget, or choose primary fingerprint `template_ids`. A tools-only custom response mapping is rejected because profiling requires text. `template_not_fingerprint` rejects auxiliary fingerprint entries and other catalogs; disabled/unknown IDs and stale revisions also fail before delivery. See [profile fields and limitations](fingerprints.md).

## The server is idle in a terminal

`run.sh` starts a stdio server. It waits for MCP requests instead of showing a menu. Configure an MCP client and check that it discovers twelve tools.

## The client shows disabled or disconnected

Enable the local server entry in your client's settings, verify the absolute checkout path, and reload the MCP connection. Use the client's connection status and stderr logs to inspect startup errors. The command should be `bash`, with the path to `run.sh` passed as a separate argument. See the [configuration example](../config/mcp-client.example.json).

Install dependencies with `bash /absolute/path/anticells_red_mcp/install.sh`. `run.sh` prefers `.venv/bin/python`, then the older `venv/bin/python`, then `python3`. Set `ANTICELLS_RED_MCP_PYTHON` in the client's environment to choose another interpreter.

## Paths with spaces fail

Pass the script path as one argument, as shown in the JSON example. In a shell, quote the script path:

```bash
bash '/path with spaces/anticells_red_mcp/run.sh'
```

## The endpoint tool returns failures

For `target_url`, confirm that the endpoint accepts chat-completions JSON. Set `ANTICELLS_RED_MCP_TARGET_MODEL` if it requires a model and `ANTICELLS_RED_MCP_TARGET_API_KEY` for bearer authentication. Authenticated calls require `ANTICELLS_RED_MCP_TARGET_API_URL` and must use the same scheme, host and port. For a different JSON protocol, use a [custom target definition](targets.md). Keep credentials out of the target URL and repository. Empty or failed replies do not establish that a model resisted a technique.

## Target configuration errors

Use exactly one of `target` or `target_url`; `target_variables` requires `target`. `missing_variable` means a referenced environment, definition, or generated request field is absent. Request fields differ by module. `embedded_container_variable` means an object or array was inserted into a larger string: use a whole-value placeholder instead. `invalid_response_pointer` means a mapping is not a valid JSON Pointer. Missing response fields are failed replies, not configuration errors.

`unknown_target_profile` means the selected name was not loaded. Explicitly set `ANTICELLS_RED_MCP_TARGETS_FILE` and restart the server after file edits. Relative `env_files` paths start at the profiles file's directory. There is no automatic `.env` discovery. Later files override earlier ones, and process values override files.

`inline_environment_origin_not_authorized` requires a matching `ANTICELLS_RED_MCP_TARGET_API_URL`. `target_origin_changed` means an override or request value changed a bound scheme, host, or port. Configure a separate saved profile for the other origin. In a background loop, configuration errors stop work and appear in the report's `configuration_error` field.

## Invalid arguments

Tool errors return MCP `isError: true`. Check the tool schema: unsupported categories, extra properties, negative iteration limits and out-of-range mutation parameters are rejected. The advertised injection categories now match the existing implementation.

## A loop is already running

Call `stop_attack_loop`, wait for its result, then restart. Reports preserve completed records during the session. One iteration can contain many endpoint calls; it is not a request or spending limit.

## Reports disappear after restart

The default `get_attack_report` view covers the current process. Use `{"action":"list"}` to find runs saved in SQLite across restarts, then select a `run_id` or `session_id`. Check that the restarted process uses the same report directory and inspect any persistence warnings. See [saved report setup and recovery](reports.md).

## A tool scenario was skipped

If you supply `available_tools`, anticells_red_mcp sends exactly that schema list. A catalog technique is skipped when its tool is absent or its existing arguments do not match the supplied schema. Skipped records do not count as endpoint attempts or successes.

With a custom response mapping, `target_has_no_tool_call_mapping` means the definition supplies no `response.tool_calls` mapping. Add a mapping if the API returns structured proposals; see [response mappings](targets.md#response-mappings).

## Local mutations appear without target successes

Local fitness is a template score. Generated candidates are listed separately and do not establish target behavior. The public default disables hosted mutation generation.

## Windows stdio launch

The existing Bash helpers assume `.venv/bin/python`, while native Windows virtual environments use `Scripts`. A `bash` command resolving to an unconfigured WSL installation can fail before Python starts. The current `LocalIPCPolicy` also uses a file-descriptor wakeup that is incompatible with native Windows socket descriptors. These launcher/event-loop issues are separate from target configuration. Run the stdio integration suite in a compatible Linux/Bash environment; Windows launch support remains a separate fix.
