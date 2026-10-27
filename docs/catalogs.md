# SQLite catalogs

All prompt content lives in a local SQLite database, using Python's standard-library `sqlite3` module. No PostgreSQL server, Docker, database credentials, or extra database package is needed. The original eight MCP tools retain their interfaces. Template discovery, single-template execution, and fingerprint profiles bring the total to twelve tools. Python still handles execution, scoring, mutation algorithms, selection, and HTTP transport.

The initial database contains **496 resources**: 365 techniques in 21 namespaces and 131 supporting resources. This includes auxiliary modules, conversation wrappers, prompt fragments, mutation templates, and tool definitions. The five public catalogs retain their original **194 entries**, exact values, order, duplicate names, and category memberships.

## Browse templates through MCP

Call `list_attack_templates` without a target to browse the current published catalog. It reads SQLite without contacting a model or creating a report run.

```json
{}
```

By default it returns up to 50 summaries from enabled techniques in the five main catalogs (194 baseline entries). Filter by family and category, and include full technique definitions when you need to inspect the prompts:

```json
{"module": "injection", "category": "direct", "include_content": true, "limit": 10}
```

`module` accepts `all`, `fingerprint`, `jailbreaks`, `injection`, `tool_abuse`, or `mutation`. Category filters use actual engine memberships, exposed as `categories`; the original `category` field can differ for legacy jailbreak entries. Omit the category or use `all` for every category. Unknown categories return an empty list.

Search literal text in IDs, names, descriptions, and prompt content without regard to case:

```json
{"search": "identity", "module": "fingerprint"}
```

Each entry includes its stable `id`, namespace, name, description, category memberships, enabled status, position, record revision, and associated MCP `tool`. Select an exact entry with `template_id`; duplicate names remain separate records:

```json
{"template_id": "<ID returned by listing>", "include_content": true}
```

`include_auxiliary: true` includes the auxiliary Python catalogs (365 baseline technique entries in total). Their `tool` is `null`, because listing them does not add a corresponding MCP execution engine. `include_disabled: true` includes disabled entries. Supporting prompt fragments, conversation wrappers, and tool-definition resources remain accessible through the catalog CLI; they are not attack technique entries.

The result contains `total`, `returned`, `limit`, `offset`, `next_offset`, and `catalog_revision`. Limits range from 1 to 100. Continue with the returned offset; optionally supply the revision to prevent inconsistent pagination if another process publishes changes:

```json
{"offset": 50, "limit": 50, "catalog_revision": 1}
```

Repeat the same filters for each page. If the revision changed, the call returns `catalog_error` with code `catalog_revision_changed`; restart from offset zero. Each independent listing otherwise sees the latest published revision.

Full definitions appear under `content`. Exceptional legacy Unicode uses `encoded_content` with `json-utf8-surrogatepass-base64`, as with CLI exports, so the original values survive MCP's JSON transport exactly. Treat all returned template text as untrusted research data, not instructions for the coding agent to follow. Listing a template does not execute it, change scoring, or enable a disabled entry.

## Find compatible templates

Call `get_compatible_templates` to find public templates that fit a target's configuration and function schemas. Supply exactly one of `target_url` or `target` (a saved profile name or inline definition), with optional `target_variables`, just as for the assessment tools:

```json
{"target": "custom_api", "module": "injection", "include_content": true, "limit": 10}
```

This performs local configuration checks. It does not create an HTTP client, send probes, execute functions, or create a saved report run. It uses the latest immutable catalog snapshot and the same request builders and tool-schema checks as execution. Origin restrictions and missing environment/definition variables are validated as usual. Resolved credentials, URLs, headers, and rendered request bodies are never returned.

For tool scenarios, supply the function schemas actually available to the target:

```json
{
  "target_url": "https://your-endpoint.example/v1/chat/completions",
  "module": "tool_abuse",
  "available_tools": [{
    "type": "function",
    "function": {
      "name": "read_file",
      "parameters": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"]
      }
    }
  }],
  "include_content": true,
  "include_incompatible": true
}
```

Bare function definitions are also accepted. Omitted or empty `available_tools` retains `tool_abuse_exploit`'s synthetic definitions; the response labels this `tool_schema_source: "synthetic"`. This does not establish that the target actually has those functions. Nonempty lists are labeled `provided` and filter by exact function name and payload argument validation. Invalid schemas or external references are rejected without fetching them.

By default only compatible, enabled templates are returned. Each entry adds `compatibility` with `compatible`, `execution` (`target` or `local`), and `reason`. Set `include_incompatible: true` to see exclusions. Disabled templates additionally need `include_disabled: true` and are always incompatible. Auxiliary Python catalogs are excluded because not all use the configurable transport.

| Reason | Meaning |
| --- | --- |
| `configuration_checks_passed` | The generated request can be rendered and the applicable mappings/schema checks passed. |
| `local_mutation_no_target_required` | This template belongs to the local mutation tool and does not use the target. |
| `target_has_no_tool_call_mapping` | An explicit custom response mapping lacks `tool_calls`. |
| `target_has_no_text_mapping` | A text-based module cannot extract text through the explicit response mapping. |
| `tool_unavailable` | The scenario's function name is missing from the supplied tools. |
| `arguments_do_not_match_schema` | The template's arguments fail the supplied function's JSON Schema. |
| `invalid_tool_schema_reference` | A local schema reference cannot be resolved. |
| `invalid_structured_payload` | The scenario does not contain an object payload with object arguments. |
| `target_request_not_renderable` | Rendering failed for this template; `code` gives the safe configuration error, such as `missing_variable`. |
| `template_disabled` | The record is disabled in the published catalog. |

The response includes `checked_total`, `compatible_total`, and `incompatible_total` across all entries matching the filters, before pagination. `total` counts entries eligible for the returned list. The usual `module`, category membership, `search`, `template_id`, `include_content`, `limit`, `offset`, and `catalog_revision` options apply. Repeat the same target, tool schemas, overrides, and filters on subsequent pages. Full definitions retain the lossless Unicode representation described above.

Compatibility is a static configuration assessment, not a prediction of attack success or proof of endpoint availability, authentication, model capabilities, or actual response shape. Rendering a custom body does not verify that the body forwards the prompt or tool definitions. A category called `multimodal` still uses the current text transport. Local mutation entries are labeled separately. No probing, scoring, or execution behavior changes as a result of this query.

## Execute one template

Use an entry's stable `id` from `list_attack_templates` or `get_compatible_templates` to call `execute_attack_template`:

```json
{
  "template_id": "<ID returned by discovery>",
  "target": "custom_api",
  "catalog_revision": 1
}
```

Use the actual `catalog_revision` returned by discovery, or omit it to select the latest published version. A stale revision fails before execution. Names are not accepted in place of IDs: different entries can have identical names. The operation executes exactly that entry without category selection, random sampling, chained attempts, retries, or a background loop.

For fingerprint, jailbreak, injection, and tool-abuse templates, supply exactly one of `target_url` or `target`. Saved profiles, inline definitions, and `target_variables` work as for the other target tools. For `tool_abuse` entries, optionally supply `available_tools` in the same format as compatibility discovery. The selected proposal is checked against these schemas; functions are never executed. Omitted or empty tool lists use the existing synthetic definitions.

For a local mutation template, omit all target arguments:

```json
{"template_id": "<mutation template ID>"}
```

This performs one local mutation through the existing engine, rather than the population evolution performed by `creative_mutation`. No HTTP request is made. Target arguments are rejected for mutation templates, and `available_tools` is accepted only for tool-abuse entries. This tool does not accept payload overrides, intensity, categories, generations, or a number of attempts.

Only enabled technique entries in the five public catalogs are executable. Unknown IDs return `catalog_error` / `template_not_found`; disabled entries return `template_disabled`; auxiliary techniques and supporting resources return `template_not_executable`. No target request is sent for these errors.

Execution repeats the local compatibility checks against the pinned snapshot. Missing tools, mismatched arguments, or unsupported response mappings produce one skipped result with a reason and zero target attempts. Invalid configuration, including a request placeholder that cannot be rendered, returns a configuration error without recording a failed target attempt. A compatible remote template makes one HTTP request through its existing engine and retains that engine's scoring. An HTTP failure or empty reply is an unsuccessful attempt. `status: "completed"` means execution finished, not that the heuristic result was successful.

The response includes the selected `template` identity, catalog revision, compatibility result, one-element `results`, statistics, and the normal `run_id`, `session_id`, and persistence status. Full evidence is saved once, with the stable template ID and selected revisions in run provenance. The new tool's results also appear in the current-session report, including fingerprint and local mutation results; local mutations and skips remain excluded from target-attempt totals. Existing tools retain their previous history behavior.

Export the saved run through `get_attack_report`:

```json
{"action": "export", "run_id": "<run_id from execution>", "export_format": "markdown"}
```

New calls see catalog publications; an in-flight execution keeps its original snapshot. Failed persistence produces the existing warning and retry behavior without preventing testing. See [saved reports](reports.md).

For a structured target profile, use `get_fingerprint_profile` with optional `template_ids` from the primary fingerprint catalog. It runs a bounded set of probes and saves observed behavior separately from heuristic identity estimates. See [fingerprint profiles](fingerprints.md).

## Automatic setup for coding agents

Install the package and connect its existing MCP command. First launch creates the SQLite file, applies versioned migrations, and installs the packaged catalog. Later launches apply pending migrations and add missing baseline records without overwriting edits or disabled status. No setup commands or database variables are needed for a new user. Initialization runs at server startup, including pip/wheel/package-runner installations, rather than during package builds.

The default file is `catalog.sqlite3` in the user's application data directory:

| Platform | Directory |
| --- | --- |
| Windows | `%USERPROFILE%/AppData/Local/anticells_red_mcp/catalog` |
| Linux | `~/.local/share/anticells_red_mcp/catalog` |
| macOS | `~/Library/Application Support/anticells_red_mcp/catalog` |

Agents running under the same user share this file. Set `ANTICELLS_RED_MCP_STATE_DIR` to use a different default directory, or `ANTICELLS_RED_MCP_DATABASE_PATH` to choose a specific SQLite file. An explicit file path takes precedence. Use an absolute path on a local disk outside a synchronized source checkout. SQLite URIs, connection URLs, and `:memory:` are not accepted. The database persists after the agent exits.

The Bash and PowerShell installers prepare the catalog in advance. Installed-package users may optionally do the same:

```bash
anticells_red_mcp-catalog setup
```

Startup progress goes to stderr; stdout remains reserved for MCP messages. Simultaneous agent starts and publishers coordinate through SQLite transactions. New database files receive private Unix permissions; Windows uses inherited directory permissions. Use `install.ps1` for native Windows setup.

## Configuration and manual initialization

The CLI examples below assume the project virtual environment is activated. Otherwise prefix `anticells_red_mcp-catalog` with `.venv/bin/` on macOS/Linux, or use `.venv\Scripts\anticells_red_mcp-catalog.exe` on Windows, from the repository root.

Pass variables through the MCP client's environment, or explicitly select a private environment file with `ANTICELLS_RED_MCP_ENV_FILE`. The target profile `env_files` mechanism also works. There is no automatic `.env` discovery. Process environment values win over explicitly selected files.

```bash
export ANTICELLS_RED_MCP_DATABASE_PATH='/absolute/local/path/catalog.sqlite3'
anticells_red_mcp-catalog setup
```

PowerShell equivalent:

```powershell
$env:ANTICELLS_RED_MCP_DATABASE_PATH = 'C:/local/data/catalog.sqlite3'
anticells_red_mcp-catalog setup
```

The stdio entry point remains `anticells_red_mcp`. Administration uses `anticells_red_mcp-catalog`, also available as `python -m anticells_red_mcp.catalog.cli`.

Set `ANTICELLS_RED_MCP_CATALOG_AUTO_SETUP=false` to require an existing initialized file. Runtime reads then open SQLite in read-only mode and never create or seed a missing file. Initialize it explicitly with write access:

```bash
anticells_red_mcp-catalog migrate
anticells_red_mcp-catalog seed
```

`setup` validates the existing catalog in manual mode. Technique `new` and `validate` always work offline. Other commands use the selected SQLite file. Target API credentials remain in environment/profile configuration; they are not catalog database credentials.

## Add a technique

Create an example for an existing namespace and category:

```bash
anticells_red_mcp-catalog new --namespace injection.direct --category direct --name my_probe --output my-probe.json
```

Edit `content.payload` and its description. Preserve the generated ID when editing the same record. Validate locally, then publish:

```bash
anticells_red_mcp-catalog validate my-probe.json
anticells_red_mcp-catalog import my-probe.json
```

The next `prompt_injection` call with `injection_type: "direct"` includes the technique. No Python change or restart is needed. Existing sampling and intensity rules still apply to modules that sample their catalogs. Active calls and loops retain their original snapshot.

[config/technique.example.json](../config/technique.example.json) is a complete additive example. Authoring documents separate database metadata from the existing technique dictionary:

```json
{
  "format_version": 1,
  "records": [{
    "id": "custom/example-prompt",
    "namespace": "injection.direct",
    "kind": "technique",
    "enabled": true,
    "memberships": ["direct"],
    "content": {
      "name": "example_prompt",
      "category": "direct",
      "payload": "Return the word EXAMPLE.",
      "description": "A simple response-format probe."
    }
  }]
}
```

IDs are separate from names: original duplicate names remain distinct records. A new record without `position` appends to its namespace. Updates preserve position unless explicitly changed. Positions must be unique within a technique namespace; reorder affected records together in one import. For `jailbreaks.engine`, `memberships` controls selection independently of `content.category`, preserving its historical mapping. Other engines require membership to match `content.category`. New records default to membership in their declared existing category.

The five public namespaces are `fingerprint.scanner`, `jailbreaks.engine`, `injection.direct`, `tool_abuse.exploit`, and `mutation.creative_engine`. Use `new --namespace` for any namespace in the packaged [manifest](../src/anticells_red_mcp/catalog/data/manifest.json), which declares module categories and schemas. Generated examples preserve structured payloads and tool schemas where required. New engines and new categories require a separate code change.

## Edit, inspect, and disable

The commands below use `custom/example-prompt`, the ID in the JSON example above. Import that example first, or replace the ID with the one generated for your own technique and shown by `list`.

```bash
anticells_red_mcp-catalog list --namespace injection.direct
anticells_red_mcp-catalog show custom/example-prompt
anticells_red_mcp-catalog export --id custom/example-prompt --output edit.json
# Edit content, retaining id and revision.
anticells_red_mcp-catalog validate edit.json
anticells_red_mcp-catalog import edit.json --update
```

Exports include each record's revision. `--update` and a matching record revision are required to replace an existing record. If another publisher changed it, export again and reconcile your edit. An import merges additions and explicit updates; absent IDs are not deletions. An invalid or incomplete definition rejects the entire import. Successful write transactions increment the global revision once. Seeding inserts missing baseline IDs without overwriting edits and leaves the revision unchanged if nothing changed.

```bash
# Substitute the record revision displayed by list/show/export.
anticells_red_mcp-catalog disable custom/example-prompt --revision 2
anticells_red_mcp-catalog enable custom/example-prompt --revision 3
anticells_red_mcp-catalog export --output catalog-export.json
```

Disabled techniques remain inspectable/exportable and are excluded from execution. Required supporting resources cannot be disabled. A publication that leaves a required technique catalog empty is rejected.

`validate` and technique `new` work without a database. Local validation checks file contracts; publication additionally checks the complete resulting database, positions, revisions, required resources, and availability.

## Supporting templates

Choose a `template` or `data` ID from `list`, then generate an editable copy:

```bash
anticells_red_mcp-catalog new --template mutation.creative_engine/mutate_payload_004 --output templates.json
anticells_red_mcp-catalog validate templates.json
anticells_red_mcp-catalog import templates.json --update
```

Collections may contain additional variants within their existing schema. Individual supporting resource IDs are fixed by their consuming code. Standalone templates declare named inputs in the manifest, such as `{value0}`; collection templates use declared inputs such as `{p}`. Preserve those input names. Only named placeholders are allowed: no expressions, attribute access, indexing, conversions, format specifications, or environment lookup. Double braces represent literal braces in format templates. Technique payloads are literal content and are not interpreted as templates.

Tool definitions must remain valid schemas using inline or local references. Returned functions remain proposals and are never executed. Scoring patterns and executable mutation strategies stay in Python.

## Runtime and standalone Python

Each catalog-consuming call checks the database revision inside a consistent read transaction. An unchanged revision reuses the cached immutable snapshot; a changed revision loads and validates a complete replacement. SQLite work runs in a worker thread with its own short-lived connection, closed after each transaction. Publication takes a write lock with `BEGIN IMMEDIATE`; SQLite's rollback journal provides atomic updates and readers never see partial imports. Lock waits are bounded to five seconds. No database query runs for each technique attempt.

Started calls and loops retain their snapshot even if the database becomes unavailable. Reports and stop commands do not read the database. New content-consuming calls fail with `catalog_error` before target execution when the database is unavailable, its schema is incompatible, or its content is invalid. These errors are excluded from target-attempt totals. Packaged files initialize the database; runtime calls never silently fall back to them. Configuration representations and diagnostics omit database paths, old connection strings, and stored content.

Standalone constructors retain their existing arguments and load synchronously when no snapshot is supplied. Reusing a configuration intentionally reuses its pinned snapshot. Inside an event loop, prepare it asynchronously:

```python
from anticells_red_mcp.catalog import bootstrap, using_snapshot
from anticells_red_mcp.mcp_server.config import load_config
from anticells_red_mcp.modules.injection.direct import InjectionEngine
from anticells_red_mcp.modules.fingerprint.techniques import FingerprintTechniques

async def prepare():
    config = load_config()
    snapshot = await bootstrap(config)
    engine = InjectionEngine(config)
    with using_snapshot(snapshot):
        probes = FingerprintTechniques()  # Existing constructor has no config argument.
    return engine, probes
```

Call `bootstrap` again for a new operation to refresh its snapshot. Auxiliary modules use the same repository while retaining their existing HTTP behavior.

## Storage, upgrades, and backups

Versioned SQL migrations define catalog records with stable IDs, namespace, kind, position, enabled status, memberships, and revisions. Content uses SQLite `BLOB`: serialize JSON with `ensure_ascii=False`, then encode/decode UTF-8 using `surrogatepass`. This retains dictionary order, null characters, and legacy surrogate code points exactly. See Python's [SQLite interface](https://docs.python.org/3/library/sqlite3.html).

Ordinary exports use readable JSON. Values that change under an ordinary JSON round trip use `encoded_content: {"encoding": "json-utf8-surrogatepass-base64", "data": "..."}`. Preserve that tagged envelope when editing. Compatibility tests retain original content hashes, the 194-entry digest, generated requests, and deterministic mutation fixtures.

For a portable, consistent backup, export **all records**, without filters:

```bash
anticells_red_mcp-catalog export --output catalog-backup.json
```

To restore, select a **new, empty file** before running any command that seeds it:

```bash
export ANTICELLS_RED_MCP_DATABASE_PATH='/absolute/local/path/restored.sqlite3'
anticells_red_mcp-catalog restore catalog-backup.json
anticells_red_mcp-catalog list
```

`restore` validates the complete catalog, migrates the schema, and restores all records atomically, retaining positions, enabled status, exact content, and revisions. It refuses a database that already contains catalog data. Ordinary `import --update` retains its stale-update checks and is used to edit an existing catalog. Keep backups private: they contain your authored prompts. Research evidence is saved separately in `reports.sqlite3`; a catalog export does not back it up. Follow the separate [report backup instructions](reports.md#cli-backup-and-cleanup) to preserve reports and exports.

Before upgrading, export a backup. Install the new package and restart; automatic setup applies pending migrations and missing seed records. With automatic setup disabled, run `migrate` and `seed` explicitly. Publishing content alone does not require a restart.

## Moving from PostgreSQL

Before upgrading the old installation, use its existing configuration and CLI to export all records:

```bash
anticells_red_mcp-catalog export --output catalog-backup.json
```

After upgrading, set `ANTICELLS_RED_MCP_DATABASE_PATH` to a new local file and run `restore` as above. This accepts the previous PostgreSQL version's full JSON export, including exceptional Unicode, operator edits, revisions, disabled records, and added techniques. Remove `ANTICELLS_RED_MCP_DATABASE_URL` from the MCP client's settings and selected environment files after verifying the SQLite catalog.

An old database URL or managed Docker `database.json` without an explicit SQLite path produces `postgres_migration_required`; startup will not silently replace an existing catalog with fresh seeds. An explicit SQLite path selects the new backend even while legacy settings remain available for recovery. Keep the old database and its backup until the transfer is verified. Docker containers and volumes are never deleted by the new server. PostgreSQL connections and managed Docker provisioning are no longer runtime features.

## Integration tests

```bash
python -m pytest -q
```

The original regression scenarios inject a test snapshot. Storage tests use real SQLite files in temporary directories and run without external services or database variables. They cover exact content, concurrent initialization/publication, stale edits, atomic rollback, snapshot isolation, outages, migration failures, backup/restore, and CLI authoring. MCP stdio checks use native Python on Windows and also cover the Bash helper on macOS/Linux.
