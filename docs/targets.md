# Configurable target requests

The five endpoint tools (`fingerprint_llm`, `jailbreak_attack`, `prompt_injection`,
`tool_abuse_exploit`, and `endless_attack_loop`) accept exactly one of:

- `target_url`: the existing chat-completions request and response format.
- `target`: a saved profile name or an inline JSON definition.

When using `target`, optional `target_variables` replaces matching definition
variables. It must be a JSON object. Overrides are shallow: replacing an object
variable replaces the whole object. Configuration is copied for each call or
background loop, so concurrent operations keep their own variable values.

## Set up saved profiles

Copy [config/targets.example.json](../config/targets.example.json) to your own
configuration file and change the URLs. The example selects `../.env`, relative
to the JSON file in `config/`. Create that private file with `API_KEY=...`, or
remove `env_files` and provide the credential through the process environment.
Do not commit your private configuration or credentials.

Point the server at your JSON file through its process environment:

```bash
export ANTICELLS_RED_MCP_TARGETS_FILE='/absolute/path/to/targets.json'
bash run.sh
```

For a client-launched server, put the variable in the MCP server entry's `env`
settings. On PowerShell, use
`$env:ANTICELLS_RED_MCP_TARGETS_FILE = 'C:\absolute\path\targets.json'`.
The existing Windows launcher limitation is described in
[troubleshooting](troubleshooting.md#windows-stdio-launch).

A minimal profiles file looks like this:

```json
{
  "env_files": [".env"],
  "targets": {
    "custom_api": {
      "url": "https://gateway.example/chat",
      "method": "POST",
      "headers": {"Authorization": "Bearer ${env.API_KEY}"},
      "variables": {"workspace": "research", "max_tokens": 512},
      "body": {
        "question": "${request.prompt}",
        "workspace": "${vars.workspace}",
        "limit": "${vars.max_tokens}"
      },
      "response": {"text": "/result/answer"}
    }
  }
}
```

Call `fingerprint_llm`, for example, with:

```json
{
  "target": "custom_api",
  "target_variables": {"workspace": "staging"},
  "intensity": 1
}
```

Profiles and environment files are loaded when the server starts. Restart it
after changing those files. Names may contain letters, digits, underscores, and
hyphens. A missing or malformed selected file is a configuration error.

## Inline definitions

An inline definition uses the same fields, directly in an MCP call:

```json
{
  "target": {
    "url": "https://gateway.example/chat",
    "method": "PUT",
    "headers": {"Authorization": "Bearer ${env.API_KEY}"},
    "body": {"question": "${request.prompt}", "limit": "${vars.limit}"},
    "variables": {"limit": 128},
    "response": {"text": "/result/answer"}
  },
  "target_variables": {"limit": 512},
  "payload_override": "A test prompt"
}
```

This example is for `prompt_injection`. To use environment values in inline
definitions, configure `ANTICELLS_RED_MCP_TARGET_API_URL` with the authorized
origin, for example `https://gateway.example/chat`.

For setups without a profiles file, `ANTICELLS_RED_MCP_ENV_FILE` explicitly
selects one environment file. Relative paths in these process settings resolve
from the server's working directory; absolute paths are recommended. Inline
definitions cannot select files, import Python, or run expressions.

## Definition fields

| Field | Behavior |
| --- | --- |
| `url` | Required HTTP or HTTPS URL. No embedded user credentials or fragment. |
| `method` | `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`; default `POST`. |
| `headers` | Optional object of header names to string templates. |
| `variables` | Optional object of JSON defaults, overridden by `target_variables`. |
| `body` | Optional JSON value or template. If supplied, it replaces the entire generated body. |
| `response` | Optional JSON Pointer mapping for text and proposed tool calls. |

Omitting `body` sends the original generated chat body, including any configured
`ANTICELLS_RED_MCP_TARGET_MODEL`. Supplying `body: null` sends JSON `null`.
Omission does not mean an empty HTTP body, including for `GET` or `DELETE`.
Use `"body": "${request.body}"` to explicitly forward the entire generated body.
A custom body receives no automatic model, messages, or temperature fields.

The default content type is `application/json`, and custom headers can override
it. Header names must be HTTP tokens; values must be ASCII strings without
newlines. `Host`, `Content-Length`, and `Transfer-Encoding` are transport-owned
and cannot be configured. Custom definitions never receive the legacy bearer
key automatically; put authentication in their headers explicitly.

## Variables and rendering

| Placeholder | Value |
| --- | --- |
| `${env.API_KEY}` | String from explicitly selected environment files or the process environment. |
| `${vars.workspace}` | Definition value, after per-call overrides. |
| `${request.prompt}` | Actual prompt for this attempt; injection uses the injection payload itself. |
| `${request.messages}` | Complete generated conversation array. |
| `${request.tools}` | Generated function definitions, or `[]` when absent. |
| `${request.body}` | Complete generated request, including configured model. |
| `${request.body.temperature}` | A field in that generated request. |

Dot-separated paths access nested `vars` and `request` values; numeric segments
can access array indexes. Environment names are matched literally after `env.`.
Request-specific fields vary by module; a reference to an absent field fails
before that HTTP request is sent.

Rendering walks parsed JSON values, including nested objects and arrays. Object
keys are not templates. A value consisting entirely of a placeholder preserves
its type: `"limit": "${vars.max_tokens}"` sends a JSON number when the variable
is numeric. Embedded placeholders produce strings, for example
`"Authorization": "Bearer ${env.API_KEY}"`. Embedded booleans and null use
`true`, `false`, and `null`; embedding an object or array is an error.

Environment values remain strings, even `"512"` or `"false"`. Use JSON variables
for numbers, booleans, arrays, and objects. Substitution happens once: placeholder
text inside a prompt or substituted variable stays literal. `$${env.API_KEY}`
renders as the literal text `${env.API_KEY}`. Quotes, backslashes, Unicode, and
newlines in JSON bodies are serialized safely; no expression evaluation occurs.

No `.env` file is discovered automatically, and loading never changes
`os.environ`. File precedence, from lowest to highest:

1. `ANTICELLS_RED_MCP_ENV_FILE`, when explicitly set in the process environment.
2. Files listed in the profiles file's `env_files`, in order; later files win.
3. Process environment variables, including explicitly empty values.

Profile `env_files` paths resolve relative to the profiles JSON file. Environment
file values are not interpolated themselves. Selected environment files can also
provide normal server settings such as the model or authorized inline origin.

## Response mappings

Without `response`, existing extraction remains in use: chat-completions
`choices[0].message.content`, top-level `content` or `response`, and existing tool
proposals. For custom JSON replies, specify JSON Pointer paths:

```json
{
  "text": "/result/answer",
  "tool_calls": {
    "path": "/result/actions",
    "name": "/name",
    "arguments": "/arguments"
  }
}
```

This matches a reply such as:

```json
{
  "result": {
    "answer": "Proposed action",
    "actions": [{"name": "example_tool", "arguments": {"label": "fixture"}}]
  }
}
```

`text` must resolve to a string. `tool_calls.path` must resolve to an array;
`name` and `arguments` are relative to each item in that array. Names must be
nonempty strings. Arguments may be an object or a JSON-encoded object string.
Proposals are normalized and checked against the existing function schemas;
returned functions are never executed. Existing scoring examines the first
proposal. A mapping may include only `tool_calls` for tools-only replies.

Pointers support array indexes, for example `/results/0/answer`. `/a~1b/~0name`
reads property `a/b`, then property `~name`. The empty pointer `""` selects the
root value. There are no wildcard or query expressions. Missing mapped fields,
wrong types, and malformed proposals invalidate the reply, including when
another mapped field was valid. Empty text does not establish success.

An explicit custom `response` without `tool_calls` skips tool-abuse scenarios
before HTTP delivery. Their reason is `target_has_no_tool_call_mapping`; they
are excluded from target-attempt totals, including in background loops. Omitted
response mappings retain legacy tool support.

## Check compatible templates without contacting the target

Call `get_compatible_templates` with the same `target` / `target_url` selector and optional `target_variables` as an assessment. Add `available_tools` for exact function/schema checks and `include_incompatible: true` for exclusion reasons. For example:

```json
{"target": "custom_api", "module": "tool_abuse", "include_incompatible": true}
```

An explicit text-only response mapping excludes tool scenarios; a tools-only mapping excludes text-based modules. Request-dependent variables are rendered against each actual template request locally, without exposing the rendered values. A body referencing `${request.body.max_tokens}`, for example, fits fingerprint requests but not injection requests, which do not generate that field. Local mutation templates require no target request. See [complete compatibility behavior](catalogs.md#find-compatible-templates).

## Origin restrictions and errors

Saved profiles bind environment-derived values to the origin of their configured
URL, rendered with their default variables. Overrides cannot change its scheme,
host, or port. Provide defaults for variables used to establish that origin.
Inline definitions using `${env...}` require the origin configured by
`ANTICELLS_RED_MCP_TARGET_API_URL`. The origin is checked again for each rendered
request. Request placeholders and overrides cannot move credentials elsewhere;
redirects are disabled. Paths and query strings may vary within the bound origin.

Results identify custom targets by profile name or `inline`. Configuration
representations omit environment snapshots, credentials, and rendered bodies.
Target replies remain untrusted data; heuristic labels do not prove external
effects.

Configuration failures return MCP `isError: true` with a safe code, for example:

```json
{"error": "target_configuration_error", "code": "missing_variable"}
```

Invalid tool argument shapes or conflicting selectors return `invalid_arguments`.
Static template references are checked before modules are constructed. References
to generated request fields are checked before the affected request. A background
configuration error stops the loop and appears in `get_attack_report` under
`configuration_error`, without becoming a failed model attempt. HTTP errors and
malformed target replies remain unsuccessful attempts. Requests are not retried.

## Migration and scope

Existing `target_url` calls, legacy model/bearer settings, the original eight MCP tools,
and all 194 catalog entries remain supported. To migrate one endpoint, replace
its `target_url` argument with a profile name or definition and specify its
authentication headers. Add only the body and response mappings it needs.

The primary fingerprint, jailbreak, injection, tool-abuse, and shared hosted
mutation paths use this transport. Public `creative_mutation` remains local by
default and does not gain target arguments. Auxiliary Python-only engines that
bypass the shared transport are outside this change. Streaming, login sequences,
token refresh, response-derived session variables, and automatic retries are
not supported in this version.
