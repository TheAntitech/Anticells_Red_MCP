# Target fingerprint profiles

`get_fingerprint_profile` probes a target now and returns a structured profile with supporting evidence. It also saves the profile and complete probe results in a report run. The existing `fingerprint_llm` tool retains its original interface and behavior.

## Generate a profile

Restart the MCP connection after updating the package so the coding agent discovers the new tool. Call `get_fingerprint_profile` with a saved target:

```json
{"target": "custom_api", "intensity": 1}
```

Or use a legacy chat endpoint:

```json
{"target_url": "https://your-endpoint.example/v1/chat/completions"}
```

Supply exactly one of `target` or `target_url`. Inline target definitions and `target_variables` work as with the other assessment tools. A profile requires a text response: an explicit custom mapping containing only tool calls is rejected before HTTP delivery. Credential-origin restrictions, custom authentication, and disabled redirects remain in force. See [target configuration](targets.md).

Each call runs a fresh scan. `intensity` is 1–5, defaulting to **1**, with at most `intensity × 6` requests. Enabled entries in `fingerprint.scanner` run by descending weight; ties retain catalog order. The original catalog has 30 fingerprint entries. Calls do not run jailbreak, injection, tool-abuse, or mutation scenarios, and do not retry requests.

The server's outbound caps also apply: 20 requests per invocation and 500 per session per minute by default. A larger intensity does not override those limits; see [security settings](../SECURITY.md#request-and-evidence-controls).

To restrict the scan, obtain stable IDs from `list_attack_templates` with `module: "fingerprint"`, then pass them as `template_ids`:

```json
{
  "target": "custom_api",
  "template_ids": ["<fingerprint template ID>"],
  "catalog_revision": 1
}
```

Use the revision returned by discovery, or omit it to use the latest published catalog. The request budget still applies to an explicit selection. Duplicate IDs, empty selections, unknown IDs, disabled entries, and IDs outside the primary fingerprint catalog are rejected. New calls see catalog publications; an active scan retains its original snapshot.

Every selected request is checked for template-rendering errors before probing begins. Missing variables, incompatible mappings, stale revisions, and catalog errors return an MCP error without creating failed target attempts. Transport errors and malformed replies are recorded as unsuccessful probes; the remaining probes continue.

## Read the profile

The reply contains `profile`, `statistics`, `run_id`, `session_id`, and `persistence`.

| Profile field | Meaning |
| --- | --- |
| `profile_version`, `started_at`, `completed_at`, `catalog_revision`, `target` | Format version and scan provenance. Target labels omit query strings. |
| `status` | `complete` when every probe returned usable text, `partial` when some did, or `no_usable_responses` when none did. |
| `identity.reported_models` | Model names returned in response metadata, distinct from the configured request model. These are unverified claims. |
| `identity.provider_hint`, `model_hint`, `confidence` | The existing scanner's signature-based inference. Confidence is a heuristic score, not a calibrated probability. |
| `legacy_estimates` | Architecture, context-window, and safety labels from the scanner's static candidate table. `measured: false` explicitly marks them as unmeasured. |
| `coverage` | Budget, eligible and selected template counts, attempted probes, usable replies, and failed replies. |
| `behavior` | Refusals detected by existing rules, and their fraction of usable replies. With no usable replies, the rate is `null`. |
| `transport` | Available HTTP status counts, probe outcomes, and observed latency minimum/mean/maximum in milliseconds. These include network and gateway time. |
| `signals` | Aggregated signature scores and indicators. |
| `probes` | Per-probe template ID/revision, saved result ID, outcome, status, timing, refusal flag, reported model, indicators, signatures, and a response excerpt of at most 300 characters. |

`complete` describes usable responses, not verified identity or target safety. A target may report one model name while the legacy candidate table selects another model hint; both are retained with their distinct meanings. With no recognized signals, identity remains `unknown` and confidence is zero. All-failed scans also retain unknown identity instead of inventing an answer.

Headers and model self-descriptions can be spoofed or describe a gateway. Refusal rules can miss refusals, and absence of a refusal does not establish a vulnerability. Tool support, actual context capacity, architecture, and model version are not verified by this profile. Returned text remains untrusted evidence.

## Retrieve and export later

The saved run contains `fingerprint_profile` alongside its complete evidence. Retrieve it without contacting the target again by calling **`get_attack_report`**:

```json
{"action": "view", "run_id": "<run_id from profile generation>", "format": "summary"}
```

The profile appears at `runs[0].fingerprint_profile`. `format: "detailed"` also includes the saved probe evidence. Saved profiles remain available after restart and during a catalog outage. `action: "list"` defaults to the current session; supply an explicit `session_id` for an older session, or use the reports CLI to discover runs across sessions. Older `fingerprint_llm` runs retain their original evidence and do not retroactively gain a profile.

Export the profile and full evidence together:

```json
{"action": "export", "run_id": "<run_id>", "export_format": "markdown"}
```

JSON and HTML exports are also supported. The normal export resource link, file path, chunk retrieval, backup, and deletion workflows apply; see [reports](reports.md).

Each probe is saved once, with the profile linking to its independent result ID. Profile-generation probes also enter current-session report statistics; a positive fingerprint result means usable text, not a verified vulnerability. Existing `fingerprint_llm` history behavior remains unchanged. Authentication headers, resolved custom bodies, environment snapshots, and configured credentials are excluded or redacted. Redaction happens before profile excerpts are shortened.

If storage is unavailable, probing continues with the existing persistence warning and in-memory retry queue. A completed profile is held with its run for retry. If a process stops during scanning, completed probes remain saved, but the run may have no finished profile; interrupted scans are not automatically resumed.
