"""Target definitions, isolated variable snapshots, and data-only templates."""
# ♢ 𝓜𝖗𝚇₀𝚛𝚍 ⚡🖤  —  inline-env rejection + saved-profile boundary (F2)

import copy
import io
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from dotenv import dotenv_values
from dotenv.parser import parse_stream
from jsonschema import Draft202012Validator

from .endpoint_safety import EgressPolicyError, check_host


class TargetConfigurationError(ValueError):
    """A public error code that never contains resolved values or file contents."""

    def __init__(self, code):
        self.code = code
        super().__init__(f"Invalid target configuration ({code}).")


TARGET_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["url"],
    "properties": {
        "url": {"type": "string", "minLength": 1},
        "method": {"enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "variables": {"type": "object"},
        "body": {},
        "response": {
            "type": "object", "additionalProperties": False,
            "anyOf": [{"required": ["text"]}, {"required": ["tool_calls"]}],
            "properties": {
                "text": {"type": "string"},
                "tool_calls": {
                    "type": "object", "additionalProperties": False,
                    "required": ["path", "name", "arguments"],
                    "properties": {key: {"type": "string"}
                                   for key in ("path", "name", "arguments")},
                },
            },
        },
    },
}
_FILE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["targets"],
    "properties": {
        "env_files": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "targets": {
            "type": "object", "propertyNames": {"pattern": "^[A-Za-z0-9_-]+$"},
            "additionalProperties": TARGET_SCHEMA,
        },
    },
}
_TOKEN = re.compile(r"\$\$\{[^{}]*\}|\$\{([^{}]*)\}")
_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PREVIEW = "target-request-value"


def _json(value):
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise TargetConfigurationError("invalid_json_value") from None


def _pointer_parts(pointer):
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?:[^01]|$)", pointer):
        raise TargetConfigurationError("invalid_response_pointer")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def pointer_value(data, pointer):
    """Read a JSON Pointer. Missing response fields are invalid replies, not config errors."""
    value = data
    for part in _pointer_parts(pointer):
        if isinstance(value, dict):
            value = value[part]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            value = value[int(part)]
        else:
            raise KeyError("missing_response_field")
    return value


def validate_definition(definition):
    if not Draft202012Validator(TARGET_SCHEMA).is_valid(definition):
        raise TargetConfigurationError("invalid_definition")
    _json(definition)
    response = definition.get("response", {})
    if "text" in response:
        _pointer_parts(response["text"])
    for pointer in response.get("tool_calls", {}).values():
        _pointer_parts(pointer)


def endpoint_origin(url, *, enforce_egress=True):
    """Return a canonical ``(scheme, host, port)`` for ``url``.

    When ``enforce_egress`` is true the host is also checked against the
    centralized egress policy (loopback/private/metadata deny-list unless the
    operator opted in). ``enforce_egress=False`` is only used for internal
    equality comparisons where the same URL has already been validated.
    """
    try:
        if not isinstance(url, str):
            raise ValueError()
        parsed = urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or any(c.isspace() or ord(c) < 32 for c in url)):
            raise ValueError()
        # Canonicalize through the same URL implementation used for delivery.
        normalized = httpx.URL(url)
        port = normalized.port if normalized.port is not None else (443 if parsed.scheme == "https" else 80)
    except (ValueError, TypeError, UnicodeError, httpx.InvalidURL):
        raise TargetConfigurationError("invalid_target_url") from None
    if enforce_egress:
        try:
            check_host(normalized.host)
        except EgressPolicyError as exc:
            raise TargetConfigurationError(exc.code) from None
    return normalized.scheme, normalized.host, port


def _env_file(path):
    try:
        if not path.is_file():
            raise TargetConfigurationError("env_file_unavailable")
        contents = path.read_text(encoding="utf-8")
        if any(binding.error for binding in parse_stream(io.StringIO(contents))):
            raise TargetConfigurationError("invalid_env_file")
        return {key: value for key, value in dotenv_values(stream=io.StringIO(contents), interpolate=False).items()
                if value is not None}
    except TargetConfigurationError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise TargetConfigurationError("env_file_unavailable") from None


def load_target_sources(process_environment=None):
    """Read only explicitly selected files; never surface the whole process env.

    Returns ``(profiles, template_values, system_values)``.

    * ``profiles`` -- saved target definitions from
      ``ANTICELLS_RED_MCP_TARGETS_FILE`` (dict, possibly empty).
    * ``template_values`` -- what target templates see as ``${env.*}``.
      Composed from, in order of precedence (later wins):

        1. values from the explicit ``ANTICELLS_RED_MCP_ENV_FILE``
        2. values from each ``env_files`` entry inside the targets file
        3. process environment variables whose names are listed in
           ``ANTICELLS_RED_MCP_TEMPLATE_ENV``
    * ``system_values`` -- the superset used by :func:`load_config` to find
      its own ``ANTICELLS_RED_MCP_*`` system knobs (database path, state
      dir, etc.). Contains the explicitly loaded .env/env_files values and
      the full process environment, with process values winning. These
      values are NEVER exposed as ``${env.*}`` to templates.
    """
    process = dict(os.environ if process_environment is None else process_environment)
    file_values = {}
    if process.get("ANTICELLS_RED_MCP_ENV_FILE"):
        file_values.update(_env_file(Path(process["ANTICELLS_RED_MCP_ENV_FILE"])))
    selected = {**file_values, **process}.get("ANTICELLS_RED_MCP_TARGETS_FILE")
    profiles = {}
    if selected:
        try:
            path = Path(selected).resolve()
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise TargetConfigurationError("targets_file_unavailable_or_invalid") from None
        if not Draft202012Validator(_FILE_SCHEMA).is_valid(document):
            raise TargetConfigurationError("invalid_targets_file")
        for filename in document.get("env_files", []):
            file_values.update(_env_file(path.parent / filename))
        profiles = document["targets"]
        for definition in profiles.values():
            validate_definition(definition)
    system_values = {**file_values, **process}
    allowed = {name.strip() for name in process.get("ANTICELLS_RED_MCP_TEMPLATE_ENV", "").split(",") if name.strip()}
    template_values = dict(file_values)
    template_values.update({name: value for name, value in process.items() if name in allowed})
    return profiles, template_values, system_values


def _lookup(reference, context, preview):
    namespace, separator, key = reference.partition(".")
    if not separator or not key or namespace not in {"env", "vars", "request"}:
        raise TargetConfigurationError("invalid_variable_reference")
    if namespace == "request" and key.split(".")[0] not in {"prompt", "messages", "tools", "body"}:
        raise TargetConfigurationError("unknown_request_variable")
    if namespace == "request" and preview:
        return _PREVIEW
    value = context[namespace]
    parts = [key] if namespace == "env" else key.split(".")
    try:
        for part in parts:
            if isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
                value = value[int(part)]
            else:
                value = value[part]
    except (KeyError, IndexError, TypeError):
        raise TargetConfigurationError("missing_variable") from None
    return copy.deepcopy(value)


def render_template(value, context, *, preview=False):
    """Substitute once in values, keeping JSON types for whole-value tokens."""
    if isinstance(value, dict):
        return {key: render_template(item, context, preview=preview) for key, item in value.items()}
    if isinstance(value, list):
        return [render_template(item, context, preview=preview) for item in value]
    if not isinstance(value, str):
        return value
    entire = _TOKEN.fullmatch(value)
    if entire and entire.group(1) is not None:
        return _lookup(entire.group(1), context, preview)

    def replace(match):
        if match.group(1) is None:
            return match.group(0)[1:]
        replacement = _lookup(match.group(1), context, preview)
        if isinstance(replacement, (dict, list)):
            raise TargetConfigurationError("embedded_container_variable")
        return replacement if isinstance(replacement, str) else _json(replacement)

    return _TOKEN.sub(replace, value)


def _uses_environment(value):
    if isinstance(value, dict):
        return any(_uses_environment(item) for item in value.values())
    if isinstance(value, list):
        return any(_uses_environment(item) for item in value)
    return isinstance(value, str) and any(
        match.group(1) is not None and match.group(1).startswith("env.")
        for match in _TOKEN.finditer(value)
    )


def _headers(headers):
    for name, value in headers.items():
        if (not _HEADER.fullmatch(name) or name.lower() in {"host", "content-length", "transfer-encoding"}
                or not isinstance(value, str)):
            raise TargetConfigurationError("invalid_headers")
        if (value != value.strip(" \t")
                or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value)):
            raise TargetConfigurationError("invalid_headers")
        try:
            value.encode("ascii")
        except UnicodeError:
            raise TargetConfigurationError("invalid_headers") from None
    return headers


@dataclass(frozen=True)
class ResolvedTarget:
    """JSON strings make nested state immutable and safe to deepcopy between modules."""

    label: str
    origin: tuple = field(repr=False)
    url: str = field(repr=False)
    _definition: str = field(repr=False)
    _variables: str = field(repr=False)
    _environment: str = field(repr=False)

    @property
    def response_mapping(self):
        return json.loads(self._definition).get("response")

    @property
    def supports_tools(self):
        mapping = self.response_mapping
        return mapping is None or "tool_calls" in mapping

    def request(self, body, prompt):
        definition = json.loads(self._definition)
        context = {
            "env": json.loads(self._environment), "vars": json.loads(self._variables),
            "request": {"prompt": prompt, "messages": body.get("messages", []),
                        "tools": body.get("tools", []), "body": body},
        }
        url = render_template(definition["url"], context)
        # Re-check origin AND the egress policy at the moment of dispatch so
        # that a DNS entry which flipped since resolve-time cannot slip past.
        if not isinstance(url, str) or endpoint_origin(url) != self.origin:
            raise TargetConfigurationError("target_origin_changed")
        headers = _headers(render_template(definition.get("headers", {}), context))
        request_body = render_template(definition["body"], context) if "body" in definition else copy.deepcopy(body)
        return definition.get("method", "POST"), url, headers, _json(request_body).encode("utf-8")


def resolve_target(config, selection, overrides=None):
    saved = isinstance(selection, str)
    if saved:
        if selection not in config.target_profiles:
            raise TargetConfigurationError("unknown_target_profile")
        definition = copy.deepcopy(config.target_profiles[selection])
    else:
        definition = copy.deepcopy(selection)
    validate_definition(definition)
    if overrides is not None and not isinstance(overrides, dict):
        raise TargetConfigurationError("invalid_target_variables")
    variables = {**definition.get("variables", {}), **(overrides or {})}
    environment = dict(config.target_environment)
    context = {"env": environment, "vars": variables, "request": {}}
    baseline = {**context, "vars": definition.get("variables", {})} if saved else context
    authorized_origin = endpoint_origin(render_template(definition["url"], baseline, preview=True))
    url = render_template(definition["url"], context, preview=True)
    if endpoint_origin(url, enforce_egress=False) != authorized_origin:
        raise TargetConfigurationError("target_origin_changed")
    templates = {key: definition[key] for key in ("url", "headers", "body") if key in definition}
    # Inline targets may NOT reference the process environment under any
    # circumstances. Saved profiles are operator-authored and may reference
    # declared environment values, bound to the configured origin.
    if not saved and _uses_environment(templates):
        raise TargetConfigurationError("inline_environment_reference_forbidden")
    if saved and _uses_environment(templates):
        if not config.target_api_url or endpoint_origin(config.target_api_url, enforce_egress=False) != authorized_origin:
            raise TargetConfigurationError("profile_environment_origin_not_authorized")
    # Check static variables before scheduling any work; request-dependent fields
    # are checked against the actual module request immediately before delivery.
    render_template(templates, context, preview=True)
    _headers(render_template(definition.get("headers", {}), context, preview=True))
    return ResolvedTarget(selection if saved else "inline", authorized_origin, url,
                          _json(definition), _json(variables), _json(environment))


def target_label(config, fallback=None):
    target = getattr(config, "target", None)
    return target.label if target else (fallback or config.target_api_url)
