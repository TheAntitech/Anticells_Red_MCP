"""Shared JSON transport and normalization for legacy and configured targets."""

import copy
import json
from typing import Any

import httpx
from ...mcp_server.targets import TargetConfigurationError, pointer_value
from .safe_http import make_http_client
from ...catalog.model import CatalogError
from ...reports.runtime import capture_request, capture_response


def make_chat_client(config, *, timeout=60.0, user_agent="anticells_red_mcp"):
    headers = {"Content-Type": "application/json", "User-Agent": user_agent}
    key = getattr(config, "target_api_key", None)
    if key and not config.target:
        headers["Authorization"] = f"Bearer {key}"
    return make_http_client(timeout=timeout, headers=headers)


def generated_request(body, config):
    """Return the model-enriched body before applying custom target rendering."""
    request = copy.deepcopy(body)
    model = getattr(config, "target_model", None)
    if model:
        request["model"] = model
    return request


async def post_chat(client, url, body, config, *, prompt=None):
    # Every real HTTP client enforces request caps through its request hook,
    # including auxiliary modules which do not use this JSON helper.
    request = generated_request(body, config)
    if config.target:
        if prompt is None:
            raise TargetConfigurationError("missing_request_prompt")
        method, url, headers, encoded = config.target.request(request, prompt)
        outgoing_headers = httpx.Headers({"Content-Type": "application/json"})
        outgoing_headers.update(headers)
        capture_request(config, prompt, headers, messages=request.get('messages'), tools=request.get('tools'))
        response = await client.request(method, url, content=encoded, headers=outgoing_headers,
                                        follow_redirects=False)
    else:
        # Escaping preserves existing Unicode templates on the UTF-8 wire.
        encoded = json.dumps(request, ensure_ascii=True).encode("utf-8")
        capture_request(config, prompt, messages=request.get('messages'), tools=request.get('tools'))
        response = await client.post(url, content=encoded, headers={"Content-Type": "application/json"},
                                     follow_redirects=False)
    capture_response(response, config)
    return response


def normalize_response(data: Any, config) -> Any:
    """Map custom replies without discarding the caller's original HTTP response.

    Missing fields and malformed proposals invalidate the reply, never producing
    a success from a partial mapping. No returned function is executed here.
    """
    mapping = config.target.response_mapping if config.target else None
    if mapping is None:
        return data
    try:
        if isinstance(data, dict) and data.get("error"):
            return {"error": True}
        content = pointer_value(data, mapping["text"]) if "text" in mapping else ""
        if not isinstance(content, str):
            raise ValueError()
        message = {"content": content}
        if "tool_calls" in mapping:
            spec = mapping["tool_calls"]
            actions = pointer_value(data, spec["path"])
            if not isinstance(actions, list):
                raise ValueError()
            proposals = []
            for action in actions:
                name = pointer_value(action, spec["name"])
                arguments = pointer_value(action, spec["arguments"])
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                if not isinstance(name, str) or not name.strip() or not isinstance(arguments, dict):
                    raise ValueError()
                proposals.append({"type": "function", "function": {
                    "name": name, "arguments": json.dumps(arguments, ensure_ascii=True, allow_nan=False)}})
            message["tool_calls"] = proposals
        # Keep model/usage/id and other provider metadata available to fingerprinting.
        normalized = dict(data) if isinstance(data, dict) else {}
        original_choices = normalized.get("choices")
        choice = (dict(original_choices[0]) if isinstance(original_choices, list) and original_choices
                  and isinstance(original_choices[0], dict) else {})
        choice["message"] = message
        normalized["choices"] = [choice]
        return normalized
    except (TargetConfigurationError, CatalogError):
        raise
    except (KeyError, IndexError, TypeError, ValueError, OverflowError):
        return {"error": True}


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(block["text"] for block in content
                       if isinstance(block, dict) and isinstance(block.get("text"), str))
    return ""


def response_text(data: Any) -> str:
    """Extract supported text fields; unknown objects are not assistant replies."""
    if not isinstance(data, dict) or data.get("error"):
        return ""
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        choice = choices[0]
        if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
            return _text(choice["message"].get("content"))
        return ""
    for name in ("content", "response"):
        if name in data:
            return _text(data[name])
    return ""


def request_error(exc: Exception) -> str:
    """Describe transport failures without exposing bodies, URLs or credentials."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"[HTTP ERROR: {exc.response.status_code}]"
    if isinstance(exc, httpx.TimeoutException):
        return "[TIMEOUT]"
    if isinstance(exc, httpx.ConnectError):
        return "[CONNECTION FAILED]"
    return "[INVALID OR FAILED RESPONSE]"
