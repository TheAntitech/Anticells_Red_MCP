"""Opt-in call context; auxiliary Python entry points remain unaffected."""
import copy
import inspect
from contextvars import ContextVar
from functools import wraps

active_run = ContextVar('report_run', default=None)
active_attempt = ContextVar('report_attempt', default=None)
_outbound_counter = ContextVar('outbound_counter', default=None)


def reset_outbound_counter():
    """Create a fresh per-call outbound-request counter.

    Returns the token that the caller must pass to :func:`clear_outbound_counter`
    once the tool invocation is complete.
    """
    return _outbound_counter.set([0])


def clear_outbound_counter(token):
    if token is not None:
        _outbound_counter.reset(token)


def bump_outbound_counter() -> int:
    """Increment the per-call counter and return the new value.

    When no counter has been set (e.g. ad-hoc test clients) the function
    returns ``1`` so that per-call caps still behave sanely during unit
    testing without needing the server wiring.
    """
    holder = _outbound_counter.get()
    if holder is None:
        return 1
    holder[0] += 1
    return holder[0]


def capture_request(config, prompt, headers=None, *, messages=None, tools=None):
    run = active_run.get()
    if run:
        run.sanitizer.configure(config)
        if headers:
            run.sanitizer.headers(headers)
    attempt = active_attempt.get()
    if attempt is not None:
        attempt['prompt'] = copy.deepcopy(prompt)
        attempt['messages'] = copy.deepcopy(messages or [])
        attempt['tools'] = copy.deepcopy(tools or [])


def capture_response(response, config):
    attempt = active_attempt.get()
    if attempt is None:
        return
    from ..modules.utils.chat_endpoint import normalize_response, response_text
    attempt['http_status'] = response.status_code
    try:
        data = normalize_response(response.json(), config)
        attempt['reply'] = response_text(data)
        if isinstance(data, dict):
            # The legacy tool engine also accepts a top-level text fallback
            # when the first message contains only a proposed function call.
            if not attempt['reply'] and not data.get('error'):
                for field in ('content', 'response'):
                    if isinstance(data.get(field), str) and data[field]:
                        attempt['reply'] = data[field]
                        break
            choices = data.get('choices') or []
            message = choices[0].get('message', {}) if choices else {}
            attempt['tool_calls'] = copy.deepcopy(message.get('tool_calls', []))
            if message.get('function_call'):
                attempt['function_call'] = copy.deepcopy(message['function_call'])
    except Exception:
        attempt['reply_status'] = 'malformed'


def recorded(module):
    """Capture leaf attempts, allowing a chain/engine wrapper to own nested calls."""
    def decorate(function):
        signature = inspect.signature(function)
        @wraps(function)
        async def wrapped(*args, **kwargs):
            run = active_run.get()
            if run is None or active_attempt.get() is not None:
                return await function(*args, **kwargs)
            bound = signature.bind(*args, **kwargs).arguments
            technique = bound.get('technique', {})
            evidence = {'prompt': copy.deepcopy(technique.get('payload')),
                        'technique_payload': copy.deepcopy(technique.get('payload'))} if isinstance(technique, dict) else {}
            token = active_attempt.set(evidence)
            try:
                result = await function(*args, **kwargs)
                if isinstance(result, dict):
                    # Do not change the public return shape to add persistence fields.
                    saved = copy.deepcopy(result)
                    saved.setdefault('module', module)
                    saved.setdefault('payload', evidence.get('prompt'))
                    saved.setdefault('technique', technique.get('name', function.__name__))
                    await run.record(saved, evidence)
                elif result is not None:
                    await run.record(result, evidence)
                return result
            except Exception as exc:
                from ..catalog.model import CatalogError
                from ..mcp_server.targets import TargetConfigurationError
                if not isinstance(exc, (CatalogError, TargetConfigurationError)):
                    await run.record(dict(module=module, technique=technique.get('name', function.__name__),
                                          payload=evidence.get('prompt'), success=False, confidence=0.0,
                                          metadata={'error': 'execution_failed'}), evidence)
                raise
            finally:
                active_attempt.reset(token)
        return wrapped
    return decorate


async def record_candidates(results):
    run = active_run.get()
    if run:
        for result in results:
            if isinstance(result, dict):
                saved = copy.deepcopy(result)
                saved.update(module='mutation', success=False, confidence=0.0)
                await run.record(saved)
            else:
                await run.record(result, refresh=True)
