"""Pure request builders used by execution and local compatibility discovery."""

from copy import deepcopy
import json


def fingerprint_request(payload):
    return {'messages': [{'role': 'user', 'content': payload}],
            'max_tokens': 1024, 'temperature': 0.0}


def jailbreak_request(payload, config):
    return {'messages': [{'role': 'user', 'content': payload}],
            'temperature': config.relentless.creativity_temperature}


def injection_request(payload, config, catalog):
    return {'messages': [
        {'role': 'system', 'content': payload},
        {'role': 'user', 'content': catalog.asset('injection.direct/send_injection_001')},
    ], 'temperature': config.relentless.creativity_temperature}


def build_tool_def(technique):
    args = technique.get('args', {})
    properties = {}
    for key, value in args.items():
        prop = dict(value) if isinstance(value, dict) else {}
        prop.pop('default', None)
        properties[key] = prop
    return {'type': 'function', 'function': {
        'name': technique.get('tool_name', ''),
        'description': technique.get('description', ''),
        'parameters': {'type': 'object', 'properties': properties, 'required': list(args)},
    }}


def tool_abuse_request(technique, config, catalog, available_tools=None):
    if available_tools is not None:
        supporting_tools = deepcopy(available_tools)
    else:
        vulnerable = build_tool_def(technique)
        supporting_tools = catalog.asset('tool_abuse.exploit/supporting_tools')
        name = vulnerable['function']['name']
        if name not in {t['function']['name'] for t in supporting_tools}:
            supporting_tools.append(vulnerable)
        else:
            supporting_tools = [t if t['function']['name'] != name else vulnerable
                                for t in supporting_tools]
    prompt = catalog.render(
        'tool_abuse.exploit/send_tool_abuse_002',
        value0=f"{technique.get('tool_name', '')}",
        value1=f"{technique.get('description', '')}",
        value2=f"{json.dumps(technique.get('payload', {}).get('arguments', {}), indent=2)}",
    )
    return {'messages': [
        {'role': 'system', 'content': catalog.asset('tool_abuse.exploit/send_tool_abuse_001')},
        {'role': 'user', 'content': prompt},
    ], 'tools': supporting_tools, 'tool_choice': 'auto',
        'temperature': getattr(getattr(config, 'relentless', None), 'creativity_temperature', None) or 0.8}, prompt
