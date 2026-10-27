"""Local function-schema checks shared by discovery and tool-call execution."""

from copy import deepcopy

from jsonschema import Draft202012Validator, SchemaError


def normalize_tools(tools):
    normalized, names = [], set()
    for supplied in tools:
        tool = deepcopy(supplied)
        if not isinstance(tool, dict):
            raise ValueError('available_tools must contain function schemas')
        if 'function' not in tool:
            tool = {'type': 'function', 'function': tool}
        function = tool.get('function')
        if tool.get('type') != 'function' or not isinstance(function, dict):
            raise ValueError('available_tools must contain function schemas')
        name = function.get('name')
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError('Tool names must be nonempty and unique')
        parameters = function.setdefault('parameters', {'type': 'object', 'properties': {}})
        if not isinstance(parameters, dict):
            raise ValueError('Tool parameters must be a JSON schema object')
        try:
            Draft202012Validator.check_schema(parameters)
        except SchemaError:
            raise ValueError('Invalid tool parameter schema') from None
        pending = [parameters]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                for keyword in ('$ref', '$dynamicRef'):
                    if keyword in value and (not isinstance(value[keyword], str)
                                             or not value[keyword].startswith('#')):
                        raise ValueError('Tool schemas must use inline or local references')
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        names.add(name)
        normalized.append(tool)
    return normalized


def tool_skip_reason(technique, config, available_tools):
    if config.target and not config.target.supports_tools:
        return 'target_has_no_tool_call_mapping'
    payload = technique.get('payload')
    if not isinstance(payload, dict) or not isinstance(payload.get('arguments', {}), dict):
        return 'invalid_structured_payload'
    if available_tools is None:
        return None
    function = next((t['function'] for t in available_tools
                     if t['function']['name'] == technique.get('tool_name')), None)
    if function is None:
        return 'tool_unavailable'
    validator = Draft202012Validator(function['parameters'])
    try:
        valid = validator.is_valid(payload.get('arguments', {}))
    except Exception:
        return 'invalid_tool_schema_reference'
    return None if valid else 'arguments_do_not_match_schema'
