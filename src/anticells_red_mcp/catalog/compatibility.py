"""Assess public templates against a configured target without executing them."""

from .browse import listing_schema, matching_templates, template_summary, template_page
from ..mcp_server.targets import TargetConfigurationError
from ..modules.utils.chat_endpoint import generated_request
from ..modules.utils.requests import (
    fingerprint_request, jailbreak_request, injection_request, tool_abuse_request,
)
from ..modules.utils.tool_schemas import normalize_tools, tool_skip_reason


def compatibility_schema():
    schema = listing_schema()
    # Auxiliary Python engines do not all use the configurable target transport.
    schema['properties'].pop('include_auxiliary')
    schema['properties'].update({
        'target_url': {'type': 'string', 'description': 'Legacy HTTP chat endpoint to check locally.'},
        'available_tools': {
            'type': 'array', 'items': {'type': 'object'},
            'description': 'Function schemas, as in tool_abuse_exploit. Omitted or empty uses synthetic definitions.',
        },
        'include_incompatible': {
            'type': 'boolean', 'default': False,
            'description': 'Also return excluded templates with reasons. Disabled records additionally need include_disabled.',
        },
    })
    # The server adds the same target/profile/variables selector as execution.
    schema['required'] = ['target_url']
    return schema


def assess_template(match, config, snapshot, tools):
    record, definition, family, _ = match
    execution = 'local' if family == 'mutation' else 'target'
    result = {'compatible': False, 'execution': execution, 'reason': None}
    if not record.get('enabled', True):
        return {**result, 'reason': 'template_disabled'}
    if family == 'mutation':
        return {**result, 'compatible': True, 'reason': 'local_mutation_no_target_required'}
    if family == 'tool_abuse':
        reason = tool_skip_reason(definition, config, tools)
        if reason:
            return {**result, 'reason': reason}
    elif config.target and config.target.response_mapping is not None:
        if 'text' not in config.target.response_mapping:
            return {**result, 'reason': 'target_has_no_text_mapping'}

    payload = definition.get('payload', '')
    if family == 'fingerprint':
        body, prompt = fingerprint_request(payload), payload
    elif family == 'jailbreaks':
        body, prompt = jailbreak_request(payload, config), payload
    elif family == 'injection':
        body, prompt = injection_request(payload, config, snapshot), payload
    else:
        body, prompt = tool_abuse_request(definition, config, snapshot, tools)
    if config.target:
        try:
            # Render exactly the execution request, then discard it. Never return
            # resolved URLs, headers, environment values, or rendered bodies.
            config.target.request(generated_request(body, config), prompt)
        except TargetConfigurationError as exc:
            return {**result, 'reason': 'target_request_not_renderable', 'code': exc.code}
    return {**result, 'compatible': True, 'reason': 'configuration_checks_passed'}


def compatible_templates(snapshot, args, config):
    tools = normalize_tools(args['available_tools']) if args.get('available_tools') else None
    matches = matching_templates(snapshot, args)
    assessed = [(match, assess_template(match, config, snapshot, tools)) for match in matches]
    compatible_count = sum(check['compatible'] for _, check in assessed)
    templates = []
    for match, check in assessed:
        if not check['compatible'] and not args.get('include_incompatible', False):
            continue
        item = template_summary(match, args.get('include_content', False))
        item['compatibility'] = check
        templates.append(item)
    result = template_page(snapshot, args, templates, tool='get_compatible_templates')
    result.update(
        assessment='static_configuration', target_contacted=False,
        checked_total=len(assessed), compatible_total=compatible_count,
        incompatible_total=len(assessed) - compatible_count,
        tool_schema_source='provided' if tools is not None else 'synthetic',
        compatibility_notice='Compatibility checks request rendering, configured response mappings, and tool schemas. '
                             'It does not verify endpoint availability, model capabilities, actual replies, or attack success. '
                             'Custom bodies are checked for rendering, not whether they forward the prompt or tools. '
                             'Local mutation templates do not contact the target.',
    )
    return result
