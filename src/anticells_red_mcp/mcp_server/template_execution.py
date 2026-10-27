"""Exact catalog selection and one execution through an existing public engine."""

import copy
import uuid

from ..catalog.browse import PUBLIC_CATALOGS
from ..catalog.model import CatalogError, import_content
from ..reports.runtime import active_run
from .engine import AttackResult
from .targets import TargetConfigurationError


def execution_schema():
    return {
        'type': 'object', 'additionalProperties': False, 'required': ['template_id'],
        'properties': {
            'template_id': {
                'type': 'string', 'minLength': 1, 'maxLength': 240,
                'description': 'Exact stable ID returned by template discovery; names are not selectors.',
            },
            'catalog_revision': {
                'type': 'integer', 'minimum': 0,
                'description': 'Optional discovery revision; reject catalog changes before executing.',
            },
            'target_url': {
                'type': 'string',
                'description': 'Legacy HTTP chat endpoint. Target templates require target_url or target; local mutation uses neither.',
            },
            'available_tools': {
                'type': 'array', 'items': {'type': 'object'},
                'description': 'Only for tool_abuse templates. Omitted or empty uses existing synthetic definitions.',
            },
        },
        # Target definitions/variables are added by the same server code as other
        # target-facing tools. The selected record determines whether one is needed.
        'not': {'required': ['target_url', 'target']},
    }


def select_template(snapshot, args):
    if 'catalog_revision' in args and args['catalog_revision'] != snapshot.revision:
        raise CatalogError('catalog_revision_changed')
    record = next((r for r in snapshot.records() if r['id'] == args['template_id']), None)
    if record is None:
        raise CatalogError('template_not_found')
    if record['kind'] != 'technique' or record['namespace'] not in PUBLIC_CATALOGS:
        raise CatalogError('template_not_executable')
    if not record.get('enabled', True):
        raise CatalogError('template_disabled')
    definition = import_content(record)
    family = record['namespace'].split('.', 1)[0]
    if family != 'tool_abuse' and 'available_tools' in args:
        raise ValueError('available_tools is only supported for tool_abuse templates')
    has_target = 'target' in args or 'target_url' in args
    if family == 'mutation' and has_target:
        raise ValueError('Local mutation templates do not accept a target')
    if family != 'mutation' and not has_target:
        raise ValueError('This template requires exactly one of target or target_url')
    return record, definition, family, record.get('memberships', [definition['category']])


async def execute_selected(match, config, tools, compatibility):
    record, definition, family, _ = match
    if compatibility['reason'] == 'target_request_not_renderable':
        # Bad substitutions are configuration errors, not failed target attempts.
        raise TargetConfigurationError(compatibility['code'])
    attack_id = str(uuid.uuid4())
    if not compatibility['compatible']:
        result = AttackResult(
            attack_id=attack_id, module=family, technique=definition['name'],
            payload=copy.deepcopy(definition['payload']), success=False, confidence=0.0,
            metadata={'status': 'skipped', 'reason': compatibility['reason'],
                      'category': definition['category'], 'template_id': record['id']},
        )
        run = active_run.get()
        if run:
            await run.record(result, {'technique_payload': copy.deepcopy(definition['payload'])})
        return result

    from ..modules.fingerprint.scanner import FingerprintScanner
    from ..modules.jailbreaks.engine import JailbreakEngine
    from ..modules.injection.direct import InjectionEngine
    from ..modules.tool_abuse.exploit import ToolAbuseEngine
    from ..modules.mutation.creative_engine import CreativeMutationEngine

    engine_type = {
        'fingerprint': FingerprintScanner, 'jailbreaks': JailbreakEngine,
        'injection': InjectionEngine, 'tool_abuse': ToolAbuseEngine,
        'mutation': CreativeMutationEngine,
    }[family]
    engine = engine_type(config)
    try:
        if family == 'tool_abuse':
            engine._available_tools = tools
        # Leaf execution avoids name/category selectors, sampling, evolution,
        # chaining, and loops. Existing decorators capture complete evidence once.
        return await engine.execute(definition, attack_id)
    finally:
        await engine.close()
