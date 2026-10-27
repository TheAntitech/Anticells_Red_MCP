"""The report tool's additional actions and MCP resource adapters."""
import asyncio
from .model import ReportError


def report_schema():
    properties = {
        'action': {'type': 'string', 'enum': ['view', 'list', 'export', 'read'], 'default': 'view'},
        'format': {'type': 'string', 'enum': ['summary', 'json', 'detailed']},
        'run_id': {'type': 'string', 'format': 'uuid'},
        'session_id': {'type': 'string', 'format': 'uuid'},
        'export_format': {'type': 'string', 'enum': ['json', 'markdown', 'html']},
        'export_id': {'type': 'string', 'format': 'uuid'},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
        'offset': {'type': 'integer', 'minimum': 0},
        'length': {'type': 'integer', 'minimum': 1, 'maximum': 65536},
    }
    allowed = {
        'view': {'action', 'format', 'run_id', 'session_id'},
        'list': {'action', 'session_id', 'limit', 'offset'},
        'export': {'action', 'run_id', 'session_id', 'export_format'},
        'read': {'action', 'export_id', 'offset', 'length'},
    }
    choices = []
    for action, keys in allowed.items():
        choice = {'properties': {'action': {'const': action}},
                  'not': {'anyOf': [{'required': [k]} for k in sorted(properties.keys() - keys)]}}
        if action != 'view':
            choice['required'] = ['action'] + (['export_id'] if action == 'read' else [])
        choices.append(choice)
    return {'type': 'object', 'properties': properties, 'additionalProperties': False,
            'oneOf': choices, 'not': {'required': ['run_id', 'session_id']}}


def selected_view(doc, mode):
    result = dict(doc)
    result['format'] = mode
    if mode == 'summary':
        result.pop('results')
    elif mode == 'detailed':
        result['results'] = doc['results'][:100]
    else:
        result['results'] = doc['results'][:10]
    result['visible_records'] = len(result.get('results', []))
    result['evidence_truncated'] = result['visible_records'] < doc['statistics']['total_records']
    return result


async def handle(recorder, args):
    if recorder is None:
        raise ReportError('report_store_not_started')
    action = args.get('action', 'view')
    repo = recorder.repository
    if action == 'view':
        doc = await recorder.snapshot(args.get('run_id'), args.get('session_id'))
        return selected_view(doc, args.get('format', 'summary'))
    if action == 'list':
        await recorder.flush()
        # Default to the current MCP session so that multiple MCP clients
        # sharing the same report directory on the same user account cannot
        # enumerate each other's saved runs. Cross-session reads still work
        # with an explicit ``session_id``.
        selected_session = args.get('session_id') or recorder.session['id']
        result = await asyncio.to_thread(repo.list_runs, selected_session, args.get('limit', 50), args.get('offset', 0))
        result['persistence'] = recorder.persistence()
        result['scope'] = 'current_session' if not args.get('session_id') else 'explicit_session'
        return result
    if action == 'export':
        return await recorder.export(args.get('export_format', 'json'), args.get('run_id'), args.get('session_id'))
    if action == 'read':
        return await asyncio.to_thread(repo.read_export, args['export_id'], args.get('offset', 0), args.get('length', 65536))
    raise ReportError('invalid_action')
