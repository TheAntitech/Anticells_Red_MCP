import asyncio
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from anticells_red_mcp.catalog.model import CatalogError, CatalogSnapshot, import_content
from anticells_red_mcp.catalog.repository import CatalogRepository, publish
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.targets import ResolvedTarget
from anticells_red_mcp.modules.tool_abuse.exploit import ToolAbuseEngine, _build_tool_def


URL = 'https://example.invalid/chat'
CALLS = {'path': '/actions', 'name': '/name', 'arguments': '/arguments'}


def unpack(reply):
    return json.loads((reply.content if hasattr(reply, 'content') else reply)[0].text)


def query(**args):
    if 'target' not in args and 'target_url' not in args:
        args['target_url'] = URL
    return unpack(asyncio.run(server.call_tool('get_compatible_templates', args)))


def test_default_query_is_read_only_paginated_and_does_not_contact_target(monkeypatch):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda *a, **k: pytest.fail('HTTP client created'))
    monkeypatch.setattr(server, '_report_recorder', SimpleNamespace(
        begin=AsyncMock(side_effect=AssertionError('created a research run'))))
    result = query()
    assert result['checked_total'] == result['compatible_total'] == result['total'] == 194
    assert result['returned'] == result['next_offset'] == 50
    assert result['incompatible_total'] == 0
    assert result['target_contacted'] is False
    assert result['assessment'] == 'static_configuration'
    assert result['tool_schema_source'] == 'synthetic'
    assert all(t['compatibility']['compatible'] for t in result['templates'])
    assert 'run_id' not in result and not server._history and server._engine is None
    tools = asyncio.run(server.list_tools())
    tool = next(t for t in tools if t.name == 'get_compatible_templates')
    assert tool.annotations.readOnlyHint and not tool.annotations.openWorldHint


@pytest.mark.parametrize('mapping,expected', [
    ({'text': '/answer'}, 159), ({'tool_calls': CALLS}, 58),
    ({'text': '/answer', 'tool_calls': CALLS}, 194), (None, 194),
])
def test_custom_response_mappings_filter_before_pagination(mapping, expected):
    target = {'url': URL}
    if mapping is not None:
        target['response'] = mapping
    result = query(target=target, limit=7)
    assert result['total'] == result['compatible_total'] == expected
    assert result['checked_total'] == 194
    pages = [result]
    while pages[-1]['next_offset'] is not None:
        pages.append(query(target=target, offset=pages[-1]['next_offset'], limit=100,
                           catalog_revision=result['catalog_revision']))
    entries = [t for page in pages for t in page['templates']]
    assert len({t['id'] for t in entries}) == expected
    if mapping == {'text': '/answer'}:
        assert all(t['module'] != 'tool_abuse' for t in entries)
        excluded = query(target=target, module='tool_abuse', include_incompatible=True)
        assert excluded['compatible_total'] == 0 and excluded['total'] == 35
        assert {t['compatibility']['reason'] for t in excluded['templates']} == {'target_has_no_tool_call_mapping'}
    if mapping == {'tool_calls': CALLS}:
        assert {t['module'] for t in entries} == {'mutation', 'tool_abuse'}
        excluded = query(target=target, module='injection', include_incompatible=True)
        assert {t['compatibility']['reason'] for t in excluded['templates']} == {'target_has_no_text_mapping'}
    local = query(target=target, module='mutation')
    assert local['total'] == 23
    assert all(t['compatibility']['execution'] == 'local' for t in local['templates'])


@pytest.mark.parametrize('schema_kind', ['matching', 'mismatch', 'missing', 'bad_reference'])
def test_function_compatibility_agrees_with_execution_skips(monkeypatch, seed_snapshot, schema_kind):
    techniques = seed_snapshot.techniques('tool_abuse.exploit')
    supplied = _build_tool_def(techniques[0])
    if schema_kind == 'mismatch':
        supplied['function']['parameters'] = {'type': 'object', 'required': ['not_in_any_fixture']}
    elif schema_kind == 'missing':
        supplied['function']['name'] = 'not_in_any_fixture'
    elif schema_kind == 'bad_reference':
        supplied['function']['parameters'] = {'$ref': '#/$defs/missing'}
    original = copy.deepcopy(supplied)
    # Both wrapped and bare function definitions are accepted without mutation.
    entries = query(module='tool_abuse', available_tools=[supplied['function']],
                    include_content=True, include_incompatible=True)['templates']
    sent = []
    client_type = httpx.AsyncClient
    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={'choices': [{'message': {'content': ''}}]})
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: client_type(
        **{**kwargs, 'transport': httpx.MockTransport(handler)}))
    async def execute():
        engine = ToolAbuseEngine(server._config)
        try:
            return await engine.run_exploit([supplied], 'all', URL)
        finally:
            await engine.close()
    results = asyncio.run(execute())
    assert len(results) == len(entries) == 35
    for result, entry in zip(results, entries):
        check = entry['compatibility']
        assert check['compatible'] == (result.metadata.get('status') != 'skipped')
        if not check['compatible']:
            assert check['reason'] == result.metadata['reason']
    assert len(sent) == sum(t['compatibility']['compatible'] for t in entries)
    assert supplied == original
    if schema_kind == 'matching':
        assert sent


def test_empty_tools_keep_synthetic_definition_behavior():
    assert query(module='tool_abuse', available_tools=[]) == query(module='tool_abuse')


@pytest.mark.parametrize('tools', [
    [{'name': 'same'}, {'name': 'same'}], [{'name': ''}],
    [{'name': 'test', 'parameters': {'type': 'invalid'}}],
    [{'name': 'test', 'parameters': {'$ref': 'https://secret.invalid/schema'}}],
    [{'name': 'test', 'parameters': {'$dynamicRef': 'file:///secret'}}],
    [{'name': 'test', 'parameters': []}], [{'type': 'other', 'function': {'name': 'test'}}],
])
def test_invalid_tool_schemas_are_rejected_without_values(tools):
    result = query(available_tools=tools)
    assert result['error'] == 'invalid_request'
    assert 'secret' not in json.dumps(result)


def test_request_rendering_checks_module_specific_fields_and_model():
    target = {'url': URL, 'body': {'limit': '${request.body.max_tokens}'}}
    result = query(target=target)
    assert result['total'] == 30 + 23  # Fingerprint has max_tokens; mutation is local.
    blocked = query(target=target, module='injection', include_incompatible=True)
    assert blocked['incompatible_total'] == 53
    assert {t['compatibility']['code'] for t in blocked['templates']} == {'missing_variable'}
    target['body'] = {'model': '${request.body.model}'}
    assert query(target=target)['total'] == 23
    server._config.target_model = 'fixture-model'
    assert query(target=target)['total'] == 194
    target['body'] = {'tools': 'embedded ${request.tools}'}
    excluded = query(target=target, module='tool_abuse', include_incompatible=True)
    assert {t['compatibility']['code'] for t in excluded['templates']} == {'embedded_container_variable'}


def test_rendering_uses_actual_injection_payload_and_structured_tools_without_leaking(monkeypatch):
    # 1.1.0: ${env.*} requires a saved profile.
    server._config.target_api_url = URL
    server._config.target_environment = {'API_KEY': 'private-fixture-credential'}
    definition = {'url': URL + '?secret=${env.API_KEY}',
                  'headers': {'Authorization': 'Bearer ${env.API_KEY}'},
                  'body': {'prompt': '${request.prompt}', 'messages': '${request.messages}',
                           'tools': '${request.tools}', 'key': '${env.API_KEY}'}}
    server._config.target_profiles = {'saved': definition}
    seen = []
    original = ResolvedTarget.request
    def capture(self, body, prompt):
        result = original(self, body, prompt)
        seen.append(json.loads(result[3]))
        return result
    monkeypatch.setattr(ResolvedTarget, 'request', capture)
    result = query(target='saved', module='injection', include_content=True, limit=100)
    assert len(seen) == result['total'] == 53
    for rendered, entry in zip(seen, result['templates']):
        payload = import_content(entry)['payload']
        # JSON decoding may combine the exceptional surrogate pair on the wire.
        assert rendered['prompt'] == json.loads(json.dumps(payload))
        assert rendered['prompt'] == rendered['messages'][0]['content']
        assert rendered['prompt'] != rendered['messages'][-1]['content']
        assert rendered['tools'] == []
    assert 'private-fixture-credential' not in json.dumps(result)
    assert '?secret=' not in json.dumps(result)
    seen.clear()
    result = query(target='saved', module='tool_abuse', limit=100)
    assert len(seen) == result['total'] == 35
    assert all(isinstance(body['tools'], list) and body['tools'] for body in seen)


def test_filters_disabled_memberships_unicode_and_revision(seed_snapshot, monkeypatch):
    exceptional = next(r for r in seed_snapshot.records() if 'encoded_content' in r)
    one = query(template_id=exceptional['id'], include_content=True)
    assert import_content(one['templates'][0]) == import_content(exceptional)
    assert query(module='injection', search='absent fixture query')['total'] == 0
    assert query(offset=10000)['templates'] == []
    assert query(limit=2.0, offset=1.0)['returned'] == 2
    member = next(r for r in seed_snapshot.records() if r['namespace'] == 'jailbreaks.engine'
                  and r['kind'] == 'technique' and r.get('memberships') != [r['content']['category']])
    assert query(template_id=member['id'], category=member['memberships'][0])['total'] == 1
    records = seed_snapshot.records()
    next(r for r in records if r['id'] == exceptional['id'])['enabled'] = False
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(
        return_value=CatalogSnapshot.build(2, records)))
    assert query(template_id=exceptional['id'])['total'] == 0
    assert query(template_id=exceptional['id'], include_disabled=True)['total'] == 0
    disabled = query(template_id=exceptional['id'], include_disabled=True, include_incompatible=True)
    assert disabled['templates'][0]['compatibility']['reason'] == 'template_disabled'
    assert query(catalog_revision=1) == {'error': 'catalog_error', 'code': 'catalog_revision_changed'}


@pytest.mark.parametrize('args', [
    {}, {'target_url': URL, 'target': 'saved'}, {'target_url': URL, 'target_variables': {}},
    {'target': {'url': URL, 'env_files': ['secret.env']}},
    {'target_url': URL, 'available_tools': [1]}, {'target_url': URL, 'limit': 101},
    {'target_url': URL, 'include_incompatible': 'yes'}, {'target_url': URL, 'include_auxiliary': True},
])
def test_schema_rejects_invalid_selectors_before_loading_catalog(args):
    reply = asyncio.run(server.call_tool('get_compatible_templates', args))
    assert reply.isError and unpack(reply)['error'] == 'invalid_arguments'
    server._catalog_repository.snapshot.assert_not_awaited()


def test_configuration_and_catalog_errors_are_safe(monkeypatch):
    # 1.1.0: tighter error codes (F7) and inline-env rejection (F2).
    assert query(target='missing')['code'] == 'unknown_target_profile'
    assert query(target={'url': URL, 'body': '${vars.missing}'})['code'] == 'missing_variable'
    server._config.target_api_url = URL
    server._config.target_api_key = 'private-fixture-credential'
    server._config.target_environment = {'API_KEY': 'private-fixture-credential'}
    other = query(target_url='https://elsewhere.invalid')
    assert other['error'] == 'target_configuration_error' and other['code'] == 'authenticated_target_origin_mismatch'
    inline_env = query(target={'url': 'https://elsewhere.invalid', 'body': '${env.API_KEY}'})
    assert inline_env['code'] == 'inline_environment_reference_forbidden'
    result = query(target_url='https://example.invalid:private-fixture-credential/chat')
    assert result['code'] == 'invalid_target_url' and 'private-fixture-credential' not in json.dumps(result)
    server._config.target_profiles = {'saved': {'url': '${vars.endpoint}',
        'variables': {'endpoint': URL}, 'headers': {'Authorization': '${env.API_KEY}'}}}
    result = query(target='saved', target_variables={'endpoint': 'https://elsewhere.invalid'})
    assert result['code'] == 'target_origin_changed'
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(side_effect=CatalogError('storage_unavailable')))
    assert query() == {'error': 'catalog_error', 'code': 'storage_unavailable'}


def test_concurrent_saved_profiles_and_inline_targets_remain_isolated():
    server._config.target_profiles = {'saved': {'url': URL, 'body': '${vars.body}',
        'variables': {'body': 'original'}, 'response': {'text': '/answer'}}}
    before = copy.deepcopy(server._config.target_profiles)
    async def check():
        replies = await asyncio.gather(
            server.call_tool('get_compatible_templates', {'target': 'saved', 'target_variables': {'body': 'override'}}),
            server.call_tool('get_compatible_templates', {'target': {'url': URL, 'response': {'tool_calls': CALLS}}}),
        )
        assert [unpack(r)['compatible_total'] for r in replies] == [159, 58]
    asyncio.run(check())
    assert server._config.target is None and server._config.target_profiles == before


def test_newly_published_template_is_compatible_on_next_call(catalog_path, monkeypatch):
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, '_catalog_repository', repository)
    async def check():
        try:
            initial = await repository.snapshot()
            record = next(r for r in initial.records() if r['namespace'] == 'injection.direct'
                          and r['kind'] == 'technique' and 'content' in r)
            record.update(id='custom/compatibility-fixture', position=1000)
            record.pop('revision', None)
            record['content'].update(name='compatibility_fixture', payload='Harmless fixture prompt')
            args = {'target': {'url': URL, 'body': '${request.prompt}'}, 'template_id': record['id']}
            assert unpack(await server.call_tool('get_compatible_templates', args))['total'] == 0
            await asyncio.to_thread(publish, catalog_path, {'format_version': 1, 'records': [record]})
            result = unpack(await server.call_tool('get_compatible_templates', args))
            assert result['total'] == 1 and result['templates'][0]['compatibility']['compatible']
            assert result['catalog_revision'] > initial.revision
            assert not any(r['id'] == record['id'] for r in initial.records())
        finally:
            await repository.close()
    asyncio.run(check())
