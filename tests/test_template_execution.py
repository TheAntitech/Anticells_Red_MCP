import asyncio
import copy
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from jsonschema import Draft202012Validator

from anticells_red_mcp.catalog.browse import PUBLIC_CATALOGS
from anticells_red_mcp.catalog.model import CatalogSnapshot, import_content
from anticells_red_mcp.catalog.repository import CatalogRepository, publish
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.modules.tool_abuse.exploit import _build_tool_def
from anticells_red_mcp.reports.model import ReportError
from anticells_red_mcp.reports.recorder import Recorder
from anticells_red_mcp.reports.repository import ReportRepository


URL = 'https://example.invalid/chat'


def unpack(reply):
    return json.loads((reply.content if hasattr(reply, 'content') else reply)[0].text)


def select(snapshot, namespace):
    return next(r for r in snapshot.records() if r['namespace'] == namespace and r['kind'] == 'technique')


def execute(template_id, **kwargs):
    return unpack(asyncio.run(server.call_tool('execute_attack_template', {'template_id': template_id, **kwargs})))


def transport(monkeypatch, handler):
    clients, requests = [], []
    original = httpx.AsyncClient
    async def receive(request):
        requests.append(request)
        response = handler(request)
        return await response if asyncio.iscoroutine(response) else response
    def factory(**kwargs):
        kwargs['transport'] = httpx.MockTransport(receive)
        client = original(**kwargs)
        clients.append(client)
        return client
    monkeypatch.setattr(httpx, 'AsyncClient', factory)
    return requests, clients


@pytest.mark.parametrize('namespace', list(PUBLIC_CATALOGS))
def test_executes_one_entry_and_records_full_evidence_once(namespace, monkeypatch, tmp_path, seed_snapshot):
    selected = select(seed_snapshot, namespace)
    definition = import_content(selected)
    reply_text = 'Fixture reply ' * 1000
    proposals = []
    if namespace == 'tool_abuse.exploit':
        proposals = [{'type': 'function', 'function': {'name': definition['tool_name'],
                      'arguments': json.dumps(definition['payload']['arguments'])}}]
    requests, clients = transport(monkeypatch, lambda _: httpx.Response(200, json={
        'choices': [{'message': {'content': reply_text, 'tool_calls': proposals}}]}))
    local = namespace == 'mutation.creative_engine'
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        args = {'template_id': selected['id'], 'catalog_revision': 1}
        if not local:
            args['target_url'] = URL
        try:
            result = unpack(await server.call_tool('execute_attack_template', args))
            assert result['tool'] == 'execute_attack_template', result
            assert result['template']['id'] == selected['id']
            assert result['catalog_revision'] == 1 and result['status'] == 'completed'
            assert result['total_attempts'] == int(not local)
            assert len(result['results']) == 1
            assert result['results'][0]['technique'] == definition['name']
            assert result['persistence']['status'] == 'saved'
            assert len(requests) == int(not local) and all(c.is_closed for c in clients)
            if not local:
                body = json.loads(requests[0].content)
                assert 'messages' in body
                if namespace == 'injection.direct':
                    assert body['messages'][0]['content'] == definition['payload']
                elif namespace != 'tool_abuse.exploit':
                    assert body['messages'] == [{'role': 'user', 'content': definition['payload']}]
            else:
                assert result['target'] == 'local'
                assert not result['results'][0]['success']
                assert result['results'][0]['metadata']['original_payload'] == definition['payload']
            saved = await recorder.snapshot(run_id=result['run_id'])
            assert saved['statistics'] == result['statistics']
            assert len(saved['results']) == 1
            assert saved['runs'][0]['template']['id'] == selected['id']
            assert saved['runs'][0]['settings']['template_id'] == selected['id']
            assert saved['results'][0]['evidence']['technique_payload'] == definition['payload']
            if not local:
                assert saved['results'][0]['evidence']['reply'] == reply_text
                assert saved['results'][0]['evidence']['tool_calls'] == proposals
            current = unpack(await server.call_tool('get_attack_report', {}))
            assert current['statistics']['total_attacks'] == int(not local)
            assert current['statistics']['local_candidates'] == int(local)
            for fmt in ('json', 'markdown', 'html'):
                exported = unpack(await server.call_tool('get_attack_report', {
                    'action': 'export', 'run_id': result['run_id'], 'export_format': fmt}))
                assert exported['byte_count'] > 0
            return result['run_id']
        finally:
            await recorder.close()
    run_id = asyncio.run(check())
    restarted = ReportRepository(tmp_path)
    restarted.initialize()
    saved = restarted.snapshot(run_id=run_id)
    assert len(saved['results']) == 1 and saved['runs'][0]['status'] == 'completed'


def test_id_not_name_selects_exact_duplicate_entry(monkeypatch, seed_snapshot):
    base = select(seed_snapshot, 'injection.direct')
    originals = seed_snapshot.records()
    clones = []
    for i in (1, 2):
        record = copy.deepcopy(base)
        record.update(id=f'custom/duplicate-{i}', position=1000 + i)
        record['content'].update(name='same fixture name', payload=f'Exact fixture {i}')
        clones.append(record)
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(
        return_value=CatalogSnapshot.build(2, originals + clones)))
    requests, clients = transport(monkeypatch, lambda _: httpx.Response(200, json={'content': 'fixture'}))
    result = execute(clones[1]['id'], target_url=URL)
    assert result['total_attempts'] == 1 and len(requests) == 1
    assert json.loads(requests[0].content)['messages'][0]['content'] == 'Exact fixture 2'
    assert all(c.is_closed for c in clients)
    assert execute('same fixture name', target_url=URL)['code'] == 'template_not_found'
    assert len(requests) == 1


def test_unsupported_disabled_unknown_and_stale_ids_never_create_clients(monkeypatch, seed_snapshot):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('unexpected HTTP'))
    records = seed_snapshot.records()
    disabled = next(r for r in records if r['namespace'] == 'injection.direct' and r['kind'] == 'technique')
    disabled['enabled'] = False
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(return_value=CatalogSnapshot.build(2, records)))
    auxiliary = next(r for r in records if r['kind'] == 'technique' and r['namespace'] not in PUBLIC_CATALOGS)
    asset = next(r for r in records if r['kind'] != 'technique')
    for identifier, code in [('missing', 'template_not_found'), (disabled['id'], 'template_disabled'),
                             (auxiliary['id'], 'template_not_executable'), (asset['id'], 'template_not_executable')]:
        result = execute(identifier, target_url=URL)
        assert result == {'error': 'catalog_error', 'code': code}
    assert execute(disabled['id'], target_url=URL, catalog_revision=1)['code'] == 'catalog_revision_changed'
    assert not server._history


@pytest.mark.parametrize('args', [
    {}, {'template_id': ''}, {'template_id': 1}, {'template_id': 'x', 'target': 'saved', 'target_url': URL},
    {'template_id': 'x', 'target_url': URL, 'target_variables': {}},
    {'template_id': 'x', 'target': {'url': URL, 'env_files': ['private.env']}},
    {'template_id': 'x', 'catalog_revision': -1}, {'template_id': 'x', 'available_tools': [1]},
    {'template_id': 'x', 'intensity': 5}, {'template_id': 'x', 'generations': 10},
    {'template_id': 'x', 'payload_override': 'custom'},
])
def test_schema_rejects_invalid_inputs_before_catalog_access(args):
    reply = asyncio.run(server.call_tool('execute_attack_template', args))
    assert reply.isError and unpack(reply)['error'] == 'invalid_arguments'
    server._catalog_repository.snapshot.assert_not_awaited()


def test_template_specific_argument_validation(monkeypatch, seed_snapshot):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('unexpected HTTP'))
    remote = select(seed_snapshot, 'injection.direct')['id']
    local = select(seed_snapshot, 'mutation.creative_engine')['id']
    assert execute(remote)['error'] == 'invalid_request'
    assert execute(remote, target_url=URL, available_tools=[])['error'] == 'invalid_request'
    assert execute(local, target_url=URL)['error'] == 'invalid_request'
    assert execute(local, target={'url': URL})['error'] == 'invalid_request'
    schema = next(t.inputSchema for t in asyncio.run(server.list_tools()) if t.name == 'execute_attack_template')
    validator = Draft202012Validator(schema)
    assert validator.is_valid({'template_id': local})
    assert validator.is_valid({'template_id': remote, 'target': 'saved', 'target_variables': {}})


@pytest.mark.parametrize('kind', ['no_tools_mapping', 'no_text_mapping', 'missing_tool', 'invalid_arguments'])
def test_incompatible_templates_save_one_skip_without_http(kind, monkeypatch, tmp_path, seed_snapshot):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('unexpected HTTP'))
    namespace = 'injection.direct' if kind == 'no_text_mapping' else 'tool_abuse.exploit'
    record = select(seed_snapshot, namespace)
    args = {'template_id': record['id'], 'target': {'url': URL}}
    if kind == 'no_text_mapping':
        args['target']['response'] = {'tool_calls': {'path': '/actions', 'name': '/name', 'arguments': '/arguments'}}
        reason = 'target_has_no_text_mapping'
    elif kind == 'no_tools_mapping':
        args['target']['response'] = {'text': '/answer'}
        reason = 'target_has_no_tool_call_mapping'
    elif kind == 'missing_tool':
        args['available_tools'] = [{'name': 'absent_fixture'}]
        reason = 'tool_unavailable'
    else:
        tool = _build_tool_def(import_content(record))
        tool['function']['parameters'] = {'type': 'object', 'required': ['absent_fixture']}
        args['available_tools'] = [tool]
        reason = 'arguments_do_not_match_schema'
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        try:
            result = unpack(await server.call_tool('execute_attack_template', args))
            assert result['status'] == 'skipped' and result['skipped'] == 1
            assert result['total_attempts'] == 0 and result['successful'] == 0
            assert result['results'][0]['metadata']['reason'] == reason
            saved = await recorder.snapshot(run_id=result['run_id'])
            assert saved['statistics'] == result['statistics']
            assert len(saved['results']) == 1 and saved['runs'][0]['status'] == 'completed'
        finally:
            await recorder.close()
    asyncio.run(check())


def test_request_configuration_failure_has_no_failed_attempt(monkeypatch, tmp_path, seed_snapshot):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('unexpected HTTP'))
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        try:
            reply = await server.call_tool('execute_attack_template', {
                'template_id': select(seed_snapshot, 'injection.direct')['id'],
                'target': {'url': URL, 'body': '${request.body.max_tokens}'}})
            result = unpack(reply)
            assert reply.isError and result['error'] == 'target_configuration_error'
            assert result['code'] == 'missing_variable'
            saved = await recorder.snapshot(run_id=result['run_id'])
            assert saved['runs'][0]['status'] == 'failed' and saved['results'] == []
            assert not server._history
        finally:
            await recorder.close()
    asyncio.run(check())


@pytest.mark.parametrize('response', ['empty', 'http_error', 'connection_error'])
def test_unsuccessful_attempts_are_retained_and_clients_closed(response, monkeypatch, seed_snapshot):
    def handler(request):
        if response == 'connection_error':
            raise httpx.ConnectError('fixture', request=request)
        return httpx.Response(500 if response == 'http_error' else 200,
                              json={'choices': [{'message': {'content': ''}}]})
    requests, clients = transport(monkeypatch, handler)
    result = execute(select(seed_snapshot, 'injection.direct')['id'], target_url=URL)
    assert result['total_attempts'] == 1 and result['successful'] == 0
    assert len(requests) == len(server._history) == 1 and all(c.is_closed for c in clients)


def test_custom_target_and_tool_schemas_keep_exact_requests(monkeypatch, seed_snapshot):
    record = select(seed_snapshot, 'tool_abuse.exploit')
    definition = import_content(record)
    supplied = _build_tool_def(definition)
    original = copy.deepcopy(supplied)
    server._config.target_profiles = {'saved': {'url': URL, 'method': 'PUT',
        'variables': {'workspace': 'default'},
        'body': {'messages': '${request.messages}', 'functions': '${request.tools}', 'workspace': '${vars.workspace}'},
        'response': {'tool_calls': {'path': '/actions', 'name': '/name', 'arguments': '/arguments'}}}}
    requests, clients = transport(monkeypatch, lambda _: httpx.Response(200, json={'actions': [{
        'name': definition['tool_name'], 'arguments': definition['payload']['arguments']}]}))
    result = execute(record['id'], target='saved', target_variables={'workspace': 'overridden'}, available_tools=[supplied])
    assert result['total_attempts'] == result['successful'] == 1 and len(requests) == 1
    request = requests[0]
    assert request.method == 'PUT'
    body = json.loads(request.content)
    assert set(body) == {'messages', 'functions', 'workspace'}
    assert body['functions'] == [original] and body['workspace'] == 'overridden'
    assert supplied == original and all(c.is_closed for c in clients)


def test_exceptional_unicode_credentials_and_recovery(monkeypatch, tmp_path, seed_snapshot):
    selected = next(r for r in seed_snapshot.records() if 'encoded_content' in r)
    payload = import_content(selected)['payload']
    server._config.target_api_url = URL
    server._config.target_environment = {'API_KEY': 'private-fixture-value'}
    requests, _ = transport(monkeypatch, lambda _: httpx.Response(200, json={
        'content': 'Fixture reply private-fixture-value second-fixture-secret'}))
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        writer = recorder.repository.write
        def broken(events):
            raise ReportError('storage_unavailable')
        monkeypatch.setattr(recorder.repository, 'write', broken)
        # 1.1.0: ${env.*} requires a saved profile.
        server._config.target_profiles = {'saved': {'url': URL + '?key=${env.API_KEY}',
            'variables': {'workspace': 'second-fixture-secret'},
            'headers': {'Authorization': 'Bearer ${vars.workspace}'}, 'body': '${request.body}'}}
        try:
            reply = await server.call_tool('execute_attack_template', {
                'template_id': selected['id'], 'target': 'saved'})
            result = unpack(reply)
            assert result['persistence']['status'] == 'pending' and result['total_attempts'] == 1
            assert len(requests) == 1
            assert requests[0].headers['authorization'] == 'Bearer second-fixture-secret'
            assert 'private-fixture-value' not in json.dumps(result)
            assert 'second-fixture-secret' not in json.dumps(result)
            monkeypatch.setattr(recorder.repository, 'write', writer)
            await recorder.flush()
            await recorder.flush()
            saved = await recorder.snapshot(run_id=result['run_id'])
            assert len(saved['results']) == 1
            assert saved['results'][0]['evidence']['technique_payload'] == payload
            assert 'private-fixture-value' not in json.dumps(saved) and '?key=' not in json.dumps(saved)
            assert 'second-fixture-secret' not in json.dumps(saved)
        finally:
            await recorder.close()
    asyncio.run(check())


def test_origin_rules_apply_before_single_execution(monkeypatch, seed_snapshot):
    # 1.1.0: tightened error channels (F7) and inline-env rejection (F2).
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('unexpected HTTP'))
    identifier = select(seed_snapshot, 'injection.direct')['id']
    server._config.target_api_url = URL
    server._config.target_api_key = 'private-fixture'
    server._config.target_environment = {'API_KEY': 'private-fixture'}
    other = execute(identifier, target_url='https://elsewhere.invalid')
    assert other['error'] == 'target_configuration_error' and other['code'] == 'authenticated_target_origin_mismatch'
    inline_env = execute(identifier, target={'url': 'https://elsewhere.invalid', 'headers': {
        'Authorization': '${env.API_KEY}'}})
    assert inline_env['code'] == 'inline_environment_reference_forbidden'
    assert execute(identifier, target_url='https://example.invalid:private-fixture/chat')['code'] == 'invalid_target_url'


def test_inflight_execution_keeps_snapshot_and_next_call_sees_update(monkeypatch, catalog_path):
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, '_catalog_repository', repository)
    async def check():
        entered, release = asyncio.Event(), asyncio.Event()
        original = await repository.snapshot()
        record = select(original, 'injection.direct')
        first_payload = import_content(record)['payload']
        async def handler(request):
            body = json.loads(request.content)
            if body['workspace'] == 'first':
                entered.set()
                await release.wait()
            return httpx.Response(200, json={'content': 'fixture'})
        requests, clients = transport(monkeypatch, handler)
        server._config.target_profiles = {'saved': {'url': URL, 'variables': {'workspace': 'original'},
            'body': {'prompt': '${request.prompt}', 'workspace': '${vars.workspace}'}}}
        args = {'template_id': record['id'], 'target': 'saved'}
        task = asyncio.create_task(server.call_tool('execute_attack_template', {
            **args, 'catalog_revision': original.revision, 'target_variables': {'workspace': 'first'}}))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            record['content']['payload'] = 'New harmless fixture'
            await asyncio.to_thread(publish, catalog_path, {'format_version': 1, 'records': [record]}, update=True)
            second = unpack(await server.call_tool('execute_attack_template', {
                **args, 'target_variables': {'workspace': 'second'}}))
            release.set()
            first = unpack(await task)
            assert first['catalog_revision'] == original.revision < second['catalog_revision']
            bodies = [json.loads(r.content) for r in requests]
            assert bodies == [{'prompt': first_payload, 'workspace': 'first'},
                              {'prompt': 'New harmless fixture', 'workspace': 'second'}]
            assert len(first['results']) == len(second['results']) == 1
            assert first['results'][0]['attack_id'] != second['results'][0]['attack_id']
            assert all(c.is_closed for c in clients)
            assert server._config.target_profiles['saved']['variables']['workspace'] == 'original'
        finally:
            release.set()
            await task
            await repository.close()
    asyncio.run(check())
