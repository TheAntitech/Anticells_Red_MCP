import asyncio
import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from anticells_red_mcp.catalog.model import CatalogError, CatalogSnapshot, import_content
from anticells_red_mcp.catalog.repository import CatalogRepository, publish
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.reports.model import ReportError
from anticells_red_mcp.reports.recorder import Recorder
from anticells_red_mcp.reports.repository import ReportRepository


URL = 'https://example.invalid/chat'


def unpack(reply):
    return json.loads((reply.content if hasattr(reply, 'content') else reply)[0].text)


def records(snapshot):
    return [r for r in snapshot.records() if r['namespace'] == 'fingerprint.scanner' and r['kind'] == 'technique']


def call(**kwargs):
    if 'target' not in kwargs and 'target_url' not in kwargs:
        kwargs['target_url'] = URL
    return unpack(asyncio.run(server.call_tool('get_fingerprint_profile', kwargs)))


def mock_http(monkeypatch, handler):
    requests, clients = [], []
    original = httpx.AsyncClient
    async def send(request):
        requests.append(request)
        result = handler(request)
        return await result if asyncio.iscoroutine(result) else result
    def factory(**kwargs):
        kwargs['transport'] = httpx.MockTransport(send)
        client = original(**kwargs)
        clients.append(client)
        return client
    monkeypatch.setattr(httpx, 'AsyncClient', factory)
    return requests, clients


@pytest.mark.parametrize('intensity', [None, 2, 3, 4, 5])
def test_budgets_order_requests_and_unknown_identity(monkeypatch, seed_snapshot, intensity):
    requests, clients = mock_http(monkeypatch, lambda _: httpx.Response(200, json={'content': 'Hello fixture'}))
    server._config.target_model = 'configured-fixture-model'
    result = call(**({'intensity': intensity} if intensity is not None else {}))
    profile = result['profile']
    expected = sorted(records(seed_snapshot), key=lambda r: r['content']['weight'], reverse=True)[:(intensity or 1) * 6]
    assert len(requests) == result['statistics']['total_attacks'] == len(expected)
    assert [p['template_id'] for p in profile['probes']] == [r['id'] for r in expected]
    assert profile['coverage']['attempted'] == len(expected)
    for request, record in zip(requests, expected):
        assert request.method == 'POST'
        assert json.loads(request.content) == {'messages': [{'role': 'user', 'content': record['content']['payload']}],
            'max_tokens': 1024, 'temperature': 0.0, 'model': 'configured-fixture-model'}
    assert profile['identity']['model_hint'] == profile['identity']['provider_hint'] == 'unknown'
    assert profile['identity']['reported_models'] == []
    assert profile['identity']['confidence'] == 0 and not profile['identity']['verified']
    assert profile['legacy_estimates']['context_window'] == 0
    assert not profile['legacy_estimates']['measured']
    assert profile['status'] == 'complete' and profile['behavior']['refusal_rate'] == 0
    assert profile['transport']['latency_ms']['samples'] == len(expected)
    assert all(c.is_closed for c in clients)
    assert len(server._history) == len(expected)


def test_profile_evidence_failures_refusals_and_exports_survive_restart(monkeypatch, tmp_path):
    counter = 0
    def respond(request):
        nonlocal counter
        counter += 1
        if counter == 1:
            return httpx.Response(200, headers={'server': 'openai', 'set-cookie': 'private-cookie'}, json={
                'model': 'gpt-fixture-actual', 'choices': [{'finish_reason': 'stop', 'message': {
                    'content': 'I am an OpenAI model. ' + 'long fixture text ' * 1000}}]})
        if counter == 2:
            return httpx.Response(200, json={'choices': [{'finish_reason': 'stop', 'message': {
                'content': 'I cannot comply with this request.'}}]})
        if counter == 3:
            return httpx.Response(200, json={'content': ''})
        if counter == 4:
            return httpx.Response(429, json={'error': 'fixture'})
        if counter == 5:
            raise httpx.ConnectError('private-error', request=request)
        return httpx.Response(200, content=b'not JSON')
    requests, clients = mock_http(monkeypatch, respond)
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        try:
            result = unpack(await server.call_tool('get_fingerprint_profile', {'target_url': URL + '?private=hidden'}))
            profile = result['profile']
            assert profile['target'] == URL and profile['status'] == 'partial'
            assert profile['identity']['reported_models'] == ['gpt-fixture-actual']
            assert profile['identity']['provider_hint'] == 'OpenAI'
            assert profile['identity']['model_hint'] == 'gpt-4o'  # Existing candidate-table heuristic, not the reported ID.
            assert profile['identity']['verified'] is False
            assert profile['legacy_estimates']['context_window'] == 128000
            assert profile['legacy_estimates']['measured'] is False
            assert profile['behavior']['refusal_count'] == 1 and profile['behavior']['refusal_rate'] == .5
            assert profile['coverage']['attempted'] == 6 and profile['coverage']['usable_responses'] == 2
            assert profile['transport']['http_status_counts'] == {'200': 4, '429': 1}
            assert profile['transport']['outcome_counts'] == {
                'usable_response': 2, 'empty_response': 1, 'http_error': 1, 'connection_failed': 1, 'invalid_response': 1}
            assert len(profile['probes'][0]['response_excerpt']) == 300
            assert all(p['refusal_detected'] is None for p in profile['probes'][2:])
            assert result['statistics']['total_attacks'] == 6 and result['statistics']['successful_attacks'] == 2
            assert len({p['result_id'] for p in profile['probes']}) == 6
            assert 'private-cookie' not in json.dumps(result) and 'private-error' not in json.dumps(result)
            saved = await recorder.snapshot(run_id=result['run_id'])
            assert saved['runs'][0]['fingerprint_profile'] == profile
            assert saved['statistics'] == result['statistics']
            assert {r['id'] for r in saved['results']} == {p['result_id'] for p in profile['probes']}
            assert len(saved['results']) == 6
            assert any(len(r['evidence']['reply']) > 15000 for r in saved['results'])
            assert 'private-cookie' not in json.dumps(saved) and '?private=' not in json.dumps(saved)
            for fmt in ('json', 'markdown', 'html'):
                exported = unpack(await server.call_tool('get_attack_report', {
                    'action': 'export', 'run_id': result['run_id'], 'export_format': fmt}))
                data = Path(exported['path']).read_bytes()
                assert b'fingerprint_profile' in data
                if fmt == 'json':
                    doc = json.loads(data)
                    assert doc['runs'][0]['fingerprint_profile'] == profile
            return result['run_id'], profile
        finally:
            await recorder.close()
    run_id, profile = asyncio.run(check())
    restarted = ReportRepository(tmp_path)
    restarted.initialize()
    assert restarted.snapshot(run_id=run_id)['runs'][0]['fingerprint_profile'] == profile
    assert len(requests) == 6 and all(c.is_closed for c in clients)


@pytest.mark.parametrize('failure', ['empty', 'http', 'timeout', 'malformed'])
def test_all_failed_probes_do_not_identify_a_model(failure, monkeypatch):
    def respond(request):
        if failure == 'timeout':
            raise httpx.ReadTimeout('private-timeout', request=request)
        if failure == 'malformed':
            return httpx.Response(200, json=['not a supported reply'])
        return httpx.Response(503 if failure == 'http' else 200, headers={'server': 'openai'}, json={'content': ''})
    mock_http(monkeypatch, respond)
    profile = call()['profile']
    assert profile['status'] == 'no_usable_responses'
    assert profile['identity']['model_hint'] == profile['identity']['provider_hint'] == 'unknown'
    assert profile['identity']['confidence'] == 0
    assert profile['identity']['reported_models'] == []
    assert profile['behavior']['refusal_rate'] is None and profile['behavior']['refusal_count'] == 0
    assert profile['coverage']['failed_responses'] == 6


def test_exact_ids_duplicate_names_and_disabled_catalog_selection(seed_snapshot, monkeypatch):
    all_records = seed_snapshot.records()
    source = records(seed_snapshot)[0]
    clones = []
    for n in (1, 2):
        record = copy.deepcopy(source)
        record.update(id=f'custom/profile-{n}', position=1000 + n)
        record['content'].update(name='same_name', payload=f'Harmless fixture {n}', weight=1.0)
        clones.append(record)
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(
        return_value=CatalogSnapshot.build(2, all_records + clones)))
    requests, _ = mock_http(monkeypatch, lambda _: httpx.Response(200, json={'content': 'Hello'}))
    profile = call(template_ids=[clones[1]['id']], catalog_revision=2)['profile']
    assert profile['coverage']['attempted'] == 1
    assert profile['probes'][0]['template_id'] == clones[1]['id']
    assert json.loads(requests[0].content)['messages'][0]['content'] == 'Harmless fixture 2'
    assert call(template_ids=['same_name'])['code'] == 'template_not_found'
    assert call(catalog_revision=1)['code'] == 'catalog_revision_changed'
    clones[1]['enabled'] = False
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(
        return_value=CatalogSnapshot.build(3, all_records + clones)))
    assert call(template_ids=[clones[1]['id']])['code'] == 'template_disabled'
    other = next(r for r in all_records if r['kind'] == 'technique' and r['namespace'] != 'fingerprint.scanner')
    assert call(template_ids=[other['id']])['code'] == 'template_not_fingerprint'
    assert len(requests) == 1


@pytest.mark.parametrize('args', [
    {}, {'target_url': URL, 'target': 'saved'}, {'target_url': URL, 'target_variables': {}},
    {'target': {'url': URL, 'env_files': ['private.env']}}, {'target_url': URL, 'intensity': 0},
    {'target_url': URL, 'intensity': 6}, {'target_url': URL, 'template_ids': []},
    {'target_url': URL, 'template_ids': ['same', 'same']}, {'target_url': URL, 'template_ids': [1]},
    {'target_url': URL, 'catalog_revision': -1}, {'target_url': URL, 'run_id': 'old'},
])
def test_schema_errors_before_catalog_load(args):
    reply = asyncio.run(server.call_tool('get_fingerprint_profile', args))
    assert reply.isError and unpack(reply)['error'] == 'invalid_arguments'
    server._catalog_repository.snapshot.assert_not_awaited()


def test_incompatible_response_and_request_configuration_fail_before_any_http(monkeypatch, seed_snapshot, tmp_path):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('HTTP must not start'))
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        try:
            for target, code in [
                ({'url': URL, 'response': {'tool_calls': {'path': '/calls', 'name': '/name', 'arguments': '/arguments'}}},
                 'target_has_no_text_mapping'),
                ({'url': URL, 'body': '${request.body.absent}'}, 'missing_variable'),
                ({'url': URL, 'body': 'embedded ${request.messages}'}, 'embedded_container_variable'),
            ]:
                reply = await server.call_tool('get_fingerprint_profile', {'target': target})
                result = unpack(reply)
                assert reply.isError and result['error'] == 'target_configuration_error' and result['code'] == code
                saved = await recorder.snapshot(run_id=result['run_id'])
                assert saved['runs'][0]['status'] == 'failed' and saved['results'] == []
                assert 'fingerprint_profile' not in saved['runs'][0]
            assert not server._history
        finally:
            await recorder.close()
    asyncio.run(check())


def test_custom_target_redacts_full_values_before_excerpts_and_recovers(monkeypatch, tmp_path, seed_snapshot):
    # 1.1.0: ${env.*} is only honored on operator-authored saved profiles.
    # The scenario is otherwise identical to the pre-1.1.0 inline variant.
    server._config.target_api_url = URL
    server._config.target_environment = {'API_KEY': 'private-env-value'}
    secret = 'private-header-value-that-crosses-excerpt-boundary'
    text = 'x' * 295 + secret + ' private-env-value'
    requests, clients = mock_http(monkeypatch, lambda _: httpx.Response(200,
        headers={'set-cookie': 'unrelated-private-cookie'}, json={'result': {'answer': text}}))
    server._config.target_profiles = {'saved': {
        'url': URL + '?key=${env.API_KEY}', 'method': 'PATCH',
        'variables': {'workspace': secret}, 'headers': {'Authorization': 'Bearer ${vars.workspace}'},
        'body': {'question': '${request.prompt}', 'count': '${request.body.max_tokens}'},
        'response': {'text': '/result/answer'}}}
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        write = recorder.repository.write
        def broken(events):
            raise ReportError('storage_unavailable')
        monkeypatch.setattr(recorder.repository, 'write', broken)
        try:
            result = unpack(await server.call_tool('get_fingerprint_profile', {
                'template_ids': [records(seed_snapshot)[0]['id']],
                'target': 'saved'}))
            assert result['persistence']['status'] == 'pending'
            assert result['profile']['target'] == 'saved'
            excerpt = result['profile']['probes'][0]['response_excerpt']
            assert excerpt == ('x' * 295 + '[REDACTED]')[:300]
            assert 'private-env' not in json.dumps(result)
            assert 'private-header' not in json.dumps(result)
            assert 'unrelated-private-cookie' not in json.dumps(result)
            request = requests[0]
            assert request.method == 'PATCH' and request.headers['authorization'] == 'Bearer ' + secret
            assert json.loads(request.content)['count'] == 1024
            monkeypatch.setattr(recorder.repository, 'write', write)
            await recorder.flush()
            await recorder.flush()
            saved = await recorder.snapshot(run_id=result['run_id'])
            assert len(saved['results']) == 1
            assert saved['runs'][0]['fingerprint_profile'] == result['profile']
            assert 'private-header' not in json.dumps(saved) and 'private-env' not in json.dumps(saved)
            # Saved retrieval remains available without the catalog or target.
            monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(side_effect=CatalogError('storage_unavailable')))
            viewed = unpack(await server.call_tool('get_attack_report', {'run_id': result['run_id']}))
            assert viewed['runs'][0]['fingerprint_profile'] == result['profile']
            assert len(requests) == 1 and all(c.is_closed for c in clients)
        finally:
            await recorder.close()
    asyncio.run(check())


def test_origin_and_catalog_errors_do_not_probe(monkeypatch):
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **k: pytest.fail('HTTP must not start'))
    server._config.target_api_url = URL
    server._config.target_api_key = 'private-fixture'
    server._config.target_environment = {'API_KEY': 'private-fixture'}
    # 1.1.0: all target-URL rejections use the stable
    # ``target_configuration_error`` error channel (finding F7). Inline
    # ${env.*} is now forbidden outright (F2).
    reject_other = call(target_url='https://elsewhere.invalid')
    assert reject_other['error'] == 'target_configuration_error'
    assert reject_other['code'] == 'authenticated_target_origin_mismatch'
    reject_env = call(target={'url': 'https://elsewhere.invalid', 'body': '${env.API_KEY}'})
    assert reject_env['code'] == 'inline_environment_reference_forbidden'
    assert call(target_url='https://example.invalid:private-fixture/chat')['code'] == 'invalid_target_url'
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(side_effect=CatalogError('storage_unavailable')))
    assert call() == {'error': 'catalog_error', 'code': 'storage_unavailable'}


def test_concurrent_profiles_keep_calls_and_catalog_revisions_isolated(monkeypatch, catalog_path, tmp_path):
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, '_catalog_repository', repository)
    async def check():
        recorder = Recorder(ReportRepository(tmp_path))
        await recorder.start()
        monkeypatch.setattr(server, '_report_recorder', recorder)
        entered, release = asyncio.Event(), asyncio.Event()
        initial = await repository.snapshot()
        record = records(initial)[0]
        original_payload = record['content']['payload']
        async def respond(request):
            body = json.loads(request.content)
            if body['workspace'] == 'first':
                entered.set()
                await release.wait()
            return httpx.Response(200, json={'model': body['workspace'], 'content': 'Fixture reply'})
        requests, clients = mock_http(monkeypatch, respond)
        server._config.target_profiles = {'saved': {'url': URL, 'variables': {'workspace': 'original'},
            'body': {'prompt': '${request.prompt}', 'workspace': '${vars.workspace}'}}}
        args = {'template_ids': [record['id']], 'target': 'saved'}
        task = asyncio.create_task(server.call_tool('get_fingerprint_profile', {
            **args, 'catalog_revision': initial.revision, 'target_variables': {'workspace': 'first'}}))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            record['content']['payload'] = 'New harmless fixture'
            await asyncio.to_thread(publish, catalog_path, {'format_version': 1, 'records': [record]}, update=True)
            second = unpack(await server.call_tool('get_fingerprint_profile', {**args, 'target_variables': {'workspace': 'second'}}))
            release.set()
            first = unpack(await task)
            assert first['profile']['catalog_revision'] == initial.revision < second['profile']['catalog_revision']
            assert first['run_id'] != second['run_id']
            assert first['profile']['identity']['reported_models'] == ['first']
            assert second['profile']['identity']['reported_models'] == ['second']
            for result in (first, second):
                saved = await recorder.snapshot(run_id=result['run_id'])
                assert len(saved['results']) == 1
                assert saved['results'][0]['id'] == result['profile']['probes'][0]['result_id']
            assert [json.loads(r.content)['prompt'] for r in requests] == [original_payload, 'New harmless fixture']
            assert all(c.is_closed for c in clients)
            assert server._config.target_profiles['saved']['variables'] == {'workspace': 'original'}
        finally:
            release.set()
            await task
            await recorder.close()
            await repository.close()
    asyncio.run(check())
