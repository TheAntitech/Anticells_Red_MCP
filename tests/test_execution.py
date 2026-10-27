"""Regression checks for execution plumbing; no live model or tool effects."""
import asyncio
from copy import deepcopy
from dataclasses import asdict
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.config import MCPConfig, load_config
from anticells_red_mcp.mcp_server.engine import AttackEngine, AttackResult
from anticells_red_mcp.mcp_server.relentless_loop import RelentlessLoop
from anticells_red_mcp.modules.fingerprint.scanner import FingerprintScanner
from anticells_red_mcp.modules.injection.direct import InjectionEngine
from anticells_red_mcp.modules.jailbreaks.engine import JailbreakEngine
from anticells_red_mcp.modules.mutation.creative_engine import CreativeMutationEngine
from anticells_red_mcp.modules.tool_abuse.exploit import ToolAbuseEngine
from anticells_red_mcp.modules.utils.chat_endpoint import make_chat_client, post_chat, response_text


def run(coro):
    return asyncio.run(coro)


def config():
    return MCPConfig(target_api_url='https://example.invalid/chat', target_model='fixture-model')


def fixture_tool():
    return {
        'name': 'fixture', 'module': 'tool_abuse', 'category': 'chain',
        'tool_name': 'fixture_tool', 'description': 'Local fixture',
        'payload': {'tool': 'fixture_tool', 'arguments': {'label': 'fixture'}},
        'args': {'label': {'type': 'string'}},
    }


def schema():
    return {'type': 'function', 'function': {
        'name': 'fixture_tool', 'description': 'Provided fixture',
        'parameters': {'type': 'object', 'properties': {'label': {'type': 'string'}},
                       'required': ['label'], 'additionalProperties': False},
    }}


@pytest.mark.parametrize('module_class,method', [
    (JailbreakEngine, '_send_payload'), (InjectionEngine, '_send_injection'),
])
@pytest.mark.parametrize('reply', [
    {}, {'choices': []}, {'choices': [{'message': {'content': ''}}]},
    {'choices': [{'message': {'content': '   '}}]},
    {'choices': [{'message': {'content': None}}]},
    {'choices': [{'message': {'content': {'unexpected': True}}}]},
    {'error': {'message': 'fixture error'}}, ['unsupported'],
])
def test_empty_or_unsupported_replies_never_succeed(module_class, method, reply):
    async def check():
        instance = module_class(config())
        instance._http_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=reply)))
        try:
            arg = {'payload': 'fixture'} if method == '_send_payload' else 'fixture'
            _, success = await getattr(instance, method)(arg, instance.config.target_api_url)
            assert success is False
        finally:
            await instance.close()
    run(check())


@pytest.mark.parametrize('module_class,method', [
    (JailbreakEngine, '_send_payload'), (InjectionEngine, '_send_injection'),
])
@pytest.mark.parametrize('status', [401, 429, 500])
def test_http_errors_remain_failures_and_do_not_echo_provider_bodies(module_class, method, status):
    async def check():
        instance = module_class(config())
        instance._http_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(status, text='private-fixture-body')))
        try:
            arg = {'payload': 'fixture'} if method == '_send_payload' else 'fixture'
            text, success = await getattr(instance, method)(arg, instance.config.target_api_url)
            assert not success
            assert str(status) in text and 'private-fixture-body' not in text
        finally:
            await instance.close()
    run(check())


@pytest.mark.parametrize('reply,expected', [
    ({'choices': [{'message': {'content': 'fixture reply'}}]}, 'fixture reply'),
    ({'content': 'fixture reply'}, 'fixture reply'),
    ({'response': 'fixture reply'}, 'fixture reply'),
    ({'choices': [{'message': {'content': [{'type': 'text', 'text': 'fixture reply'}]}}]}, 'fixture reply'),
])
def test_supported_reply_formats(reply, expected):
    assert response_text(reply) == expected


def test_basic_transport_honors_model_auth_and_unicode(monkeypatch):
    monkeypatch.setenv('ANTICELLS_RED_MCP_TARGET_API_KEY', 'fixture-credential')
    monkeypatch.setenv('ANTICELLS_RED_MCP_TARGET_MODEL', 'fixture-model')
    settings = load_config()
    assert 'fixture-credential' not in repr(settings)
    assert 'fixture-credential' not in json.dumps(settings.to_dict())
    async def check():
        client = make_chat_client(settings)
        assert client.headers['authorization'] == 'Bearer fixture-credential'
        assert client.headers['user-agent'] == 'anticells_red_mcp'
        await client.aclose()
        seen = []
        def capture(request):
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={'content': 'fixture'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(capture)) as mock:
            original = {'messages': [{'role': 'user', 'content': 'fixture' + chr(0xD800)}]}
            await post_chat(mock, 'https://example.invalid', original, settings)
            assert seen[0]['model'] == 'fixture-model'
            assert seen[0]['messages'] == original['messages']
            assert 'model' not in original
    run(check())


def test_all_endpoint_modules_apply_the_configured_model(monkeypatch):
    async def check():
        seen = []
        def capture(request):
            body = json.loads(request.content)
            seen.append(body)
            return httpx.Response(200, json={'choices': [{'message': {'content': 'fixture reply'}}]})
        modules = [FingerprintScanner(config()), JailbreakEngine(config()),
                   InjectionEngine(config()), ToolAbuseEngine(config())]
        try:
            for instance in modules:
                client = httpx.AsyncClient(transport=httpx.MockTransport(capture))
                if isinstance(instance, FingerprintScanner):
                    instance._client = client
                    await instance._probe(instance.config.target_api_url,
                                          {'name': 'fixture', 'payload': 'fixture', 'category': 'identity'})
                else:
                    instance._http_client = client
                    if isinstance(instance, JailbreakEngine):
                        await instance._send_payload({'payload': 'fixture'}, instance.config.target_api_url)
                    elif isinstance(instance, InjectionEngine):
                        await instance._send_injection('fixture', instance.config.target_api_url)
                    else:
                        instance._available_tools = [schema()]
                        await instance._send_tool_abuse(fixture_tool(), instance.config.target_api_url)
            assert len(seen) == 4
            assert all(body['model'] == 'fixture-model' for body in seen)
            assert seen[-1]['tools'] == [schema()]
        finally:
            for instance in modules:
                await instance.close()
    run(check())


@pytest.mark.parametrize('returned_arguments,success', [
    ('{"label":"fixture"}', True), ('{}', False),
    ('{"label":7}', False), ('not-json', False), ('[]', False),
])
def test_tool_schema_is_used_and_returned_arguments_checked(returned_arguments, success):
    async def check():
        seen = []
        def capture(request):
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={'choices': [{'message': {
                'content': None, 'tool_calls': [{'function': {
                    'name': 'fixture_tool', 'arguments': returned_arguments,
                }}],
            }}]})
        instance = ToolAbuseEngine(config())
        instance._techniques = [fixture_tool()]
        instance._http_client = httpx.AsyncClient(transport=httpx.MockTransport(capture))
        supplied = [schema()]
        try:
            records = await instance.run_exploit(supplied, 'chain', instance.config.target_api_url)
            assert len(records) == 1 and records[0].success is success
            assert seen[0]['tools'] == supplied
            assert supplied == [schema()]
        finally:
            await instance.close()
    run(check())


@pytest.mark.parametrize('reason', ['tool_unavailable', 'arguments_do_not_match_schema'])
def test_incompatible_tool_scenarios_skip_before_delivery(reason):
    async def check():
        instance = ToolAbuseEngine(config())
        instance._techniques = [fixture_tool()]
        send = AsyncMock()
        instance._send_tool_abuse = send
        supplied = schema()
        if reason == 'tool_unavailable':
            supplied['function']['name'] = 'other_fixture'
        else:
            supplied['function']['parameters']['properties']['label']['type'] = 'integer'
        try:
            records = await instance.run_exploit([supplied], 'chain', instance.config.target_api_url)
            assert records[0].metadata['status'] == 'skipped'
            assert records[0].metadata['reason'] == reason
            send.assert_not_awaited()
            server._history = [asdict(r) for r in records]
            report = await server._handle_report({})
            assert report['statistics']['skipped_records'] == 1
            assert report['statistics']['total_attacks'] == 0
        finally:
            await instance.close()
    run(check())


def test_local_mutation_never_claims_target_success_or_calls_http(monkeypatch):
    async def check():
        mutator = CreativeMutationEngine(config())
        monkeypatch.setattr(mutator, '_get_client', lambda: pytest.fail('unexpected HTTP client'))
        try:
            assert await mutator._llm_mutate('fixture') is None
            record = await mutator.execute({'name': 'fixture', 'payload': 'fixture',
                                            'strategy': 'restructure'}, 'fixture')
            assert record.success is False and record.confidence == 0
            assert record.metadata['evaluation'] == 'local_template'
            assert 'local_fitness' in record.metadata
        finally:
            await mutator.close()
    run(check())


def test_report_excludes_local_and_skipped_records_even_with_legacy_success_flags():
    records = [
        AttackResult('target', 'injection', 'fixture', 'fixture', True, .5),
        AttackResult('local', 'mutation', 'fixture', 'fixture', True, .9),
        AttackResult('skip', 'tool_abuse', 'fixture', 'fixture', True, .9, metadata={'status': 'skipped'}),
    ]
    engine = AttackEngine(config())
    engine._results = records
    assert engine.get_stats()['success_rate'] == 1
    assert engine.get_stats()['total_attacks'] == 1
    server._history = [asdict(r) for r in records]
    stats = run(server._handle_report({}))['statistics']
    assert stats['total_records'] == 3 and stats['total_attacks'] == 1
    assert stats['local_candidates'] == 1 and stats['skipped_records'] == 1
    assert stats['successful_attacks'] == 1


def test_structured_payloads_survive_loop_operations_and_catalog_stays_unchanged():
    async def check():
        structured = fixture_tool()
        original = deepcopy(structured)
        text = {'name': 'fixture', 'module': 'injection', 'payload': 'fixture'}
        module = SimpleNamespace(get_techniques=lambda: [structured],
                                 execute=AsyncMock(return_value=AttackResult(
                                     'fixture', 'tool_abuse', 'fixture', json.dumps(structured['payload']), False, 0)))
        engine = SimpleNamespace(_modules={'tool_abuse': module}, _results=[], _successful_attacks=[])
        loop = RelentlessLoop(config(), engine)
        assert (await loop._mutate_individual(structured))['payload'] == original['payload']
        child = await loop._crossover(structured, text)
        assert child in [original, text]
        variants = await loop._generate_variants(structured, 2)
        assert all(v['payload'] == original['payload'] for v in variants)
        catalogs = await loop._gather_all_techniques()
        catalogs['tool_abuse'][0]['payload']['arguments']['label'] = 'changed fixture'
        await loop._try_technique(structured)
        await loop._go_deeper(engine._results[0])
        assert structured == original
        assert all(call.kwargs['technique']['tool_name'] == 'fixture_tool'
                   for call in module.execute.await_args_list)
    run(check())


def test_single_execution_failure_does_not_crash_the_loop():
    async def check():
        module = SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError('private-fixture-error')))
        engine = SimpleNamespace(_modules={'injection': module}, _results=[], _successful_attacks=[])
        loop = RelentlessLoop(config(), engine)
        record = await loop._try_technique({'name': 'fixture', 'module': 'injection', 'payload': 'fixture'})
        assert not record.success and record.metadata['error'] == 'execution_failed'
        assert engine._results == [record]
    run(check())


def test_complete_original_endpoint_cycle_records_failures_without_local_successes(monkeypatch):
    from anticells_red_mcp.modules.fingerprint import scanner
    from anticells_red_mcp.modules.jailbreaks import engine as jailbreak
    from anticells_red_mcp.modules.injection import direct
    from anticells_red_mcp.modules.tool_abuse import exploit
    def factory(*args, **kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
            200, json={'choices': [{'message': {'content': ''}}]})))
    for module in (scanner, jailbreak, direct, exploit):
        monkeypatch.setattr(module, 'make_chat_client', factory)
    async def check():
        settings = config()
        settings.relentless.auto_escalate = False
        engine = AttackEngine(settings)
        try:
            await engine.initialize()
            records = await engine.run_attack_cycle()
            assert len(records) == 174
            assert engine.get_stats()['total_attacks'] == 171
            assert engine.get_stats()['local_candidates'] == 3
            assert engine.get_stats()['successful_attacks'] == 0
            assert engine.get_successful_attacks() == []
        finally:
            await engine.close()
    run(check())


@pytest.mark.parametrize('target', ['https://other.invalid/chat', 'http://example.invalid/chat',
                                    'https://example.invalid:9443/chat'])
def test_authenticated_calls_cannot_forward_credentials_to_other_origins(target):
    # 1.1.0: stable code replaces the old free-form message (finding F7).
    server._config = MCPConfig(target_api_url='https://example.invalid/v1/chat/completions',
                               target_api_key='fixture-credential')
    with pytest.raises(ValueError, match='authenticated_target_origin_mismatch'):
        server._target_config(target)
    assert server._target_config('https://example.invalid:443/other').target_api_key == 'fixture-credential'


def test_authenticated_calls_require_a_configured_endpoint_origin():
    # 1.1.0: stable code replaces the old free-form message (finding F7).
    server._config = MCPConfig(target_api_key='fixture-credential')
    with pytest.raises(ValueError, match='authenticated_calls_require_configured_origin'):
        server._target_config('https://example.invalid')


def test_tool_schemas_cannot_trigger_external_reference_fetches():
    supplied = schema()
    supplied['function']['parameters']['properties']['label'] = {'$ref': 'https://example.invalid/schema'}
    with pytest.raises(ValueError, match='inline or local'):
        ToolAbuseEngine._normalize_tools([supplied])
