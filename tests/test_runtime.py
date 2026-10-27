import asyncio
import hashlib
import importlib
import inspect
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from jsonschema import Draft202012Validator

from anticells_red_mcp import __author__
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.config import MCPConfig
from anticells_red_mcp.mcp_server.engine import AttackEngine, AttackResult
from anticells_red_mcp.mcp_server.relentless_loop import LoopMode, RelentlessLoop


TOOLS = {
    'fingerprint_llm', 'jailbreak_attack', 'prompt_injection',
    'tool_abuse_exploit', 'creative_mutation', 'endless_attack_loop',
    'get_attack_report', 'stop_attack_loop', 'list_attack_templates', 'get_compatible_templates', 'execute_attack_template', 'get_fingerprint_profile',
}
CATALOGS = {
    'fingerprint.scanner': 'FingerprintScanner',
    'injection.direct': 'InjectionEngine',
    'jailbreaks.engine': 'JailbreakEngine',
    'mutation.creative_engine': 'CreativeMutationEngine',
    'tool_abuse.exploit': 'ToolAbuseEngine',
}


def run(coro):
    return asyncio.run(coro)


def unpack(value):
    blocks = value.content if hasattr(value, 'content') else value
    return json.loads(blocks[0].text)


def result(module='injection', success=True):
    return AttackResult('fixture', module, 'fixture', 'fixture', success, .5)


def test_original_catalogs_unchanged():
    async def collect():
        catalogs = {}
        for name, cls in CATALOGS.items():
            module = importlib.import_module('anticells_red_mcp.modules.' + name)
            instance = getattr(module, cls)(MCPConfig())
            try:
                catalogs[name] = instance.get_techniques()
            finally:
                await instance.close()
        raw = json.dumps(catalogs, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
        assert sum(map(len, catalogs.values())) == 194
        assert hashlib.sha256(raw).hexdigest() == '446e5cb2cf5edb8d3c4a73f7e75a7171e0809d800c8fab144a184f48ef134f47'
    run(collect())


def test_original_tools_plus_template_listing_and_valid_schemas():
    tools = run(server.list_tools())
    assert {t.name for t in tools} == TOOLS
    for tool in tools:
        Draft202012Validator.check_schema(tool.inputSchema)
    injection = next(t for t in tools if t.name == 'prompt_injection')
    assert 'rag_poisoning' not in injection.inputSchema['properties']['injection_type']['enum']
    assert not inspect.iscoroutinefunction(server.main)


@pytest.mark.parametrize('name,args', [
    ('unknown', {}),
    ('fingerprint_llm', {}),
    ('prompt_injection', {'target_url': 'https://example.invalid', 'injection_type': 'rag_poisoning'}),
    ('creative_mutation', {'generations': 0}),
    ('creative_mutation', {'creativity_level': 2}),
    ('endless_attack_loop', {'target_url': 'https://example.invalid', 'max_iterations': -1}),
    ('get_attack_report', {'extra': 'unwanted'}),
])
def test_bad_arguments_are_mcp_errors_without_initializing_engine(name, args):
    response = run(server.call_tool(name, args))
    assert response.isError
    assert 'traceback' not in response.content[0].text
    assert server._engine is None


@pytest.mark.parametrize('target', ['file:///tmp/fixture', 'https://', 'https://example.invalid/#fragment'])
def test_bad_target_url_is_rejected(target):
    # 1.1.0 (finding F7): the legacy ``target_url`` path now returns a
    # stable ``target_configuration_error`` instead of a free-form
    # ``invalid_request`` message, matching the inline/saved paths.
    response = run(server.call_tool('fingerprint_llm', {'target_url': target}))
    assert response.isError
    body = unpack(response)
    assert body['error'] == 'target_configuration_error'
    assert body['code'] == 'invalid_target_url'


def test_unicode_serialization_preserves_original_surrogates():
    value = 'fixture' + chr(0xD800)
    response = server._json_content({'payload': value})
    response[0].text.encode('utf-8')
    assert unpack(response)['payload'] == value


@pytest.mark.parametrize('representation', ['dataclass', 'dict'])
@pytest.mark.parametrize('tool,module_name,class_name,operation', [
    ('jailbreak_attack', 'jailbreaks.engine', 'JailbreakEngine', 'run_attack'),
    ('prompt_injection', 'injection.direct', 'InjectionEngine', 'run_injection'),
    ('tool_abuse_exploit', 'tool_abuse.exploit', 'ToolAbuseEngine', 'run_exploit'),
])
def test_handlers_normalize_results_close_clients_and_record_history(
    monkeypatch, representation, tool, module_name, class_name, operation
):
    from dataclasses import asdict
    record = result()
    output = record if representation == 'dataclass' else asdict(record)
    instance = SimpleNamespace(close=AsyncMock())
    setattr(instance, operation, AsyncMock(return_value=[output]))
    configs = []
    def factory(config):
        configs.append(config)
        return instance
    module = importlib.import_module('anticells_red_mcp.modules.' + module_name)
    monkeypatch.setattr(module, class_name, factory)
    response = run(server.call_tool(tool, {'target_url': 'https://example.invalid/chat'}))
    assert isinstance(response, list)
    assert unpack(response)['total_attempts'] == 1
    assert unpack(response)['operator_signature'] == __author__
    instance.close.assert_awaited_once()
    assert configs[0] is not server._config
    assert server._config.target_api_url is None
    assert run(server._handle_report({}))['statistics']['total_attacks'] == 1


def test_fingerprint_scan_uses_synchronous_catalog_and_selected_probe(monkeypatch):
    from anticells_red_mcp.modules.fingerprint.scanner import FingerprintScanner
    probe = AsyncMock(return_value={'success': False})
    monkeypatch.setattr(FingerprintScanner, '_probe', probe)
    response = run(server.call_tool('fingerprint_llm', {
        'target_url': 'https://example.invalid', 'techniques': ['direct_identity_query'], 'intensity': 1,
    }))
    assert unpack(response)['techniques_used'] == 1
    assert unpack(response)['intensity'] == 1
    probe.assert_awaited_once()


def test_injection_uses_synchronous_catalog_and_filters(monkeypatch):
    from anticells_red_mcp.modules.injection.direct import InjectionEngine
    execute = AsyncMock(return_value=result())
    monkeypatch.setattr(InjectionEngine, 'execute', execute)
    async def check():
        instance = InjectionEngine(MCPConfig())
        try:
            name = instance.get_techniques()[0]['name']
            records = await instance.run_injection(name, payload_override='fixture')
            assert len(records) == 1
            assert execute.call_args.args[0]['payload'] == 'fixture'
        finally:
            await instance.close()
    run(check())


def test_default_mutation_seed_runs_locally():
    response = run(server.call_tool('creative_mutation', {'generations': 1}))
    assert isinstance(response, list)
    data = unpack(response)
    assert data['techniques_generated'] > 0
    assert all(len(x['evolution_log']) == 1 for x in data['evolved_techniques'])
    assert server._engine is None


def test_fallback_logger_writes_to_stderr(monkeypatch, capsys):
    from anticells_red_mcp.modules.utils import logger
    monkeypatch.setattr(logger, '_HAS_STRUCTLOG', False)
    name = 'anticells_red_mcp-regression'
    logging.getLogger(name).handlers.clear()
    instance = logger.AttackLogger(name)
    try:
        instance.info('fixture diagnostic')
        captured = capsys.readouterr()
        assert captured.out == ''
        assert 'fixture diagnostic' in captured.err
    finally:
        logging.getLogger(name).handlers.clear()


@pytest.mark.parametrize('mode', list(LoopMode))
def test_each_loop_strategy_honors_finite_round_limit(mode):
    async def check():
        config = MCPConfig()
        config.relentless.max_iterations = 2
        stub = SimpleNamespace(
            get_techniques=lambda: [{'name': 'fixture', 'module': 'fingerprint', 'payload': 'fixture'}],
            execute=AsyncMock(return_value=result('fingerprint', False)),
        )
        engine = SimpleNamespace(
            _modules={'fingerprint': stub}, _results=[], _successful_attacks=[],
            run_attack_cycle=AsyncMock(return_value=[]),
        )
        loop = RelentlessLoop(config, engine)
        loop.mode = mode
        await asyncio.wait_for(loop.run(), 3)
        assert loop.state.iteration == (1 if mode == LoopMode.DEPTH_FIRST else 2)
        assert len(engine._results) == stub.execute.await_count
    run(check())


def test_attack_cycle_records_results(monkeypatch):
    async def check():
        config = MCPConfig()
        config.relentless.auto_escalate = False
        engine = AttackEngine(config)
        module = SimpleNamespace(get_techniques=lambda: [{'name': 'fixture'}],
                                 execute=AsyncMock(return_value=result(success=False)))
        engine.register_module('injection', module)
        engine._mutator = SimpleNamespace(mutate_and_retry=AsyncMock(return_value=[]))
        records = await engine.run_attack_cycle()
        assert records == engine._results
        assert len(records) == 1
    run(check())


def test_overlapping_loop_rejected_stop_awaited_and_restart_gets_new_target(monkeypatch):
    from anticells_red_mcp.mcp_server import relentless_loop
    engines = []
    class FakeEngine:
        def __init__(self, config):
            self.config = config
            self._results = []
            self.initialize = AsyncMock()
            self.close = AsyncMock()
            self.stop = lambda: None
            engines.append(self)
    async def wait_until_cancelled(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(server, 'AttackEngine', FakeEngine)
    monkeypatch.setattr(relentless_loop.RelentlessLoop, 'run', wait_until_cancelled)
    async def check():
        await server._handle_endless_loop({'target_url': 'https://first.invalid'})
        first_task = server._loop_task
        await asyncio.sleep(0)
        rejected = await server.call_tool('endless_attack_loop', {'target_url': 'https://second.invalid'})
        assert rejected.isError
        engines[0]._results.append(result())
        await server._handle_stop({})
        assert first_task.done()
        engines[0].close.assert_awaited()
        await server._handle_endless_loop({'target_url': 'https://second.invalid'})
        assert engines[1].config.target_api_url == 'https://second.invalid'
        assert engines[1].config.relentless.max_iterations == 1
        assert (await server._handle_report({}))['statistics']['total_attacks'] == 1
        await server._handle_stop({})
    run(check())
