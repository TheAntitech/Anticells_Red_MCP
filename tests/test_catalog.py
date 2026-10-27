import asyncio
import copy
import importlib
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from anticells_red_mcp.catalog import CatalogError, CatalogSnapshot
from anticells_red_mcp.catalog.cli import parser, run, seed_document
from anticells_red_mcp.catalog.model import (
    decode, digest, encode, export_content, import_content, manifest,
    read_document, template_fields, validate_record,
)
from anticells_red_mcp.catalog.runtime import active_snapshot, snapshot_for
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.config import MCPConfig
from catalog_compatibility import capture, capture_auxiliary


def document(*records):
    return {'format_version': 1, 'records': list(records)}


def test_seed_values_order_and_all_auxiliary_hashes(seed_snapshot):
    original = seed_document()['records']
    for namespace, contract in manifest()['catalogs'].items():
        techniques = seed_snapshot.techniques(namespace)
        assert len(techniques) == contract['count']
        assert digest(techniques) == contract['hash']
        expected = [r for r in original if r['namespace'] == namespace and r['kind'] == 'technique']
        actual = [r for r in seed_snapshot.records() if r['namespace'] == namespace and r['kind'] == 'technique']
        assert encode(actual) == encode(expected)
    for key, contract in manifest()['assets'].items():
        assert digest(seed_snapshot.asset(key)) == contract['hash']
    assert len(original) == 496
    assert len({r['id'] for r in original}) == len(original)
    names = [import_content(r)['name'] for r in original if r['kind'] == 'technique']
    assert len(set(names)) < len(names)


def test_original_request_and_deterministic_mutation_fixtures():
    config = MCPConfig(target_api_url='https://example.invalid/chat')
    actual = asyncio.run(capture(config, manifest()['catalogs']))
    expected = json.loads((Path(__file__).parent / 'fixtures/catalog_compatibility.json').read_text())
    assert actual['mutation_hash'] == expected['mutation_hash']
    assert actual['requests'] == expected['requests']


def test_auxiliary_mutation_requests_memberships_and_mcp_schemas(seed_snapshot):
    expected = json.loads((Path(__file__).parent / 'fixtures/catalog_auxiliary_compatibility.json').read_text())
    actual = asyncio.run(capture_auxiliary(MCPConfig(target_api_url='https://example.invalid/chat')))
    assert actual['requests'] == expected['requests']
    assert actual['mutation_hash'] == expected['mutation_hash']
    # Adding discovery must not alter any of the original eight tools' contracts.
    assert digest([t.model_dump() for t in asyncio.run(server.list_tools())
                   if t.name not in {'list_attack_templates', 'get_compatible_templates', 'execute_attack_template', 'get_fingerprint_profile'}]) == expected['mcp_schemas_hash']
    assert digest([r['memberships'] for r in seed_snapshot.records()
                   if r['namespace'] == 'jailbreaks.engine' and r['kind'] == 'technique']) == expected['memberships_hash']


def test_lossless_unicode_and_exports(seed_snapshot):
    exceptional = [r for r in seed_snapshot.records() if 'encoded_content' in r]
    assert len(exceptional) == 1
    original = import_content(exceptional[0])
    assert json.loads(json.dumps(original)) != original
    assert decode(encode(original)) == original
    assert import_content(json.loads(json.dumps(export_content(original)))) == original
    value = {'null': '\0', 'surrogates': '\ud800\udc00', 'unicode': 'é漢😀', 'order': {'z': 1, 'a': 2}}
    assert encode(import_content(export_content(value))) == encode(value)


def test_snapshot_is_immutable_and_modules_do_not_share_mutable_values(seed_snapshot):
    from anticells_red_mcp.modules.injection.direct import InjectionEngine
    first, second = InjectionEngine(MCPConfig()), InjectionEngine(MCPConfig())
    first.get_techniques()[0]['payload'] = 'changed'
    assert second.get_techniques()[0]['payload'] != 'changed'
    records = seed_snapshot.records()
    records.clear()
    assert len(seed_snapshot.records()) == 496
    assert copy.deepcopy(seed_snapshot) is seed_snapshot
    key = next(k for k, c in manifest()['assets'].items() if c['schema']['type'] == 'array')
    asset = seed_snapshot.asset(key)
    asset.clear()
    assert seed_snapshot.asset(key)
    assert 'payload' not in repr(seed_snapshot)


@pytest.mark.parametrize('text', ['{env.API_KEY}', '{value[0]}', '{value!r}', '{value:20}', '{}', '{broken'])
def test_templates_reject_expressions_and_undeclared_inputs(text):
    with pytest.raises(CatalogError):
        template_fields(text)


def test_templates_render_once_and_payloads_remain_literal(seed_snapshot):
    record = next(r for r in seed_snapshot.records() if r['kind'] == 'template' and manifest()['assets'][r['id']]['inputs'] == ['value0'])
    record['content'] = 'Literal {{braces}}: {value0}'
    records = [record if r['id'] == record['id'] else r for r in seed_snapshot.records()]
    snapshot = CatalogSnapshot.build(2, records)
    assert snapshot.render(record['id'], value0='${env.SECRET} {value0}') == 'Literal {braces}: ${env.SECRET} {value0}'
    with pytest.raises(CatalogError):
        snapshot.render(record['id'], missing='value')


@pytest.mark.parametrize('change', [
    {'id': []}, {'namespace': []}, {'kind': {}}, {'enabled': 1}, {'position': -1},
    {'revision': True}, {'memberships': ['new_category']}, {'unknown': True},
    {'content': {'name': 'incomplete'}}, {'content': None},
])
def test_malformed_record_validation_is_safe(change, seed_snapshot):
    record = next(r for r in seed_snapshot.records() if r['kind'] == 'technique')
    record.update(change)
    with pytest.raises(CatalogError) as exc:
        validate_record(record)
    assert 'payload' not in str(exc.value)


def test_invalid_strategy_tool_schema_and_missing_assets(seed_snapshot):
    records = seed_snapshot.records()
    mutation = next(r for r in records if r['namespace'] == 'mutation.creative_engine' and r['kind'] == 'technique')
    mutation['content']['strategy'] = 'arbitrary_python'
    with pytest.raises(CatalogError): validate_record(mutation)
    tool = next(r for r in records if r['namespace'] == 'tool_abuse.exploit' and r['kind'] == 'technique')
    tool['content']['args'] = {'tool': {'$ref': 'https://example.invalid/schema'}}
    with pytest.raises(CatalogError): validate_record(tool)
    with pytest.raises(CatalogError, match='missing_required_asset'):
        CatalogSnapshot.build(1, [r for r in seed_snapshot.records() if r['kind'] == 'technique'])
    with pytest.raises(CatalogError, match='duplicate_id'):
        read_document(document(seed_snapshot.records()[0], seed_snapshot.records()[0]))


@pytest.mark.parametrize('namespace', list(manifest()['catalogs']))
def test_cli_examples_validate_offline(namespace, tmp_path, monkeypatch):
    monkeypatch.delenv('ANTICELLS_RED_MCP_DATABASE_URL', raising=False)
    path = str(tmp_path / 'technique.json')
    run(parser().parse_args(['new', '--namespace', namespace, '--output', path]))
    assert run(parser().parse_args(['validate', path])) == {'valid': True, 'records': 1}


def test_no_runtime_seed_fallback_and_redacted_configuration(monkeypatch, tmp_path):
    from anticells_red_mcp.catalog import runtime
    monkeypatch.delenv('ANTICELLS_RED_MCP_DATABASE_URL', raising=False)
    token = active_snapshot.set(None)
    try:
        with pytest.raises(CatalogError, match='database_unavailable'):
            snapshot_for(MCPConfig(database_path=str(tmp_path / 'missing.sqlite3'), catalog_auto_setup=False))
    finally:
        active_snapshot.reset(token)
    assert 'secret-password' not in repr(MCPConfig(database_url='postgresql://user:secret-password@host/db'))
    assert not (tmp_path / 'missing.sqlite3').exists()
    assert 'private-path' not in repr(MCPConfig(database_path='private-path/catalog.sqlite3'))


def test_database_failure_does_not_count_attempt_and_reports_remain_usable(monkeypatch):
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(side_effect=CatalogError('database_unavailable')))
    async def check():
        failed = await server.call_tool('prompt_injection', {'target_url': 'https://example.invalid/chat'})
        assert failed.isError
        assert json.loads(failed.content[0].text) == {'error': 'catalog_error', 'code': 'database_unavailable'}
        report = await server.call_tool('get_attack_report', {})
        assert isinstance(report, list)
        assert json.loads(report[0].text)['statistics']['total_attacks'] == 0
        assert isinstance(await server.call_tool('stop_attack_loop', {}), list)
    asyncio.run(check())


def test_overlapping_calls_keep_selected_snapshot(monkeypatch, seed_snapshot):
    observed = []
    revised = CatalogSnapshot.build(2, seed_snapshot.records())
    snapshots = [seed_snapshot, revised]
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(side_effect=snapshots))
    from anticells_red_mcp.modules.injection.direct import InjectionEngine
    async def injected(self, *args, **kwargs):
        selected = self._catalog
        await asyncio.sleep(.02)
        assert self._catalog is selected
        observed.append(selected.revision)
        return []
    monkeypatch.setattr(InjectionEngine, 'run_injection', injected)
    async def check():
        replies = await asyncio.gather(*[
            server.call_tool('prompt_injection', {'target_url': 'https://example.invalid/chat'}) for _ in range(2)])
        assert all(isinstance(r, list) for r in replies)
    asyncio.run(check())
    assert sorted(observed) == [1, 2]
