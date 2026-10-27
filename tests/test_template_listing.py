import asyncio
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from anticells_red_mcp.catalog.browse import PUBLIC_CATALOGS
from anticells_red_mcp.catalog.model import CatalogError, CatalogSnapshot, import_content
from anticells_red_mcp.catalog.repository import CatalogRepository, publish
from anticells_red_mcp.mcp_server import server


def unpack(reply):
    return json.loads((reply.content if hasattr(reply, 'content') else reply)[0].text)


def listing(**args):
    return unpack(asyncio.run(server.call_tool('list_attack_templates', args)))


def test_default_listing_is_read_only_and_paginated(monkeypatch, seed_snapshot):
    recorder = SimpleNamespace(begin=AsyncMock(side_effect=AssertionError('must not create a run')))
    monkeypatch.setattr(server, '_report_recorder', recorder)
    # Discovery must not validate a configured target, instantiate a module, or send HTTP.
    monkeypatch.setattr(server, '_configured_target', lambda _: pytest.fail('target resolution'))
    import httpx
    monkeypatch.setattr(httpx, 'AsyncClient', lambda *a, **k: pytest.fail('HTTP client'))
    page = listing()
    assert page['total'] == 194 and page['returned'] == 50
    assert page['next_offset'] == 50 and page['catalog_revision'] == 1
    assert all('content' not in t and 'encoded_content' not in t for t in page['templates'])
    assert all(t['enabled'] and t['tool'] for t in page['templates'])
    actual = page['templates']
    while page['next_offset'] is not None:
        page = listing(offset=page['next_offset'], catalog_revision=page['catalog_revision'])
        actual.extend(page['templates'])
    expected = [r for r in seed_snapshot.records() if r['kind'] == 'technique' and r['namespace'] in PUBLIC_CATALOGS]
    assert [t['id'] for t in actual] == [r['id'] for r in expected]
    assert len({t['id'] for t in actual}) == 194
    assert server._history == [] and server._engine is None
    recorder.begin.assert_not_awaited()


@pytest.mark.parametrize('module,total', [('fingerprint', 30), ('jailbreaks', 53),
                                        ('injection', 53), ('tool_abuse', 35), ('mutation', 23)])
def test_module_filters(module, total):
    page = listing(module=module, limit=100)
    assert page['total'] == total
    assert all(t['module'] == module for t in page['templates'])


def test_category_filter_uses_actual_membership(seed_snapshot):
    records = [r for r in seed_snapshot.records() if r['namespace'] == 'jailbreaks.engine' and r['kind'] == 'technique']
    # Legacy selection membership intentionally differs from the entry category for some records.
    different = next(r for r in records if r['memberships'] != [import_content(r)['category']] and r['memberships'])
    category = different['memberships'][0]
    page = listing(module='jailbreaks', category=category, limit=100)
    assert [t['id'] for t in page['templates']] == [r['id'] for r in records if category in r['memberships']]
    assert different['id'] in [t['id'] for t in page['templates']]


def test_auxiliary_listing_and_disabled_records(monkeypatch, seed_snapshot):
    all_records = listing(include_auxiliary=True, limit=100)
    assert all_records['total'] == 365
    assert any(t['tool'] is None for t in all_records['templates'])
    records = seed_snapshot.records()
    selected = next(r for r in records if r['namespace'] == 'injection.direct' and r['kind'] == 'technique')
    selected['enabled'] = False
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(return_value=CatalogSnapshot.build(2, records)))
    assert listing()['total'] == 193
    assert listing(template_id=selected['id'])['total'] == 0
    disabled = listing(template_id=selected['id'], include_disabled=True)['templates'][0]
    assert disabled['enabled'] is False
    assert listing(include_disabled=True)['total'] == 194


def test_search_id_full_content_and_structured_payloads(seed_snapshot):
    first = listing(module='tool_abuse', include_content=True, limit=1)['templates'][0]
    assert isinstance(first['content']['payload'], dict)
    assert listing(search=first['name'].upper(), module='tool_abuse')['total'] >= 1
    selected = listing(template_id=first['id'], include_content=True)
    assert selected['templates'] == [first]
    source = next(r for r in seed_snapshot.records() if r['id'] == first['id'])
    assert first['content'] == import_content(source)
    payload = listing(module='injection', include_content=True, limit=1)['templates'][0]['content']['payload']
    assert listing(module='injection', search=payload[:20])['total'] >= 1
    assert listing(search='a search string absent from every original technique')['total'] == 0
    assert listing(offset=10000)['templates'] == []
    assert listing(offset=10000)['next_offset'] is None
    assert listing(limit=2.0, offset=1.0)['returned'] == 2


def test_exceptional_unicode_is_lossless_over_mcp(seed_snapshot):
    record = next(r for r in seed_snapshot.records() if 'encoded_content' in r)
    reply = listing(template_id=record['id'], include_content=True)
    entry = reply['templates'][0]
    assert entry['encoded_content']['encoding'] == 'json-utf8-surrogatepass-base64'
    assert import_content(entry) == import_content(record)


@pytest.mark.parametrize('args', [
    {'limit': 0}, {'limit': 101}, {'offset': -1}, {'offset': True},
    {'module': 'unknown'}, {'include_content': 'yes'}, {'search': '   '},
    {'search': 'x' * 201}, {'template_id': ''}, {'catalog_revision': -1},
    {'target_url': 'https://example.invalid'}, {'extra': 'unknown'},
])
def test_invalid_arguments_are_rejected_before_catalog_access(args):
    response = asyncio.run(server.call_tool('list_attack_templates', args))
    assert response.isError and unpack(response)['error'] == 'invalid_arguments'
    server._catalog_repository.snapshot.assert_not_awaited()


def test_revision_guard_and_catalog_errors(monkeypatch):
    result = listing(catalog_revision=999)
    assert result == {'error': 'catalog_error', 'code': 'catalog_revision_changed'}
    monkeypatch.setattr(server._catalog_repository, 'snapshot', AsyncMock(side_effect=CatalogError('storage_unavailable')))
    assert listing() == {'error': 'catalog_error', 'code': 'storage_unavailable'}


def test_published_templates_appear_on_next_call(catalog_path, monkeypatch):
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, '_catalog_repository', repository)
    async def check():
        try:
            initial = await repository.snapshot()
            baseline = unpack(await server.call_tool('list_attack_templates', {}))
            record = copy.deepcopy(next(r for r in initial.records() if r['namespace'] == 'injection.direct' and 'content' in r))
            record.update(id='custom/discovery-test', position=1000)
            record.pop('revision', None)
            payload = 'A harmless fixture prompt with "quotes"\n\u00e9.'
            record['content'].update(name='new_discoverable_template', payload=payload)
            await asyncio.to_thread(publish, catalog_path, {'format_version': 1, 'records': [record]})
            result = unpack(await server.call_tool('list_attack_templates', {'search': 'new_discoverable_template', 'include_content': True}))
            assert result['total'] == 1
            assert result['templates'][0]['content']['payload'] == payload
            literal = unpack(await server.call_tool('list_attack_templates', {'search': '"quotes"\n\u00c9'}))
            assert literal['total'] == 1
            assert result['catalog_revision'] > baseline['catalog_revision']
            stale = unpack(await server.call_tool('list_attack_templates', {'catalog_revision': baseline['catalog_revision'], 'offset': 50}))
            assert stale['code'] == 'catalog_revision_changed'
        finally:
            await repository.close()
    asyncio.run(check())
