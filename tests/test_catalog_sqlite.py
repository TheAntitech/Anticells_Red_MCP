import asyncio
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock

import httpx
import sqlite3
from contextlib import closing
from pathlib import Path
import pytest

from anticells_red_mcp.catalog import CatalogError, bootstrap
from anticells_red_mcp.catalog.cli import parser, run, seed_document
from anticells_red_mcp.catalog.model import encode, import_content
from anticells_red_mcp.catalog.repository import CatalogRepository, migrate, publish, read_sync
from anticells_red_mcp.catalog.runtime import active_snapshot
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.config import MCPConfig


def document(*records):
    return {'format_version': 1, 'records': list(records)}


def new_record(snapshot, name='database_fixture'):
    record = next(r for r in snapshot.records() if r['namespace'] == 'injection.direct' and r['kind'] == 'technique')
    for key in ('position', 'revision'):
        record.pop(key, None)
    record['id'] = 'custom/' + name
    record['content']['name'] = name
    record['content']['payload'] = 'Literal database fixture ${env.DO_NOT_EXPAND} {value0}'
    return record


def test_real_storage_exact_content_migrations_and_idempotent_seed(catalog_path, seed_snapshot):
    assert migrate(catalog_path) == 1
    assert publish(catalog_path, seed_document(), seed=True) == {'revision': 1, 'changed': 0}
    loaded = read_sync(catalog_path)
    for expected, actual in zip(seed_snapshot.records(), loaded.records(), strict=True):
        actual.pop('revision')
        if 'memberships' not in expected: actual.pop('memberships')
        assert encode(actual) == encode(expected)
    with closing(sqlite3.connect(catalog_path)) as conn, conn:
        assert conn.execute("SELECT typeof(content) FROM catalog_records LIMIT 1").fetchone()[0] == 'blob'
    changed = loaded.records()[0]
    changed['enabled'] = False
    if changed['kind'] != 'technique':
        changed = next(r for r in loaded.records() if r['kind'] == 'technique')
        changed['enabled'] = False
    publish(catalog_path, document(changed), update=True)
    assert publish(catalog_path, seed_document(), seed=True)['changed'] == 0
    assert next(r for r in read_sync(catalog_path).records() if r['id'] == changed['id'])['enabled'] is False


def test_atomic_additions_stale_updates_and_positions(catalog_path):
    initial = read_sync(catalog_path)
    new = new_record(initial)
    assert publish(catalog_path, document(new)) == {'revision': 2, 'changed': 1}
    current = next(r for r in read_sync(catalog_path).records() if r['id'] == new['id'])
    assert current['position'] == len(initial.techniques('injection.direct'))
    updated = copy.deepcopy(current)
    updated['content']['payload'] = 'Edited fixture'
    with pytest.raises(CatalogError, match='update_requires_flag'):
        publish(catalog_path, document(updated))
    publish(catalog_path, document(updated), update=True)
    with pytest.raises(CatalogError, match='stale_update'):
        publish(catalog_path, document(new_record(initial, 'rolled_back'), current), update=True)
    assert not any(r['id'] == 'custom/rolled_back' for r in read_sync(catalog_path).records())
    final = next(r for r in read_sync(catalog_path).records() if r['id'] == new['id'])
    assert final['position'] == current['position']
    assert final['content']['payload'] == 'Edited fixture'


def test_publication_rejects_empty_required_catalog_and_disabled_templates(catalog_path):
    initial = read_sync(catalog_path)
    records = [r for r in initial.records() if r['namespace'] == 'injection.direct' and r['kind'] == 'technique']
    for r in records: r['enabled'] = False
    with pytest.raises(CatalogError, match='empty_required_catalog'):
        publish(catalog_path, document(*records), update=True)
    template = next(r for r in initial.records() if r['kind'] == 'template')
    template['enabled'] = False
    with pytest.raises(CatalogError, match='invalid_asset'):
        publish(catalog_path, document(template), update=True)
    assert read_sync(catalog_path).revision == 1


def test_concurrent_publication_serializes_revisions_and_rejects_stale_writers(catalog_path):
    initial = read_sync(catalog_path)
    records = [new_record(initial, f'writer_{i}') for i in range(4)]
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(lambda r: publish(catalog_path, document(r)), records))
    assert sorted(r['revision'] for r in results) == [2, 3, 4, 5]
    current = next(r for r in read_sync(catalog_path).records() if r['id'] == records[0]['id'])
    def update():
        try: return publish(catalog_path, document(current), update=True)
        except CatalogError as exc: return exc.code
    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(lambda _: update(), range(2)))
    assert outcomes.count('stale_update') == 1
    assert read_sync(catalog_path).revision == 6


def test_async_cache_snapshot_refresh_and_cleanup(catalog_path):
    async def check():
        repository = CatalogRepository(catalog_path)
        try:
            original = await repository.snapshot()
            assert await repository.snapshot() is original
            publish(catalog_path, document(new_record(original)))
            changed = await repository.snapshot()
            assert changed.revision == 2
            assert len(changed.techniques('injection.direct')) == len(original.techniques('injection.direct')) + 1
            assert await repository.snapshot() is changed
            assert original.revision == 1
        finally:
            await repository.close()
            assert repository._snapshot is None
    asyncio.run(check())


def test_cancelled_load_finishes_connection_cleanup_before_close(catalog_path, monkeypatch):
    from threading import Event
    from anticells_red_mcp.catalog import repository as module
    entered, release, finished = Event(), Event(), Event()
    original = module.read_sync
    def blocked(*args):
        entered.set()
        assert release.wait(5)
        try:
            return original(*args)
        finally:
            finished.set()
    monkeypatch.setattr(module, 'read_sync', blocked)
    async def check():
        repository = CatalogRepository(catalog_path)
        task = asyncio.create_task(repository.snapshot())
        try:
            async def wait_for_worker():
                while not entered.is_set():
                    await asyncio.sleep(.01)
            await asyncio.wait_for(wait_for_worker(), 3)
            task.cancel()
            closing = asyncio.create_task(repository.close())
            await asyncio.sleep(.01)
            assert not closing.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            await closing
            assert finished.is_set() and repository._snapshot is None
        finally:
            release.set()
    asyncio.run(check())


def test_imported_technique_runs_next_mcp_call_without_restart(catalog_path, monkeypatch):
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, '_catalog_repository', repository)
    seen = []
    original = httpx.AsyncClient
    def reply(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={'choices': [{'message': {'content': 'I cannot comply'}}]})
    def client(*args, **kwargs):
        kwargs['transport'] = httpx.MockTransport(reply)
        return original(*args, **kwargs)
    monkeypatch.setattr(httpx, 'AsyncClient', client)
    async def check():
        try:
            initial = await repository.snapshot()
            record = new_record(initial)
            publish(catalog_path, document(record))
            result = await server.call_tool('prompt_injection', {
                'target_url': 'https://example.invalid/chat', 'injection_type': record['memberships'][0]})
            assert isinstance(result, list)
            results = json.loads(result[0].text)['results']
            assert any(r['technique'] == record['content']['name'] for r in results)
            assert any(any(m['content'] == record['content']['payload'] for m in body['messages']) for body in seen)
        finally:
            await repository.close()
    asyncio.run(check())


def test_outage_blocks_new_calls_but_pinned_loop_and_reports_continue(catalog_path, monkeypatch):
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, '_catalog_repository', repository)
    from anticells_red_mcp.mcp_server.relentless_loop import RelentlessLoop
    async def check():
        started, finish = asyncio.Event(), asyncio.Event()
        observed = []
        async def loop(self):
            selected = self.config.catalog_snapshot
            started.set()
            await finish.wait()
            observed.append((selected.revision, len(selected.techniques('injection.direct'))))
        monkeypatch.setattr(RelentlessLoop, 'run', loop)
        try:
            reply = await server.call_tool('endless_attack_loop', {'target_url': 'https://example.invalid/chat', 'max_iterations': 1})
            assert isinstance(reply, list)
            await started.wait()
            initial = await repository.snapshot()
            publish(catalog_path, document(new_record(initial)))
            assert (await repository.snapshot()).revision == 2
            with closing(sqlite3.connect(catalog_path)) as conn, conn:
                conn.execute('DROP TABLE catalog_state')
            failed = await server.call_tool('creative_mutation', {'generations': 1})
            assert failed.isError
            assert json.loads(failed.content[0].text)['error'] == 'catalog_error'
            finish.set()
            await server._loop_task
            assert observed == [(1, len(initial.techniques('injection.direct')))]
            assert isinstance(await server.call_tool('get_attack_report', {}), list)
            assert isinstance(await server.call_tool('stop_attack_loop', {}), list)
        finally:
            finish.set()
            await repository.close()
    asyncio.run(check())


def test_invalid_database_contents_schema_and_partial_initialization(catalog_path):
    with closing(sqlite3.connect(catalog_path)) as conn, conn:
        conn.execute('INSERT INTO catalog_schema_migrations(version) VALUES (999)')
    with pytest.raises(CatalogError, match='incompatible_schema'): read_sync(catalog_path)
    with pytest.raises(CatalogError, match='incompatible_schema'): migrate(catalog_path)
    with closing(sqlite3.connect(catalog_path)) as conn, conn:
        conn.execute('DELETE FROM catalog_schema_migrations WHERE version=999')
        conn.execute("DELETE FROM catalog_records WHERE kind='template'")
    with pytest.raises(CatalogError, match='missing_required_asset'): read_sync(catalog_path)
    with closing(sqlite3.connect(catalog_path)) as conn, conn:
        conn.execute('DELETE FROM catalog_records')
    with pytest.raises(CatalogError): publish(catalog_path, document(new_record_from_seed()))


def new_record_from_seed():
    from anticells_red_mcp.catalog import CatalogSnapshot
    return new_record(CatalogSnapshot.build(1, seed_document()['records']))


def test_standalone_sync_and_async_bootstrap_use_database(catalog_path, monkeypatch):
    from anticells_red_mcp.modules.injection.indirect import IndirectInjectionEngine
    token = active_snapshot.set(None)
    monkeypatch.setenv('ANTICELLS_RED_MCP_DATABASE_PATH', catalog_path)
    try:
        module = IndirectInjectionEngine()
        assert module._catalog.revision == 1
        config = MCPConfig(database_path=catalog_path)
        snapshot = asyncio.run(bootstrap(config))
        assert IndirectInjectionEngine(config)._catalog is snapshot
    finally:
        active_snapshot.reset(token)


def test_cli_edit_export_disable_and_enable(catalog_path, monkeypatch, tmp_path):
    monkeypatch.setenv('ANTICELLS_RED_MCP_DATABASE_PATH', catalog_path)
    def command(*args): return run(parser().parse_args(list(args)))
    path = str(tmp_path / 'new.json')
    command('new', '--namespace', 'injection.direct', '--output', path)
    assert command('validate', path)['valid']
    assert command('import', path)['revision'] == 2
    record_id = json.loads(open(path, encoding='utf-8').read())['records'][0]['id']
    assert command('show', record_id)['revision'] == 2
    command('disable', record_id, '--revision', '2')
    assert not command('show', record_id)['enabled']
    command('enable', record_id, '--revision', '3')
    assert command('show', record_id)['enabled']
    command('export', '--output', path)
    assert command('validate', path)['records'] == 497
    assert command('import', path, '--update')['changed'] == 497
    template = next(r for r in read_sync(catalog_path).records() if r['kind'] == 'template')
    command('new', '--template', template['id'], '--output', path)
    assert command('import', path, '--update')['changed'] == 1


def test_connection_failure_redacts_paths_and_content(tmp_path, caplog):
    bad_path = str(tmp_path / 'private-directory' / 'catalog.sqlite3')
    with pytest.raises(CatalogError) as error:
        read_sync(bad_path)
    assert 'private-directory' not in str(error.value)
    async def check():
        repository = CatalogRepository(bad_path)
        with pytest.raises(CatalogError, match='database_unavailable'):
            await repository.snapshot()
        assert repository._snapshot is None
        await repository.close()
    asyncio.run(check())
    assert bad_path not in caplog.text
    assert not Path(bad_path).exists()


def test_server_keeps_reports_available_and_closes_invalid_catalog(catalog_path, tmp_path, monkeypatch):
    with closing(sqlite3.connect(catalog_path)) as conn, conn:
        conn.execute('DELETE FROM catalog_records')
    repository = CatalogRepository(catalog_path)
    monkeypatch.setattr(server, 'load_config', lambda: MCPConfig(database_path=catalog_path, catalog_auto_setup=False, reports_dir=str(tmp_path / 'reports')))
    monkeypatch.setattr(server, 'CatalogRepository', lambda url: repository)
    close = repository.close
    closed = []
    async def close_and_record():
        await close()
        closed.append(True)
    monkeypatch.setattr(repository, 'close', close_and_record)
    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def stdio():
        yield None, None
    async def run(*args):
        reply = await server.call_tool('get_attack_report', {'action': 'list'})
        assert json.loads(reply[0].text)['total'] == 0
        failure = await server.call_tool('creative_mutation', {'generations': 1})
        assert json.loads(failure.content[0].text)['error'] == 'catalog_error'
    monkeypatch.setattr(server, 'stdio_server', stdio)
    monkeypatch.setattr(server._server, 'run', run)
    asyncio.run(server.serve())
    assert closed and repository._snapshot is None


def test_automatic_initialization_is_concurrent_and_preserves_edits(tmp_path):
    from anticells_red_mcp.catalog.setup import prepare_database
    catalog_path = str(tmp_path / 'new' / 'catalog.sqlite3')
    def start(_):
        return prepare_database(MCPConfig(database_path=catalog_path))
    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(start, range(3)))
    assert sorted(r['changed'] for r in results) == [0, 0, 496]
    snapshot = read_sync(catalog_path)
    assert snapshot.revision == 1
    record = next(r for r in snapshot.records() if r['kind'] == 'technique' and 'content' in r)
    record['content']['payload'] = 'An operator edit that automatic setup must preserve.'
    publish(catalog_path, document(record), update=True)
    assert start(None) == {'schema_version': 1, 'revision': 2, 'changed': 0}
    actual = next(r for r in read_sync(catalog_path).records() if r['id'] == record['id'])
    assert actual['content']['payload'] == record['content']['payload']
