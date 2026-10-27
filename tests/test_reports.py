import asyncio
import base64
import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from anticells_red_mcp.catalog.model import import_content
from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.config import MCPConfig
from anticells_red_mcp.mcp_server.engine import AttackResult
from anticells_red_mcp.reports.model import ReportError, new_id, now, render
from anticells_red_mcp.reports.repository import ReportRepository, SessionLock
from anticells_red_mcp.reports.recorder import Recorder
from anticells_red_mcp.reports.runtime import active_run


def result(**kwargs):
    return AttackResult('same-legacy-id', 'injection', 'example', 'prompt', True, .7, **kwargs)


def decoded(response):
    blocks = response.content if hasattr(response, 'content') else response
    return json.loads(blocks[0].text)


async def setup(tmp_path, monkeypatch=None):
    recorder = Recorder(ReportRepository(tmp_path))
    await recorder.start()
    if monkeypatch:
        monkeypatch.setattr(server, '_report_recorder', recorder)
    return recorder


def test_restart_lossless_evidence_statistics_and_exports(tmp_path):
    async def check():
        recorder = await setup(tmp_path)
        run = await recorder.begin('prompt_injection', {}, MCPConfig(), 7)
        unusual = '\ud800\udc00\0\u00e9'
        first = result(response='long reply ' * 1000)
        first.payload = {'unusual': unusual, 'structured': [True, 3]}
        await run.record(first, {'reply': first.response, 'tool_calls': [{'function': {'name': 'test', 'arguments': '{}'}}]})
        await run.record(first)  # Same object, not two results.
        await run.record(result(response='second'))  # Colliding old attack_id still a new result.
        await run.record(AttackResult('x', 'mutation', 'local', 'p', False, 0))
        await run.record(result(metadata={'status': 'skipped'}))
        await run.finish()
        await recorder.close()
        repo = ReportRepository(tmp_path)
        repo.initialize()
        doc = repo.snapshot(run_id=run.data['id'])
        assert len(doc['results']) == 4
        assert len({r['id'] for r in doc['results']}) == 4
        assert doc['statistics']['total_attacks'] == 2
        assert doc['statistics']['local_candidates'] == 1
        assert doc['statistics']['skipped_records'] == 1
        assert doc['runs'][0]['catalog_revision'] == 7
        assert doc['results'][0]['result']['payload']['unusual'] == unusual
        for fmt in ('json', 'markdown', 'html'):
            info = repo.create_export(doc, fmt)
            data = Path(info['path']).read_bytes()
            assert info['sha256'] == hashlib.sha256(data).hexdigest()
            assert len(data) == info['byte_count']
            if fmt == 'json':
                assert import_content(json.loads(data)) == doc
            else:
                assert b'long reply ' * 500 in data
        assert len(repo.list_exports()) == 3
    asyncio.run(check())


def test_failed_writes_recover_once_without_failing_execution(tmp_path, monkeypatch):
    async def check():
        recorder = await setup(tmp_path)
        original = recorder.repository.write
        def broken(events):
            raise ReportError('storage_unavailable')
        monkeypatch.setattr(recorder.repository, 'write', broken)
        run = await recorder.begin('fingerprint_llm', {}, MCPConfig(), 1)
        await run.record(result())
        await run.finish()
        assert run.metadata()['persistence']['status'] == 'pending'
        doc = await recorder.snapshot(run_id=run.data['id'])
        assert len(doc['results']) == 1
        assert doc['persistence']['warning']
        monkeypatch.setattr(recorder.repository, 'write', original)
        await recorder.flush()
        await recorder.flush()
        assert recorder.persistence()['status'] == 'saved'
        assert len(recorder.repository.snapshot(run_id=run.data['id'])['results']) == 1
        await recorder.close()
    asyncio.run(check())


def test_active_exports_are_immutable_and_delete_refuses_active_runs(tmp_path):
    async def check():
        recorder = await setup(tmp_path)
        run = await recorder.begin('endless_attack_loop', {}, MCPConfig(), 1)
        await run.record(result())
        info = await recorder.export('json', run_id=run.data['id'])
        first = Path(info['path']).read_bytes()
        assert json.loads(first)['partial']
        await run.record(result())
        assert Path(info['path']).read_bytes() == first
        with pytest.raises(ReportError, match='active_run'):
            recorder.repository.delete(run_id=run.data['id'])
        await run.finish('stopped')
        unrelated = tmp_path / 'exports' / 'keep.txt'
        unrelated.write_text('keep')
        assert recorder.repository.delete(run_id=run.data['id'])['deleted_runs'] == 1
        assert not Path(info['path']).exists()
        assert unrelated.read_text() == 'keep'
        await recorder.close()
    asyncio.run(check())


def test_live_sessions_and_abandoned_locks(tmp_path):
    async def check():
        first = await setup(tmp_path)
        run = await first.begin('endless_attack_loop', {}, MCPConfig(), 1)
        second = await setup(tmp_path)
        assert second.repository.snapshot(run_id=run.data['id'])['runs'][0]['status'] == 'running'
        # Simulate a crash: OS lease disappears without finalizing the database rows.
        first.task.cancel()
        try:
            await first.task
        except asyncio.CancelledError:
            pass
        first.lease.close()
        first.lease = None
        recovered = second.repository.snapshot(run_id=run.data['id'])
        assert recovered['runs'][0]['status'] == 'interrupted'
        assert recovered['persistence']['status'] == 'incomplete'
        await second.close()
    asyncio.run(check())


def test_chunks_checksums_resources_and_traversal(tmp_path, monkeypatch):
    async def check():
        recorder = await setup(tmp_path, monkeypatch)
        run = await recorder.begin('jailbreak_attack', {}, MCPConfig(), 1)
        await run.record(result(response='x' * 1100000))
        await run.finish()
        info = await recorder.export('json')
        chunks = []
        offset = 0
        while True:
            chunk = recorder.repository.read_export(info['id'], offset)
            chunks.append(base64.b64decode(chunk['data']))
            offset = chunk['next_offset']
            if chunk['eof']:
                break
        assert hashlib.sha256(b''.join(chunks)).hexdigest() == info['sha256']
        with pytest.raises(ReportError, match='resource_too_large'):
            recorder.repository.read_export(info['id'], whole=True)
        with pytest.raises(ReportError, match='invalid_id'):
            recorder.repository.read_export('../../secret')
        with pytest.raises(ReportError, match='invalid_chunk'):
            recorder.repository.read_export(info['id'], length=65537)
        with pytest.raises(ReportError, match='invalid_chunk'):
            recorder.repository.read_export(info['id'], offset=info['byte_count'] + 1)
        assert len((await server.list_report_resources()).resources) == 1
        await recorder.close()
    asyncio.run(check())


@pytest.mark.parametrize('args', [
    {'run_id': 'a', 'session_id': 'b'}, {'action': 'read'}, {'action': 'export', 'format': 'json'},
    {'action': 'list', 'run_id': 'a'}, {'action': 'view', 'export_id': 'a'},
    {'action': 'read', 'export_id': new_id(), 'length': 65537},
])
def test_report_schema_rejects_conflicting_arguments(args):
    assert decoded(asyncio.run(server.call_tool('get_attack_report', args)))['error'] == 'invalid_arguments'


def test_mcp_mutation_fingerprint_capture_full_evidence(tmp_path, monkeypatch):
    from anticells_red_mcp.modules.fingerprint.scanner import FingerprintScanner
    async def check():
        recorder = await setup(tmp_path, monkeypatch)
        async def client(self):
            return httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200,
                json={'choices': [{'message': {'content': 'reply ' * 2000}}]}, request=request)))
        monkeypatch.setattr(FingerprintScanner, '_get_client', client)
        response = decoded(await server.call_tool('fingerprint_llm', {'target_url': 'https://example.invalid/chat?secret=hidden', 'intensity': 1}))
        assert response['persistence']['status'] == 'saved', response
        doc = await recorder.snapshot(run_id=response['run_id'])
        assert len(doc['results']) == 6
        assert all(len(r['evidence']['reply']) == 12000 for r in doc['results'])
        assert '?secret' not in json.dumps(doc)
        mutation = decoded(await server.call_tool('creative_mutation', {'generations': 1}))
        assert mutation['run_id'] != response['run_id']
        local = await recorder.snapshot(run_id=mutation['run_id'])
        assert local['statistics']['total_attacks'] == 0
        assert local['statistics']['local_candidates'] >= 5
        # Legacy current-session report intentionally retains its previous accounting.
        old = decoded(await server.call_tool('get_attack_report', {}))
        assert old['statistics']['total_attacks'] == 0
        exported = await server.call_tool('get_attack_report', {'action': 'export', 'run_id': response['run_id']})
        assert exported[1].type == 'resource_link'
        info = decoded(exported)
        assert (await server.read_report_resource(info['uri']))[0].content
        saved = decoded(await server.call_tool('get_attack_report', {'action': 'list'}))
        assert saved['total'] == 2
        await recorder.close()
    asyncio.run(check())


def test_credentials_and_literal_html_markdown(tmp_path):
    async def check():
        recorder = await setup(tmp_path)
        config = MCPConfig(target_api_key='private-test-value', target_api_url='https://example.invalid/chat?q=hidden')
        run = await recorder.begin('jailbreak_attack', {'target_variables': {'secret': 'omitted'}}, config, 1)
        await run.record(result(response='<script>alert(1)</script>\n```\nprivate-test-value',
                                metadata={'headers': {'Authorization': 'private-test-value'}}))
        await run.finish()
        doc = await recorder.snapshot(run_id=run.data['id'])
        assert 'private-test-value' not in json.dumps(doc)
        assert 'headers' not in doc['results'][0]['result']['metadata']
        html = render(doc, 'html').decode()
        assert '<script>' not in html and '&lt;script&gt;' in html
        markdown = render(doc, 'markdown').decode()
        assert '\n```' not in markdown
        assert 'private-test-value' not in markdown
        await recorder.close()
    asyncio.run(check())


def test_concurrent_calls_isolated(tmp_path, monkeypatch):
    async def check():
        recorder = await setup(tmp_path, monkeypatch)
        outputs = await asyncio.gather(*(server.call_tool('creative_mutation', {'generations': 1}) for _ in range(3)))
        ids = [decoded(x)['run_id'] for x in outputs]
        assert len(set(ids)) == 3
        assert len({decoded(x)['session_id'] for x in outputs}) == 1
        for rid in ids:
            doc = await recorder.snapshot(run_id=rid)
            assert all(r['run_id'] == rid for r in doc['results'])
        await recorder.close()
    asyncio.run(check())


def test_actual_injection_and_tool_transport_are_recorded(tmp_path, monkeypatch):
    from anticells_red_mcp.modules.injection.direct import InjectionEngine
    from anticells_red_mcp.modules.tool_abuse.exploit import ToolAbuseEngine
    original = httpx.AsyncClient
    technique = ToolAbuseEngine(MCPConfig()).get_techniques()[0]
    text = 'normalized full reply ' * 1000
    def reply(request):
        return httpx.Response(200, json={'result': {'answer': text, 'actions': [
            {'name': technique['tool_name'], 'arguments': technique['payload']['arguments']}]}})
    def client(*args, **kwargs):
        kwargs['transport'] = httpx.MockTransport(reply)
        return original(*args, **kwargs)
    monkeypatch.setattr(httpx, 'AsyncClient', client)
    injection_get = InjectionEngine.get_techniques
    monkeypatch.setattr(InjectionEngine, 'get_techniques', lambda self: injection_get(self)[:1])
    definition = {'url': 'https://example.invalid/chat', 'headers': {'Authorization': 'Bearer fixture-secret'},
                  'body': {'question': '${request.prompt}', 'private': 'never-archive-the-rendered-body'},
                  'response': {'text': '/result/answer', 'tool_calls': {
                      'path': '/result/actions', 'name': '/name', 'arguments': '/arguments'}}}
    async def check():
        recorder = await setup(tmp_path, monkeypatch)
        injection = decoded(await server.call_tool('prompt_injection', {'target': definition, 'payload_override': 'actual injection'}))
        doc = await recorder.snapshot(run_id=injection['run_id'])
        assert doc['results'][0]['evidence']['prompt'] == 'actual injection'
        assert doc['results'][0]['evidence']['messages'][0]['content'] == 'actual injection'
        assert doc['results'][0]['evidence']['reply'] == text
        assert 'never-archive-the-rendered-body' not in json.dumps(doc)
        assert 'fixture-secret' not in json.dumps(doc)
        tool = decoded(await server.call_tool('tool_abuse_exploit', {'target': definition}))
        doc = await recorder.snapshot(run_id=tool['run_id'])
        assert len(doc['results']) == tool['total_attempts']
        assert doc['results'][0]['evidence']['reply'] == text
        assert doc['results'][0]['evidence']['tool_calls'][0]['function']['name'] == technique['tool_name']
        assert isinstance(doc['results'][0]['evidence']['technique_payload'], dict)
        assert doc['results'][0]['evidence']['tools']
        # Custom text-only responses skip all scenarios, with no target attempts.
        definition['response'].pop('tool_calls')
        skipped = decoded(await server.call_tool('tool_abuse_exploit', {'target': definition}))
        doc = await recorder.snapshot(run_id=skipped['run_id'])
        assert doc['statistics']['skipped_records'] == 35
        assert doc['statistics']['total_attacks'] == 0
        # Configuration errors remain run errors without model-attempt evidence.
        definition['body']['missing'] = '${vars.missing}'
        failure = decoded(await server.call_tool('prompt_injection', {'target': definition}))
        assert failure['error'] == 'target_configuration_error'
        doc = await recorder.snapshot(run_id=failure['run_id'])
        assert doc['runs'][0]['status'] == 'failed'
        assert doc['statistics']['total_attacks'] == 0
        await recorder.close()
    asyncio.run(check())


def test_background_cancel_keeps_one_run_and_records_once(tmp_path, monkeypatch):
    from anticells_red_mcp.mcp_server.relentless_loop import RelentlessLoop
    async def check():
        recorder = await setup(tmp_path, monkeypatch)
        reached = asyncio.Event()
        async def run(self):
            await active_run.get().record(result(response='background'))
            reached.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(RelentlessLoop, 'run', run)
        started = decoded(await server.call_tool('endless_attack_loop', {'target_url': 'https://example.invalid/chat'}))
        await reached.wait()
        await server.call_tool('stop_attack_loop', {})
        doc = await recorder.snapshot(run_id=started['run_id'])
        assert doc['runs'][0]['status'] == 'stopped'
        assert len(doc['results']) == 1
        reached.clear()
        second = decoded(await server.call_tool('endless_attack_loop', {'target_url': 'https://example.invalid/chat'}))
        await reached.wait()
        await server.call_tool('stop_attack_loop', {})
        assert second['run_id'] != started['run_id']
        assert len((await recorder.snapshot(session_id=started['session_id']))['results']) == 2
        await recorder.close()
    asyncio.run(check())


def test_cli_and_move_directory_without_catalog(tmp_path, monkeypatch, capsys):
    from anticells_red_mcp.reports.cli import main
    async def create():
        recorder = await setup(tmp_path / 'source')
        run = await recorder.begin('creative_mutation', {}, MCPConfig(), 1)
        await run.record(result())
        await run.finish()
        info = await recorder.export('html')
        await recorder.close()
        return run.data['id'], info['id']
    rid, eid = asyncio.run(create())
    # Backup relocation reconstructs paths, rather than trusting stored absolute paths.
    import shutil
    shutil.copytree(tmp_path / 'source', tmp_path / 'restored')
    moved = ReportRepository(tmp_path / 'restored')
    assert str(tmp_path / 'restored') in moved.export_info(eid)['path']
    monkeypatch.setenv('ANTICELLS_RED_MCP_DATABASE_PATH', str(tmp_path / 'missing-catalog'))
    monkeypatch.delenv('ANTICELLS_RED_MCP_ENV_FILE', raising=False)
    prefix = ['--reports-dir', str(tmp_path / 'restored')]
    assert main(prefix + ['list']) == 0
    assert json.loads(capsys.readouterr().out)['total'] == 1
    output = tmp_path / 'copied.json'
    assert main(prefix + ['export', '--run-id', rid, '--output', str(output)]) == 0
    assert output.exists()
    capsys.readouterr()
    assert main(prefix + ['export', '--run-id', rid, '--output', str(output)]) == 2
    assert 'output_exists' in capsys.readouterr().err
    assert main(prefix + ['delete', '--run-id', rid]) == 0
    assert moved.list_runs()['total'] == 0


def test_export_registration_failure_never_claims_or_leaves_file(tmp_path, monkeypatch):
    async def check():
        recorder = await setup(tmp_path)
        run = await recorder.begin('creative_mutation', {}, MCPConfig(), 1)
        await run.finish()
        doc = await recorder.snapshot(run_id=run.data['id'])
        from contextlib import contextmanager
        @contextmanager
        def broken(*args, **kwargs):
            raise ReportError('storage_unavailable')
            yield
        with monkeypatch.context() as patch:
            patch.setattr(recorder.repository, 'connection', broken)
            with pytest.raises(ReportError, match='export_failed'):
                recorder.repository.create_export(doc, 'json')
        assert list((tmp_path / 'exports').iterdir()) == []
        await recorder.close()
    asyncio.run(check())


def test_multiple_processes_keep_sessions_live_and_isolated(tmp_path):
    import subprocess
    import sys
    import os
    script = '''
import asyncio, sys
from anticells_red_mcp.reports.repository import ReportRepository
from anticells_red_mcp.reports.recorder import Recorder
from anticells_red_mcp.mcp_server.config import MCPConfig
async def main():
    recorder = Recorder(ReportRepository(sys.argv[1]))
    await recorder.start()
    run = await recorder.begin('creative_mutation', {}, MCPConfig(), 1)
    await run.record({'module': 'mutation', 'payload': 'child', 'success': False})
    print(run.data['id'], flush=True)
    await asyncio.to_thread(sys.stdin.readline)
    await run.finish()
    await recorder.close()
asyncio.run(main())
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    processes = [subprocess.Popen([sys.executable, '-c', script, str(tmp_path)], stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env) for _ in range(2)]
    try:
        ids = [p.stdout.readline().strip() for p in processes]
        assert len(set(ids)) == 2
        repo = ReportRepository(tmp_path)
        assert all(r['status'] == 'running' for r in repo.list_runs()['runs'])
        for process in processes:
            out, err = process.communicate('\n', timeout=15)
            assert process.returncode == 0, err
        assert len(repo.list_runs()['runs']) == 2
        assert all(repo.snapshot(run_id=rid)['statistics']['total_records'] == 1 for rid in ids)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def test_initial_storage_failure_testing_continues_and_shutdown_flushes(tmp_path, monkeypatch):
    root = tmp_path / 'blocked'
    root.write_text('not a directory')
    async def check():
        recorder = await setup(root, monkeypatch)
        response = decoded(await server.call_tool('creative_mutation', {'generations': 1}))
        assert response['techniques_generated'] == 5
        assert response['persistence']['status'] == 'pending'
        assert response['persistence']['pending_records'] == 10
        root.unlink()
        await recorder.close()
        saved = recorder.repository.snapshot(run_id=response['run_id'])
        assert len(saved['results']) == 10
        assert recorder.persistence()['status'] == 'saved'
    asyncio.run(check())


def test_export_name_collision_and_symlinks_leave_unrelated_files(tmp_path, monkeypatch):
    import os
    async def check():
        recorder = await setup(tmp_path)
        run = await recorder.begin('creative_mutation', {}, MCPConfig(), 1)
        await run.finish()
        doc = await recorder.snapshot(run_id=run.data['id'])
        info = recorder.repository.create_export(doc, 'json')
        content = Path(info['path']).read_bytes()
        with monkeypatch.context() as patch:
            patch.setattr('anticells_red_mcp.reports.repository.new_id', lambda: info['id'])
            with pytest.raises(ReportError, match='export_failed'):
                recorder.repository.create_export(doc, 'json')
        assert Path(info['path']).read_bytes() == content
        if os.name != 'nt':
            assert recorder.repository.path.stat().st_mode & 0o777 == 0o600
            outside = tmp_path / 'unrelated'
            outside.write_text('private')
            Path(info['path']).unlink()
            Path(info['path']).symlink_to(outside)
            with pytest.raises(ReportError, match='invalid_export_path'):
                recorder.repository.delete(run_id=run.data['id'])
            assert outside.read_text() == 'private'
            assert recorder.repository.list_runs()['total'] == 1
        await recorder.close()
    asyncio.run(check())


def test_short_credentials_do_not_change_record_identity(tmp_path):
    async def check():
        recorder = await setup(tmp_path)
        run = await recorder.begin('creative_mutation', {}, MCPConfig(target_api_key='a'), 1)
        await run.record(result(response='a'))
        await run.finish()
        doc = await recorder.snapshot(run_id=run.data['id'])
        assert doc['results'][0]['run_id'] == run.data['id']
        assert doc['results'][0]['result']['response'] == '[REDACTED]'
        await recorder.close()
    asyncio.run(check())


def test_legacy_tool_reply_fallback_is_not_truncated():
    from anticells_red_mcp.reports.runtime import active_attempt, capture_response
    evidence = {}
    token = active_attempt.set(evidence)
    try:
        capture_response(httpx.Response(200, json={
            'choices': [{'message': {'content': None, 'function_call': {'name': 'example', 'arguments': '{}'}}}],
            'response': 'complete fallback ' * 1000}), MCPConfig())
        assert evidence['reply'] == 'complete fallback ' * 1000
        assert evidence['function_call']['name'] == 'example'
    finally:
        active_attempt.reset(token)
