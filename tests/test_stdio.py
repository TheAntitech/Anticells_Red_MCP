import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]


def test_real_mcp_launch_from_another_directory(tmp_path):
    # Verify first-launch migration/seeding without any database configuration.
    state_dir = str(tmp_path / 'new-state')
    async def check():
        params = StdioServerParameters(
            command=sys.executable if os.name == 'nt' else 'bash',
            args=['-m', 'anticells_red_mcp.mcp_server.server'] if os.name == 'nt' else [str(ROOT / 'run.sh')],
            env={'ANTICELLS_RED_MCP_PYTHON': sys.executable,
                 'PYTHONPATH': str(ROOT / 'src'),
                 'ANTICELLS_RED_MCP_STATE_DIR': state_dir,
                 'ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS': 'true',
                 'ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION': 'true',
                 'ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL': '0'}, cwd=str(tmp_path),
        )
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=10)) as client:
                initialized = await client.initialize()
                assert initialized.serverInfo.name == 'anticells_red_mcp'
                assert initialized.serverInfo.version == '1.1.0'
                assert 'anticells_red_mcp' in initialized.instructions
                tools = await client.list_tools()
                assert len(tools.tools) == 12
                discovery = next(t for t in tools.tools if t.name == 'list_attack_templates')
                assert discovery.annotations.readOnlyHint
                templates = await client.call_tool('list_attack_templates', {
                    'module': 'injection', 'limit': 2, 'include_content': True})
                assert not templates.isError
                page = json.loads(templates.content[0].text)
                assert page['total'] == 53 and page['returned'] == 2
                assert page['templates'][0]['content']['payload']
                compatibility = next(t for t in tools.tools if t.name == 'get_compatible_templates')
                assert compatibility.annotations.readOnlyHint
                compatible = await client.call_tool('get_compatible_templates', {
                    'target': {'url': 'https://never-contact.invalid/chat', 'response': {'text': '/answer'}},
                    'module': 'tool_abuse', 'include_incompatible': True, 'include_content': True,
                })
                assert not compatible.isError
                checked = json.loads(compatible.content[0].text)
                assert checked['total'] == checked['incompatible_total'] == 35
                assert checked['compatible_total'] == 0 and not checked['target_contacted']
                assert checked['templates'][0]['content']['payload']
                assert checked['templates'][0]['compatibility']['reason'] == 'target_has_no_tool_call_mapping'
                saved = await client.call_tool('get_attack_report', {'action': 'list'})
                assert json.loads(saved.content[0].text)['total'] == 0
                report = await client.call_tool('get_attack_report', {'format': 'summary'})
                assert not report.isError
                assert json.loads(report.content[0].text)['statistics']['total_attacks'] == 0
                bad = await client.call_tool('creative_mutation', {'generations': -1})
                assert bad.isError
                mutation = await client.call_tool('creative_mutation', {'generations': 1})
                assert not mutation.isError
                assert json.loads(mutation.content[0].text)['techniques_generated'] > 0
                run_id = json.loads(mutation.content[0].text)['run_id']
                listing = await client.call_tool('get_attack_report', {'action': 'list'})
                assert json.loads(listing.content[0].text)['total'] == 1
                exported = await client.call_tool('get_attack_report', {
                    'action': 'export', 'run_id': run_id, 'export_format': 'markdown'})
                assert not exported.isError
                metadata = json.loads(exported.content[0].text)
                assert exported.content[1].type == 'resource_link'
                resources = await client.list_resources()
                assert len(resources.resources) == 1
                contents = await client.read_resource(metadata['uri'])
                assert contents.contents[0].mimeType == 'text/markdown'
                chunk = await client.call_tool('get_attack_report', {
                    'action': 'read', 'export_id': metadata['export_id'], 'length': 100})
                assert json.loads(chunk.content[0].text)['next_offset'] == 100
                stopped = await client.call_tool('stop_attack_loop', {})
                assert not stopped.isError
                local_templates = await client.call_tool('list_attack_templates', {'module': 'mutation', 'limit': 1})
                local_id = json.loads(local_templates.content[0].text)['templates'][0]['id']
                single = await client.call_tool('execute_attack_template', {'template_id': local_id})
                assert not single.isError
                single_result = json.loads(single.content[0].text)
                assert single_result['statistics']['local_candidates'] == 1
                assert single_result['total_attempts'] == 0 and single_result['target'] == 'local'
                saved_single = await client.call_tool('get_attack_report', {
                    'action': 'view', 'run_id': single_result['run_id'], 'format': 'detailed'})
                single_doc = json.loads(saved_single.content[0].text)
                assert len(single_doc['results']) == 1
                assert single_doc['runs'][0]['template']['id'] == local_id
    asyncio.run(check())


def test_all_tools_through_real_mcp_with_mock_http(tmp_path, catalog_path):
    bootstrap = '''
import httpx
import json
from anticells_red_mcp.mcp_server.server import main
original = httpx.AsyncClient

def fixture_reply(request):
    body = json.loads(request.content)
    if 'question' in body:
        assert request.headers['authorization'] == 'Bearer custom-fixture-credential'
        assert body['workspace'] in ('staging', 'inline')
        assert isinstance(body['question'], str)
        return httpx.Response(200, json={'result': {'answer': ''}})
    assert request.headers['authorization'] == 'Bearer fixture-credential'
    return httpx.Response(200, json={'choices': [{'message': {'content': ''}}]})

def fixture_client(*args, **kwargs):
    kwargs['transport'] = httpx.MockTransport(fixture_reply)
    return original(*args, **kwargs)

httpx.AsyncClient = fixture_client
main()
'''
    (tmp_path / 'custom.env').write_text('CUSTOM_API_KEY=custom-fixture-credential\n', encoding='utf-8')
    definition = {'url': 'https://example.invalid/chat',
                  'headers': {'Authorization': 'Bearer ${env.CUSTOM_API_KEY}'},
                  'variables': {'workspace': 'research'},
                  'body': {'question': '${request.prompt}', 'workspace': '${vars.workspace}'},
                  'response': {'text': '/result/answer'}}
    profiles = tmp_path / 'targets.json'
    profiles.write_text(json.dumps({'env_files': ['custom.env'], 'targets': {'custom': definition}}), encoding='utf-8')
    async def check():
        params = StdioServerParameters(
            command=sys.executable, args=['-c', bootstrap], cwd=str(tmp_path),
            env={'PYTHONPATH': str(ROOT / 'src'), 'ANTICELLS_RED_MCP_DATABASE_PATH': catalog_path,
                 'ANTICELLS_RED_MCP_REPORTS_DIR': str(tmp_path / 'reports'),
                 'ANTICELLS_RED_MCP_TARGET_MODEL': 'fixture-model',
                 'ANTICELLS_RED_MCP_TARGET_API_KEY': 'fixture-credential',
                 'ANTICELLS_RED_MCP_TARGETS_FILE': str(profiles),
                 'ANTICELLS_RED_MCP_TARGET_API_URL': 'https://example.invalid/chat',
                 # 1.1.0 egress policy opt-ins for the stdio fixture.
                 'ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS': 'true',
                 'ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION': 'true',
                 'ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL': '0',
                 'ANTICELLS_RED_MCP_TEMPLATE_ENV': 'CUSTOM_API_KEY'},
        )
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=10)) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert len(tools.tools) == 12
                async def call(name, args):
                    reply = await client.call_tool(name, args)
                    assert not reply.isError, name
                    return json.loads(reply.content[0].text)
                selected = await call('list_attack_templates', {'module': 'injection', 'limit': 1})
                selected_id = selected['templates'][0]['id']
                single = await call('execute_attack_template', {
                    'template_id': selected_id, 'catalog_revision': selected['catalog_revision'],
                    'target': 'custom', 'target_variables': {'workspace': 'staging'},
                })
                assert single['total_attempts'] == 1 and len(single['results']) == 1
                assert single['successful'] == 0
                single_doc = await call('get_attack_report', {
                    'action': 'view', 'run_id': single['run_id'], 'format': 'detailed'})
                assert len(single_doc['results']) == 1
                assert single_doc['runs'][0]['template']['id'] == selected_id
                fingerprint_templates = await call('list_attack_templates', {'module': 'fingerprint', 'limit': 1})
                profile_result = await call('get_fingerprint_profile', {
                    'target': 'custom', 'target_variables': {'workspace': 'staging'},
                    'template_ids': [fingerprint_templates['templates'][0]['id']],
                })
                assert profile_result['profile']['coverage']['attempted'] == 1
                assert profile_result['profile']['status'] == 'no_usable_responses'
                profile_doc = await call('get_attack_report', {'run_id': profile_result['run_id']})
                assert profile_doc['runs'][0]['fingerprint_profile'] == profile_result['profile']
                fingerprint = await call('fingerprint_llm', {
                    'target_url': 'https://example.invalid/chat', 'intensity': 1,
                    'techniques': ['direct_identity_query'],
                })
                assert fingerprint['confidence'] == 0
                custom = await call('fingerprint_llm', {
                    'target': 'custom', 'target_variables': {'workspace': 'staging'},
                    'techniques': ['direct_identity_query'], 'intensity': 1,
                })
                assert custom['confidence'] == 0 and custom['target'] == 'custom'
                # 1.1.0: ${env.*} is only honored on saved profiles. The
                # same ``custom`` profile exercised above now covers this.
                saved_injection = await call('prompt_injection', {
                    'target': 'custom', 'target_variables': {'workspace': 'inline'},
                    'payload_override': 'fixture payload', 'injection_type': 'multi_stage',
                })
                assert saved_injection['successful'] == 0 and saved_injection['target'] == 'custom'
                jailbreak = await call('jailbreak_attack', {
                    'target_url': 'https://example.invalid/chat', 'category': 'psychological', 'intensity': 1,
                })
                assert jailbreak['successful_attacks'] == 0
                injection = await call('prompt_injection', {
                    'target_url': 'https://example.invalid/chat', 'injection_type': 'multi_stage',
                    'payload_override': 'fixture',
                })
                assert injection['successful'] == 0
                proposed_tools = await call('tool_abuse_exploit', {
                    'target_url': 'https://example.invalid/chat', 'available_tools': [{
                        'type': 'function', 'function': {'name': 'fixture_only',
                            'parameters': {'type': 'object', 'properties': {}}},
                    }],
                })
                assert proposed_tools['total_attempts'] == 0 and proposed_tools['skipped'] == 35
                await call('creative_mutation', {'generations': 1})
                await call('endless_attack_loop', {
                    'target_url': 'https://example.invalid/chat', 'mode': 'infinite', 'max_iterations': 1,
                })
                # A full catalog cycle persists hundreds of records. Bound the
                # elapsed time instead of assuming 100 rapid polls suffice on
                # every filesystem/CI host; still require the loop to finish.
                deadline = asyncio.get_running_loop().time() + 120
                while asyncio.get_running_loop().time() < deadline:
                    report = await call('get_attack_report', {})
                    if not report['loop_running']:
                        break
                    await asyncio.sleep(.1)
                else:
                    raise AssertionError(f"finite fixture loop did not finish: {report['statistics']}")
                assert report['statistics']['local_candidates'] == 3
                assert report['statistics']['skipped_records'] == 35
                assert report['statistics']['successful_attacks'] == 0
                await call('stop_attack_loop', {})
    asyncio.run(check())
