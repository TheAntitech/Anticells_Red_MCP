"""Configurable requests: mocked HTTP only, no live targets or tool execution."""
import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json

import httpx
import pytest
from jsonschema import Draft202012Validator

from anticells_red_mcp.mcp_server import server
from anticells_red_mcp.mcp_server.config import MCPConfig, load_config
from anticells_red_mcp.mcp_server.targets import (
    TargetConfigurationError, load_target_sources, resolve_target,
)
from anticells_red_mcp.modules.fingerprint.scanner import FingerprintScanner
from anticells_red_mcp.modules.injection.direct import InjectionEngine
from anticells_red_mcp.modules.jailbreaks.engine import JailbreakEngine
from anticells_red_mcp.modules.mutation.creative_engine import CreativeMutationEngine
from anticells_red_mcp.modules.tool_abuse.exploit import ToolAbuseEngine
from anticells_red_mcp.modules.utils.chat_endpoint import (
    make_chat_client, normalize_response, post_chat, response_text,
)


URL = 'https://gateway.example/chat'
SECRET = 'private-fixture-credential'
TEXT_MAPPING = {'text': '/result/answer'}
TOOL_MAPPING = {'text': '/result/answer', 'tool_calls': {
    'path': '/result/actions', 'name': '/name', 'arguments': '/arguments',
}}
TOOL_SCHEMA = {'type': 'function', 'function': {'name': 'fixture_tool', 'parameters': {
    'type': 'object', 'properties': {'label': {'type': 'string'}},
    'required': ['label'], 'additionalProperties': False,
}}}
TOOL_TECHNIQUE = {'name': 'fixture', 'module': 'tool_abuse', 'category': 'chain',
                  'tool_name': 'fixture_tool', 'description': 'Local fixture',
                  'payload': {'arguments': {'label': 'fixture'}},
                  'args': {'label': {'type': 'string'}}}


def run(coro):
    return asyncio.run(coro)


def unpack(reply):
    return json.loads((reply.content if hasattr(reply, 'content') else reply)[0].text)


def configured(definition, overrides=None, *, saved=False):
    config = MCPConfig(target_api_url=URL, target_model='fixture-model',
                       target_api_key='legacy-key', target_environment={'API_KEY': SECRET})
    config.target_profiles = {'custom': definition}
    config.target = resolve_target(config, 'custom' if saved else definition, overrides)
    config.target_api_url = config.target.url
    return config


def transport(monkeypatch, handler):
    original = httpx.AsyncClient
    def client(*args, **kwargs):
        kwargs['transport'] = httpx.MockTransport(handler)
        return original(*args, **kwargs)
    monkeypatch.setattr(httpx, 'AsyncClient', client)


def test_explicit_env_files_precedence_no_discovery_or_process_mutation(tmp_path, monkeypatch):
    # 1.1.0: ``target_environment`` is now the restricted template-visible
    # subset. Explicit .env file values stay visible; process env values are
    # visible only when their names are listed in TEMPLATE_ENV.
    monkeypatch.chdir(tmp_path)
    (tmp_path / '.env').write_text('UNSELECTED=do-not-load\n', encoding='utf-8')
    assert load_target_sources({}) == ({}, {}, {})
    (tmp_path / 'first.env').write_text('FROM_FILES=first\nAPI_KEY=first\nRAW=${API_KEY}\n', encoding='utf-8')
    (tmp_path / 'second.env').write_text('FROM_FILES=second\nAPI_KEY=second\n', encoding='utf-8')
    definition = {'url': URL, 'headers': {'Authorization': 'Bearer ${env.API_KEY}'}}
    profile = tmp_path / 'targets.json'
    profile.write_text(json.dumps({'env_files': ['first.env', 'second.env'],
                                   'targets': {'custom': definition}}), encoding='utf-8')
    monkeypatch.setenv('ANTICELLS_RED_MCP_TARGETS_FILE', str(profile))
    monkeypatch.setenv('API_KEY', 'process')
    monkeypatch.setenv('ANTICELLS_RED_MCP_TEMPLATE_ENV', 'API_KEY')
    monkeypatch.delenv('FROM_FILES', raising=False)
    config = load_config()
    # Whitelisted process name wins (process value), file-only name comes
    # from the last .env file, and token-looking values stay literal.
    assert config.target_environment['API_KEY'] == 'process'
    assert config.target_environment['FROM_FILES'] == 'second'
    assert config.target_environment['RAW'] == '${API_KEY}'
    assert 'UNSELECTED' not in config.target_environment
    import os
    assert 'FROM_FILES' not in os.environ
    assert config.target_profiles['custom'] == definition


def test_process_env_without_whitelist_is_invisible_to_templates(tmp_path, monkeypatch):
    # 1.1.0 enforcement for finding F2: without TEMPLATE_ENV, no process env
    # value crosses into the template-visible dict.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('API_KEY', 'process-should-not-leak')
    monkeypatch.delenv('ANTICELLS_RED_MCP_TEMPLATE_ENV', raising=False)
    monkeypatch.delenv('ANTICELLS_RED_MCP_TARGETS_FILE', raising=False)
    monkeypatch.delenv('ANTICELLS_RED_MCP_ENV_FILE', raising=False)
    config = load_config()
    assert 'API_KEY' not in config.target_environment


def test_saved_profile_env_file_and_snapshot(tmp_path, monkeypatch):
    # 1.1.0: ${env.*} references are only honored for operator-authored
    # saved profiles. The inline path is covered by the hardening suite's
    # ``test_f2_*`` regressions.
    envfile = tmp_path / 'profile.env'
    envfile.write_text(f'API_KEY={SECRET}\nANTICELLS_RED_MCP_TARGET_API_URL={URL}\n', encoding='utf-8')
    profiles_file = tmp_path / 'targets.json'
    definition = {'url': URL, 'headers': {'Authorization': '${env.API_KEY}'},
                  'variables': {'list': [1]}, 'body': '${vars.list}'}
    profiles_file.write_text(json.dumps({'env_files': ['profile.env'],
                                         'targets': {'custom': definition}}), encoding='utf-8')
    monkeypatch.setenv('ANTICELLS_RED_MCP_TARGETS_FILE', str(profiles_file))
    monkeypatch.setenv('ANTICELLS_RED_MCP_ENV_FILE', str(envfile))
    for key in ('ANTICELLS_RED_MCP_TARGET_API_URL', 'API_KEY'):
        monkeypatch.delenv(key, raising=False)
    config = load_config()
    overrides = {'list': [2]}
    target = resolve_target(config, 'custom', overrides)
    config.target_environment['API_KEY'] = 'changed'
    overrides['list'].append(3)
    envfile.write_text('API_KEY=changed-on-disk', encoding='utf-8')
    _, url, headers, body = target.request({}, 'prompt')
    assert url == URL and headers['Authorization'] == SECRET and json.loads(body) == [2]
    with pytest.raises(FrozenInstanceError):
        target.url = 'https://changed.example'
    assert SECRET not in repr(target) + repr(config) + json.dumps(config.to_dict())


@pytest.mark.parametrize('document', [
    '{not-json', '{"targets": [], "secret":"private-fixture-credential"}',
    '{"targets":{"bad":{"url":"https://example.invalid","method":"TRACE"}}}',
    '{"targets":{"bad":{"url":"https://example.invalid","response":{"text":"/bad~2"}}}}',
])
def test_bad_profiles_fail_safely(tmp_path, document):
    path = tmp_path / 'profiles.json'
    path.write_text(document, encoding='utf-8')
    with pytest.raises(TargetConfigurationError) as error:
        load_target_sources({'ANTICELLS_RED_MCP_TARGETS_FILE': str(path)})
    assert SECRET not in str(error.value) and str(path) not in str(error.value)


def test_invalid_selected_env_file_has_safe_error(tmp_path):
    path = tmp_path / 'private.env'
    path.write_text('API_KEY="' + SECRET, encoding='utf-8')
    with pytest.raises(TargetConfigurationError) as error:
        load_target_sources({'ANTICELLS_RED_MCP_ENV_FILE': str(path)})
    assert error.value.code == 'invalid_env_file'
    assert SECRET not in str(error.value) and str(path) not in str(error.value)


# 1.1.0: this scenario exercises ${env.*} which is only honored on
# operator-authored saved profiles. The inline variant is covered by a
# dedicated rejection test below.
@pytest.mark.parametrize('saved', [True])
@pytest.mark.parametrize('method', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def test_exact_custom_http_request_and_no_legacy_auth(monkeypatch, saved, method):
    seen = []
    def capture(request):
        seen.append(request)
        return httpx.Response(202, json={'result': {'answer': 'reply'}}, headers={'x-fixture': 'yes'})
    transport(monkeypatch, capture)
    config = configured({'url': URL + '?workspace=${vars.workspace}', 'method': method,
                         'headers': {'X-Key': '${env.API_KEY}', 'Content-Type': 'application/vnd.fixture+json'},
                         'variables': {'workspace': 'research', 'limit': 10},
                         'body': {'question': '${request.prompt}', 'limit': '${vars.limit}',
                                  'model': '${request.body.model}'}, 'response': TEXT_MAPPING},
                        {'workspace': 'staging', 'limit': 512}, saved=saved)
    async def check():
        async with make_chat_client(config) as client:
            response = await post_chat(client, URL, {'messages': []}, config, prompt='quotes " \\ Unicode é 🧪')
        assert response.status_code == 202 and response.headers['x-fixture'] == 'yes'
        assert response_text(normalize_response(response.json(), config)) == 'reply'
    run(check())
    assert len(seen) == 1 and seen[0].method == method
    assert str(seen[0].url) == URL + '?workspace=staging'
    assert 'authorization' not in seen[0].headers and seen[0].headers['x-key'] == SECRET
    assert seen[0].headers['content-type'] == 'application/vnd.fixture+json'
    assert json.loads(seen[0].content) == {'question': 'quotes " \\ Unicode é 🧪', 'limit': 512, 'model': 'fixture-model'}


def test_typed_variables_single_pass_escaping_and_complete_generated_body(monkeypatch):
    # 1.1.0: ${env.*} requires a saved profile.
    seen = []
    transport(monkeypatch, lambda request: (seen.append(json.loads(request.content)) or httpx.Response(200, json={})))
    config = configured({'url': URL, 'variables': {'n': 2, 'flag': False, 'nil': None,
                        'object': {'child': [1, '雪']}, 'literal': '${env.API_KEY}'}, 'body': {
        'n': '${vars.n}', 'flag': '${vars.flag}', 'nil': '${vars.nil}', 'object': '${vars.object}',
        'nested': '${vars.object.child.1}', 'embedded': 'n=${vars.n};flag=${vars.flag};nil=${vars.nil}',
        'env_string': '${env.API_KEY}', 'literal': '$${env.API_KEY}',
        'escaped_embedded': 'literal=$${request.prompt}', 'once': '${vars.literal}',
        'messages': '${request.messages}', 'tools': '${request.tools}', 'original': '${request.body}',
        'temperature': '${request.body.temperature}',
    }}, saved=True)
    original = {'messages': [{'role': 'system', 'content': 'payload ${env.API_KEY}'}],
                'tools': [TOOL_SCHEMA], 'temperature': .25}
    async def check():
        async with make_chat_client(config) as client:
            await post_chat(client, URL, original, config, prompt='payload')
    run(check())
    body = seen[0]
    assert body['n'] == 2 and body['flag'] is False and body['nil'] is None
    assert body['object'] == {'child': [1, '雪']} and body['nested'] == '雪'
    assert body['embedded'] == 'n=2;flag=false;nil=null' and body['env_string'] == SECRET
    assert body['literal'] == body['once'] == '${env.API_KEY}'
    assert body['escaped_embedded'] == 'literal=${request.prompt}'
    assert body['messages'] == original['messages'] and body['tools'] == [TOOL_SCHEMA]
    assert body['original'] == {**original, 'model': 'fixture-model'} and body['temperature'] == .25
    assert 'model' not in original


@pytest.mark.parametrize('body', [None, [], 17, 'fixed', {'exact': True}])
def test_supplied_body_is_a_complete_replacement(body):
    config = configured({'url': URL, 'body': body})
    assert json.loads(config.target.request({'model': 'unused'}, 'prompt')[3]) == body


def test_omitted_body_and_response_preserve_legacy_behavior(monkeypatch):
    seen = []
    reply = {'choices': [{'message': {'content': 'legacy reply'}}]}
    transport(monkeypatch, lambda request: (seen.append(request) or httpx.Response(200, json=reply)))
    config = configured({'url': URL})
    async def check():
        async with make_chat_client(config) as client:
            response = await post_chat(client, URL, {'messages': []}, config, prompt='prompt')
        assert normalize_response(response.json(), config) == reply
    run(check())
    assert seen[0].method == 'POST' and json.loads(seen[0].content) == {'messages': [], 'model': 'fixture-model'}
    assert config.target.supports_tools


@pytest.mark.parametrize('body,code', [
    ('${vars.missing}', 'missing_variable'),
    # 1.1.0: inline ${env.*} is now rejected before any missing-key lookup.
    ('${env.MISSING}', 'inline_environment_reference_forbidden'),
    ('embed ${vars.object}', 'embedded_container_variable'),
    ('${unknown.value}', 'invalid_variable_reference'), ('${request.unknown}', 'unknown_request_variable'),
])
def test_static_template_errors_are_configuration_errors(body, code):
    with pytest.raises(TargetConfigurationError) as error:
        configured({'url': URL, 'variables': {'object': {}}, 'body': body})
    assert error.value.code == code


def test_saved_profile_env_missing_variable_reports_missing_variable():
    """Saved profiles still receive the pre-1.1.0 behavior for env refs."""
    from anticells_red_mcp.mcp_server.config import MCPConfig
    cfg = MCPConfig(target_api_url=URL)
    cfg.target_profiles = {'p': {'url': URL, 'body': '${env.MISSING}'}}
    with pytest.raises(TargetConfigurationError) as error:
        resolve_target(cfg, 'p', None)
    assert error.value.code == 'missing_variable'


@pytest.mark.parametrize('tool,args', [
    ('fingerprint_llm', {'techniques': ['direct_identity_query']}),
    ('prompt_injection', {'payload_override': 'fixture'}),
    ('jailbreak_attack', {'intensity': 1}),
    ('tool_abuse_exploit', {}),
])
def test_request_dependent_errors_escape_modules_without_http_or_failed_records(monkeypatch, tool, args):
    transport(monkeypatch, lambda request: pytest.fail('Configuration error reached HTTP'))
    reply = run(server.call_tool(tool, {**args, 'target': {'url': URL, 'body': '${request.body.missing}'}}))
    assert reply.isError and unpack(reply) == {'error': 'target_configuration_error', 'code': 'missing_variable'}
    assert not server._history


@pytest.mark.parametrize('body', ['${request.prompt}', 'embedded ${request.messages}'])
def test_injection_passes_actual_payload_and_rejects_embedded_arrays(monkeypatch, body):
    seen = []
    transport(monkeypatch, lambda request: (seen.append(json.loads(request.content)) or
        httpx.Response(200, json={'result': {'answer': 'acknowledged'}})))
    args = {'target': {'url': URL, 'body': body, 'response': TEXT_MAPPING}, 'payload_override': 'actual payload'}
    reply = run(server.call_tool('prompt_injection', args))
    if body.startswith('embedded'):
        assert reply.isError and unpack(reply)['code'] == 'embedded_container_variable' and not seen
    else:
        assert seen and set(seen) == {'actual payload'}
        assert unpack(reply)['successful'] == len(seen)


def test_json_pointer_arrays_escaped_keys_and_root():
    config = configured({'url': URL, 'response': {'text': '/results/0/a~1b/~0name'}})
    data = {'results': [{'a/b': {'~name': 'reply'}}], 'model': 'fixture-model', 'usage': {'tokens': 12}}
    normalized = normalize_response(data, config)
    assert response_text(normalized) == 'reply' and normalized['model'] == 'fixture-model'
    assert normalized['usage'] == {'tokens': 12} and 'choices' not in data
    root = configured({'url': URL, 'response': {'text': ''}})
    assert response_text(normalize_response('root reply', root)) == 'root reply'


@pytest.mark.parametrize('reply', [{}, {'result': {}}, {'result': {'answer': None}},
                                  {'result': {'answer': []}}, {'error': 'failed'}, []])
def test_missing_or_malformed_custom_text_never_succeeds(monkeypatch, reply):
    transport(monkeypatch, lambda request: httpx.Response(200, json=reply))
    config = configured({'url': URL, 'response': TEXT_MAPPING})
    async def check():
        module = InjectionEngine(config)
        try:
            assert (await module._send_injection('fixture', URL))[1] is False
        finally:
            await module.close()
    run(check())


@pytest.mark.parametrize('arguments,success', [
    ({'label': 'fixture'}, True), ('{"label":"fixture"}', True), ({'label': 7}, False),
    ({}, False), ('malformed', False), ('[]', False), ([], False),
])
def test_custom_tool_proposals_use_existing_schema_validation(monkeypatch, arguments, success):
    seen = []
    def capture(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={'result': {'answer': '', 'actions': [
            {'name': 'fixture_tool', 'arguments': arguments},
        ]}})
    transport(monkeypatch, capture)
    config = configured({'url': URL, 'response': TOOL_MAPPING,
                         'body': {'prompt': '${request.prompt}', 'functions': '${request.tools}'}})
    async def check():
        module = ToolAbuseEngine(config)
        module._techniques = [deepcopy(TOOL_TECHNIQUE)]
        try:
            results = await module.run_exploit([TOOL_SCHEMA], 'all', URL)
            assert results[0].success is success
        finally:
            await module.close()
    run(check())
    assert seen[0]['functions'] == [TOOL_SCHEMA] and 'fixture_tool' in seen[0]['prompt']


@pytest.mark.parametrize('actions', [None, {}, [{}], [{'name': 3, 'arguments': {}}]])
def test_malformed_tool_response_invalidates_even_valid_text(actions):
    config = configured({'url': URL, 'response': TOOL_MAPPING})
    assert normalize_response({'result': {'answer': 'accepted', 'actions': actions}}, config) == {'error': True}
    assert normalize_response({'result': {'answer': 'accepted'}}, config) == {'error': True}


def test_text_only_targets_skip_all_tool_scenarios_and_exclude_totals(monkeypatch):
    transport(monkeypatch, lambda request: pytest.fail('Skipped tool scenario reached HTTP'))
    response = unpack(run(server.call_tool('tool_abuse_exploit', {'target': {'url': URL, 'response': TEXT_MAPPING}})))
    assert response['total_attempts'] == response['successful'] == 0 and response['skipped'] == 35
    assert all(r['metadata']['reason'] == 'target_has_no_tool_call_mapping' for r in response['results'])
    stats = run(server._handle_report({}))['statistics']
    assert stats['total_attacks'] == 0 and stats['skipped_records'] == 35


@pytest.mark.parametrize('definition', [
    {'url': 'https://other.example', 'headers': {'Authorization': '${env.API_KEY}'}},
    {'url': 'https://other.example', 'body': '${env.API_KEY}'},
    {'url': 'https://other.example/${env.API_KEY}'},
])
def test_inline_environment_is_forbidden_outright(definition):
    # 1.1.0 (finding F2): inline targets cannot reference ${env.*} at all,
    # regardless of destination origin. The code name changed accordingly.
    with pytest.raises(TargetConfigurationError) as error:
        configured(definition)
    assert error.value.code == 'inline_environment_reference_forbidden' and SECRET not in str(error.value)


def test_inline_env_forbidden_but_saved_profile_bound_to_configured_origin():
    # 1.1.0: inline ${env.*} refs are rejected outright; saved profiles are
    # bound to the configured provider origin and may read the whitelisted
    # env values.
    config = MCPConfig(target_api_url=URL, target_environment={'API_KEY': SECRET})
    definition = {'url': URL, 'headers': {'Authorization': '${env.API_KEY}'}}
    with pytest.raises(TargetConfigurationError) as excinfo:
        resolve_target(config, definition)
    assert excinfo.value.code == 'inline_environment_reference_forbidden'
    config.target_profiles = {'custom': definition}
    assert resolve_target(config, 'custom').request({}, 'prompt')[2]['Authorization'] == SECRET


@pytest.mark.parametrize('url,allowed', [
    ('https://GATEWAY.example:443/other', True), ('https://gateway.example:0/chat', False),
    ('https://gateway.example:8443/chat', False), ('http://gateway.example/chat', False),
])
def test_origin_binding_normalizes_hosts_and_preserves_explicit_ports(url, allowed):
    # 1.1.0: use the saved-profile path so the ${env.*} ref is honored.
    definition = {'url': url, 'headers': {'Authorization': '${env.API_KEY}'}}
    if allowed:
        assert configured(definition, saved=True).target.request({}, 'fixture')[2]['Authorization'] == SECRET
    else:
        with pytest.raises(TargetConfigurationError, match='profile_environment_origin_not_authorized'):
            configured(definition, saved=True)


def test_legacy_bearer_binding_does_not_treat_port_zero_as_default():
    # 1.1.0 (finding F7): stable error code replaces the free-form message.
    server._config.target_api_key = SECRET
    server._config.target_api_url = URL
    with pytest.raises(ValueError, match='authenticated_target_origin_mismatch'):
        server._target_config('https://gateway.example:0/chat')


def test_overrides_cannot_rebind_saved_origin_or_request_variables_redirect_credentials(monkeypatch):
    definition = {'url': 'https://${vars.host}/chat', 'variables': {'host': 'gateway.example'},
                  'headers': {'Authorization': '${env.API_KEY}'}}
    with pytest.raises(TargetConfigurationError, match='target_origin_changed'):
        configured(definition, {'host': 'other.example'}, saved=True)
    config = configured({'url': 'https://${request.prompt}/chat'})
    transport(monkeypatch, lambda request: pytest.fail('Changed origin reached HTTP'))
    async def check():
        async with make_chat_client(config) as client:
            with pytest.raises(TargetConfigurationError, match='target_origin_changed'):
                await post_chat(client, URL, {}, config, prompt='other.example')
    run(check())


@pytest.mark.parametrize('headers', [
    {'Host': 'other.example'}, {'Content-Length': '3'}, {'Authorization': 'value\r\ninjected'},
    {'bad header': SECRET}, {'X-Key': '雪'}, {'X-Key': 'bad\x00value'}, {'X-Key': ' leading'},
])
def test_invalid_headers_fail_without_echoing_values(headers):
    with pytest.raises(TargetConfigurationError) as error:
        configured({'url': URL, 'headers': headers})
    assert SECRET not in str(error.value)


def test_redirects_are_not_followed_even_if_client_enables_them():
    # 1.1.0: ${env.*} requires a saved profile.
    seen = []
    async def check():
        config = configured({'url': URL, 'headers': {'Authorization': '${env.API_KEY}'}}, saved=True)
        def capture(request):
            seen.append(request)
            return httpx.Response(307, headers={'Location': 'https://other.example'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(capture), follow_redirects=True) as client:
            reply = await post_chat(client, URL, {}, config, prompt='fixture')
            assert reply.status_code == 307
    run(check())
    assert len(seen) == 1 and seen[0].url.host == 'gateway.example'


def test_configuration_error_and_target_metadata_do_not_expose_credentials(monkeypatch):
    # 1.1.0: ${env.*} is only honored on saved profiles.
    server._config.target_api_url = URL
    server._config.target_environment = {'API_KEY': SECRET}
    transport(monkeypatch, lambda request: httpx.Response(400, json={'error': SECRET}))
    definition = {'url': URL + '?key=${env.API_KEY}', 'body': {'credential': '${env.API_KEY}'}}
    server._config.target_profiles = {'saved': definition}
    reply = run(server.call_tool('prompt_injection', {'target': 'saved', 'payload_override': 'fixture'}))
    assert SECRET not in json.dumps(unpack(reply)) and unpack(reply)['target'] == 'saved'
    bad = dict(definition, headers={'Authorization': SECRET + '\r\ninvalid'})
    server._config.target_profiles = {'saved': bad}
    reply = run(server.call_tool('prompt_injection', {'target': 'saved'}))
    assert reply.isError and unpack(reply)['error'] == 'target_configuration_error'
    assert SECRET not in reply.content[0].text


def test_target_schemas_with_discovery_reject_conflicting_selectors():
    tools = run(server.list_tools())
    assert len(tools) == 12
    target_tools = [t for t in tools if 'target' in t.inputSchema['properties'] and t.name != 'execute_attack_template']
    assert len(target_tools) == 7
    for tool in target_tools:
        validate = Draft202012Validator(tool.inputSchema).is_valid
        assert validate({'target_url': URL}) and validate({'target': 'saved', 'target_variables': {'n': 2}})
        assert validate({'target': {'url': URL, 'body': '${request.body}'}})
        for args in ({}, {'target': 'saved', 'target_url': URL}, {'target_url': URL, 'target_variables': {}},
                     {'target': {'url': URL, 'env_files': ['secret.env']}},
                     {'target': {'url': URL, 'method': 'TRACE'}}, {'target': 'saved', 'target_variables': []}):
            assert not validate(args)


def test_concurrent_calls_keep_variables_isolated(monkeypatch):
    seen = []
    async def capture(request):
        body = json.loads(request.content)
        seen.append(body)
        await asyncio.sleep(0)
        return httpx.Response(200, json={'result': {'answer': body['workspace']}})
    transport(monkeypatch, capture)
    server._config.target_profiles = {'custom': {'url': URL, 'variables': {'workspace': 'default'},
        'body': {'workspace': '${vars.workspace}', 'payload': '${request.prompt}'}, 'response': TEXT_MAPPING}}
    async def check():
        replies = await asyncio.gather(*(server.call_tool('prompt_injection', {
            'target': 'custom', 'target_variables': {'workspace': label}, 'payload_override': label,
        }) for label in ('first', 'second')))
        for label, reply in zip(('first', 'second'), replies):
            assert all(r['response'] == label for r in unpack(reply)['results'])
    run(check())
    assert seen and all(b['workspace'] == b['payload'] for b in seen)
    assert server._config.target_profiles['custom']['variables']['workspace'] == 'default'


@pytest.mark.parametrize('mode', ['infinite', 'breadth_first', 'evolutionary'])
def test_loop_configuration_errors_surface_without_counting_failed_attempts(monkeypatch, mode):
    transport(monkeypatch, lambda request: pytest.fail('Configuration error reached HTTP'))
    async def check():
        reply = await server.call_tool('endless_attack_loop', {
            'target': {'url': URL, 'body': '${request.body.missing}'}, 'mode': mode, 'max_iterations': 1,
        })
        assert unpack(reply)['status'] == 'STARTED'
        await asyncio.wait_for(server._loop_task, timeout=5)
        report = await server._handle_report({})
        assert report['configuration_error'] == {'error': 'target_configuration_error', 'code': 'missing_variable'}
        assert not report['loop_running'] and report['statistics']['total_attacks'] == 0
        await server._handle_stop({})
    run(check())


def test_loop_snapshot_survives_concurrent_call_and_global_configuration_changes(monkeypatch):
    async def check():
        started, release = asyncio.Event(), asyncio.Event()
        seen = []
        async def capture(request):
            body = json.loads(request.content)
            seen.append(body)
            if body['workspace'] == 'loop':
                started.set()
                await release.wait()
            return httpx.Response(200, json={'result': {'answer': ''}})
        transport(monkeypatch, capture)
        server._config.target_profiles = {'custom': {'url': URL, 'variables': {'workspace': 'default'},
            'body': {'workspace': '${vars.workspace}'}, 'response': TEXT_MAPPING}}
        await server._handle_endless_loop({'target': 'custom', 'target_variables': {'workspace': 'loop'},
                                          'mode': 'infinite', 'max_iterations': 1})
        try:
            await asyncio.wait_for(started.wait(), timeout=5)
            server._config.target_profiles['custom']['variables']['workspace'] = 'changed'
            reply = await server.call_tool('prompt_injection', {'target': 'custom', 'payload_override': 'fixture'})
            assert unpack(reply)['successful'] == 0
            release.set()
            await asyncio.wait_for(server._loop_task, timeout=5)
            report = await server._handle_report({})
            assert report['configuration_error'] is None
            assert report['statistics']['skipped_records'] == 35
        finally:
            release.set()
            await server._handle_stop({})
        assert {body['workspace'] for body in seen} == {'loop', 'changed'}
        assert json.loads(server._engine.config.target.request({}, 'fixture')[3]) == {'workspace': 'loop'}
    run(check())


def test_shared_mutation_transport_uses_custom_definition(monkeypatch):
    seen = []
    transport(monkeypatch, lambda request: (seen.append(json.loads(request.content)) or
        httpx.Response(200, json={'result': {'answer': 'fixture rewritten text'}})))
    config = configured({'url': URL, 'body': {'prompt': '${request.prompt}'}, 'response': TEXT_MAPPING})
    config.mutation.use_llm_for_mutation = True
    async def check():
        module = CreativeMutationEngine(config)
        try:
            assert await module._llm_mutate('original payload') == 'fixture rewritten text'
        finally:
            await module.close()
    run(check())
    assert 'original payload' in seen[0]['prompt'] and 'model' not in seen[0]


def test_fingerprint_keeps_response_headers_and_model_hints(monkeypatch):
    transport(monkeypatch, lambda request: httpx.Response(200,
        json={'result': {'answer': 'fixture reply'}, 'model': 'gpt-4', 'usage': {}},
        headers={'server': 'openai', 'x-request-id': 'fixture-request'}))
    async def check():
        module = FingerprintScanner(configured({'url': URL, 'response': TEXT_MAPPING}))
        try:
            result = await module._probe(URL, {'name': 'fixture', 'category': 'identity', 'payload': 'fixture'})
            assert result['status_code'] == 200 and result['latency_ms'] >= 0
            assert result['headers']['x-request-id'] == 'fixture-request'
            assert 'openai_header' in result['indicators']
        finally:
            await module.close()
    run(check())


def test_custom_targets_through_mcp_client_session(monkeypatch):
    from datetime import timedelta
    from mcp.shared.memory import create_connected_server_and_client_session
    seen = []
    transport(monkeypatch, lambda request: (seen.append(json.loads(request.content)) or
        httpx.Response(200, json={'result': {'answer': 'fixture reply'}})))
    server._config.target_profiles = {'custom': {'url': URL, 'body': {'prompt': '${request.prompt}'},
                                                 'response': TEXT_MAPPING}}
    async def check():
        async with create_connected_server_and_client_session(
            server._server, read_timeout_seconds=timedelta(seconds=5),
        ) as client:
            assert len((await client.list_tools()).tools) == 12
            reply = await client.call_tool('fingerprint_llm', {
                'target': 'custom', 'techniques': ['direct_identity_query'], 'intensity': 1,
            })
            assert not reply.isError and unpack(reply)['target'] == 'custom'
            reply = await client.call_tool('prompt_injection', {
                'target': {'url': URL, 'body': '${request.prompt}', 'response': TEXT_MAPPING},
                'payload_override': 'actual payload',
            })
            assert not reply.isError and unpack(reply)['successful'] > 0
            conflict = await client.call_tool('fingerprint_llm', {'target': 'custom', 'target_url': URL})
            assert conflict.isError and unpack(conflict)['error'] == 'invalid_arguments'
            bad = await client.call_tool('fingerprint_llm', {'target': 'missing'})
            assert bad.isError and unpack(bad)['error'] == 'target_configuration_error'
    run(check())
    assert isinstance(seen[0]['prompt'], str) and all(body == 'actual payload' for body in seen[1:])
