"""Network-boundary regression tests; no external service is contacted."""

import asyncio
import ipaddress
import socket

import httpcore
import httpx
import pytest

from anticells_red_mcp.mcp_server import endpoint_safety
from anticells_red_mcp.mcp_server.targets import TargetConfigurationError
from anticells_red_mcp.modules.utils import safe_http
from anticells_red_mcp.reports.runtime import reset_outbound_counter, clear_outbound_counter


def test_dns_rebinding_connects_only_to_vetted_ip_and_preserves_tls(monkeypatch):
    monkeypatch.delenv('ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION', raising=False)
    monkeypatch.delenv('ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS', raising=False)
    resolutions, connects, tls_names, writes = [], [], [], []

    def resolve(host, timeout):
        resolutions.append(host)
        # A second resolution would return a private destination.
        return [ipaddress.ip_address('8.8.8.8' if len(resolutions) == 1 else '127.0.0.1')]

    class Stream(httpcore.AsyncMockStream):
        async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            assert ssl_context.check_hostname
            tls_names.append(server_hostname)
            return self

        async def write(self, buffer, timeout=None):
            writes.append(buffer)

    async def connect(self, host, port, **kwargs):
        connects.append((host, port))
        return Stream([b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'])

    monkeypatch.setattr(endpoint_safety, '_resolve', resolve)
    monkeypatch.setattr(httpcore.AnyIOBackend, 'connect_tcp', connect)

    async def check():
        async with safe_http.make_http_client() as client:
            reply = await client.post('https://rebind.example/chat', json={})
            assert reply.status_code == 200

    asyncio.run(check())
    assert resolutions == ['rebind.example']
    assert connects == [('8.8.8.8', 443)]
    assert tls_names == ['rebind.example']
    assert b'Host: rebind.example\r\n' in b''.join(writes)


@pytest.mark.parametrize('host', ['127.0.0.1', '169.254.169.254', '10.1.2.3', '::1'])
def test_connection_backend_blocks_private_addresses_before_connect(monkeypatch, host):
    monkeypatch.delenv('ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS', raising=False)
    connected = []

    async def connect(*args, **kwargs):
        connected.append(True)

    monkeypatch.setattr(httpcore.AnyIOBackend, 'connect_tcp', connect)
    with pytest.raises(TargetConfigurationError):
        asyncio.run(safe_http.PolicyNetworkBackend().connect_tcp(host, 80))
    assert connected == []


def test_auxiliary_http_clients_enforce_per_call_cap(monkeypatch):
    monkeypatch.setenv('ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL', '2')
    sent = []
    original = httpx.AsyncClient

    def client_factory(**kwargs):
        def reply(request):
            sent.append(request)
            return httpx.Response(200, json={})
        kwargs['transport'] = httpx.MockTransport(reply)
        return original(**kwargs)

    monkeypatch.setattr(httpx, 'AsyncClient', client_factory)

    async def check():
        token = reset_outbound_counter()
        try:
            async with safe_http.make_http_client() as client:
                await client.post('https://example.invalid/chat', json={})
                await client.post('https://example.invalid/chat', json={})
                with pytest.raises(TargetConfigurationError, match='per_call_request_cap_exceeded'):
                    await client.post('https://example.invalid/chat', json={})
        finally:
            clear_outbound_counter(token)

    asyncio.run(check())
    assert len(sent) == 2


def test_proxy_environment_is_ignored_and_redirects_are_disabled(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:9')
    monkeypatch.setenv('ALL_PROXY', 'http://127.0.0.1:9')

    async def check():
        async with safe_http.make_http_client() as client:
            assert not client.trust_env
            assert not client.follow_redirects
            assert isinstance(client._transport, safe_http.PolicyTransport)
            assert not client._mounts

    asyncio.run(check())


def test_dns_resolution_does_not_change_global_socket_timeout(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 0))])
    before = socket.getdefaulttimeout()
    endpoint_safety._resolve('public.example', 0.5)
    assert socket.getdefaulttimeout() == before
