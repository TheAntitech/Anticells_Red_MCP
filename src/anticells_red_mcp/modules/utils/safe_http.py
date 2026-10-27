"""HTTP clients with connection-time destination validation and DNS pinning."""

import ssl

import anyio
import httpcore
import httpx

from ...mcp_server.endpoint_safety import check_host, EgressPolicyError, _float_env
from ...mcp_server.targets import TargetConfigurationError, endpoint_origin
from ...mcp_server.limits import session_limiter, max_requests_per_call
from ...reports.runtime import bump_outbound_counter


class PolicyNetworkBackend(httpcore.AnyIOBackend):
    """Keep the URL hostname for TLS while connecting to a vetted numeric IP."""

    async def connect_tcp(self, host, port, timeout=None, local_address=None,
                          socket_options=None):
        resolution_timeout = _float_env("ANTICELLS_RED_MCP_RESOLVE_TIMEOUT_SECONDS", 2.0)
        if timeout is not None:
            resolution_timeout = min(resolution_timeout, timeout)
        try:
            with anyio.fail_after(resolution_timeout):
                addresses = await anyio.to_thread.run_sync(
                    check_host, host, abandon_on_cancel=True)
        except TimeoutError:
            raise TargetConfigurationError("target_host_resolution_timeout") from None
        except EgressPolicyError as exc:
            raise TargetConfigurationError(exc.code) from None
        # The connector receives only the IP approved by check_host. It cannot
        # perform a second hostname lookup. HTTP Host and TLS SNI stay untouched.
        return await super().connect_tcp(
            addresses[0], port, timeout=timeout, local_address=local_address,
            socket_options=socket_options)


class PolicyTransport(httpx.AsyncHTTPTransport):
    def __init__(self):
        super().__init__(trust_env=False)
        # HTTPX exposes transport customization; HTTPCore exposes network_backend.
        # Reuse HTTPX's stream/exception adapters with a policy-aware core pool.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            network_backend=PolicyNetworkBackend(),
            max_connections=100, max_keepalive_connections=20)


async def enforce_request_policy(request):
    endpoint_origin(str(request.url), enforce_egress=False)
    cap = max_requests_per_call()
    if cap > 0 and bump_outbound_counter() > cap:
        raise TargetConfigurationError("per_call_request_cap_exceeded")
    session_limiter.check()


def make_http_client(*, timeout=60.0, headers=None):
    """Ignore proxy credentials/settings inherited from the operator's shell."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), headers=headers,
        transport=PolicyTransport(), trust_env=False, follow_redirects=False,
        event_hooks={"request": [enforce_request_policy]})
