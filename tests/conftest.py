import asyncio

import pytest
import json
from importlib.resources import files
from types import SimpleNamespace
from unittest.mock import AsyncMock

from anticells_red_mcp.catalog.model import CatalogSnapshot
from anticells_red_mcp.catalog.runtime import active_snapshot


@pytest.fixture(scope='session')
def seed_snapshot():
    document = json.loads(files('anticells_red_mcp.catalog').joinpath('data/seed.json').read_text(encoding='utf-8'))
    return CatalogSnapshot.build(1, document['records'])

from anticells_red_mcp.mcp_server.local_ipc import LocalIPCPolicy


@pytest.fixture(autouse=True)
def isolated_server(monkeypatch, seed_snapshot):
    from anticells_red_mcp.mcp_server import server
    from anticells_red_mcp.mcp_server.config import MCPConfig

    # The 1.1.0 egress policy denies loopback/private targets by default.
    # The historical test suite talks to local mocks on 127.0.0.1 and
    # fictional hosts like ``api.example`` which do not resolve. Give every
    # test the "lab" opt-in; the hardening regression tests scrub this
    # variable with ``monkeypatch`` to verify the production default.
    monkeypatch.setenv("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", "true")
    # Legacy tests use fictional hostnames like ``example.invalid`` that do
    # not resolve. The egress check normally performs DNS; skip that step
    # for the test suite. Literal IP checks and allow/deny-lists still run.
    monkeypatch.setenv("ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION", "true")
    # Give the per-call cap enough headroom for existing techniques-per-run
    # (max ~ 53 injection + chains). Session rate limiter stays off.
    monkeypatch.setenv("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL", "0")
    monkeypatch.setenv("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_SESSION_PER_MIN", "0")
    previous = asyncio.get_event_loop_policy()
    asyncio.set_event_loop_policy(LocalIPCPolicy())
    monkeypatch.setattr(server, '_config', MCPConfig())
    monkeypatch.setattr(server, '_engine', None)
    monkeypatch.setattr(server, '_loop_task', None)
    monkeypatch.setattr(server, '_history', [])
    monkeypatch.setattr(server, '_report_recorder', None)
    monkeypatch.setattr(server, '_catalog_startup_error', None)
    monkeypatch.setattr(server, '_loop_lock', asyncio.Lock())
    monkeypatch.setattr(server, '_catalog_repository', SimpleNamespace(
        snapshot=AsyncMock(return_value=seed_snapshot), close=AsyncMock()))
    token = active_snapshot.set(seed_snapshot)
    yield
    active_snapshot.reset(token)
    asyncio.set_event_loop_policy(previous)


@pytest.fixture
def catalog_path(tmp_path):
    """Production SQLite storage, isolated for every integration scenario."""
    from anticells_red_mcp.catalog.seed import seed_document
    from anticells_red_mcp.catalog.repository import migrate, publish

    path = str(tmp_path / 'catalog.sqlite3')
    migrate(path)
    publish(path, seed_document(), seed=True)
    return path
