"""Snapshot injection for MCP calls and standalone Python modules."""
from contextvars import ContextVar
from contextlib import contextmanager
import asyncio
from .repository import CatalogRepository, read_sync
from .setup import prepare_database

active_snapshot = ContextVar('anticells_catalog_snapshot', default=None)


@contextmanager
def using_snapshot(snapshot):
    """Supply an existing snapshot to legacy constructors with no config argument."""
    token = active_snapshot.set(snapshot)
    try:
        yield snapshot
    finally:
        active_snapshot.reset(token)


def snapshot_for(config=None):
    snapshot = getattr(config, 'catalog_snapshot', None) or active_snapshot.get()
    if snapshot is not None:
        if config is not None:
            config.catalog_snapshot = snapshot
        return snapshot
    from ..mcp_server.config import load_config
    configured = config if (getattr(config, 'database_path', None) or getattr(config, 'database_url', None)) else load_config()
    # Preserve explicit standalone settings even when no path was supplied.
    if config is not None:
        configured.catalog_auto_setup = config.catalog_auto_setup and configured.catalog_auto_setup
        configured.catalog_state_dir = config.catalog_state_dir or configured.catalog_state_dir
    prepare_database(configured)
    snapshot = read_sync(configured.database_path)
    if config is not None:
        config.database_path = configured.database_path
        config.catalog_snapshot = snapshot
    return snapshot


async def bootstrap(config):
    """Prepare a standalone config before constructing modules in an event loop."""
    await asyncio.to_thread(prepare_database, config)
    repository = CatalogRepository(config.database_path)
    try:
        config.catalog_snapshot = await repository.snapshot()
        return config.catalog_snapshot
    finally:
        await repository.close()
