"""Automatic local SQLite initialization before MCP stdio starts."""
from pathlib import Path
import sys

from .model import CatalogError
from .repository import SCHEMA_VERSION, migrate, publish, read_sync, require_path
from .seed import seed_document


def state_directory(config):
    if config.catalog_state_dir:
        return require_path(config.catalog_state_dir)
    env = config.target_environment
    if sys.platform == 'win32':
        base = Path(env.get('LOCALAPPDATA') or Path.home() / 'AppData/Local')
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library/Application Support'
    else:
        base = Path(env.get('XDG_DATA_HOME') or Path.home() / '.local/share')
    return require_path(base / 'anticells_red_mcp' / 'catalog')


def resolve_database(config):
    if not config.database_path:
        # Do not silently abandon an existing operator's PostgreSQL catalog.
        if config.database_url or (state_directory(config) / 'database.json').exists():
            raise CatalogError('postgres_migration_required')
        config.database_path = str(state_directory(config) / 'catalog.sqlite3')
    config.database_path = str(require_path(config.database_path))
    return config.database_path


def prepare_database(config):
    """Idempotent startup initialization; never overwrite an existing record."""
    path = resolve_database(config)
    if not config.catalog_auto_setup:
        snapshot = read_sync(path)
        return {'schema_version': SCHEMA_VERSION, 'revision': snapshot.revision, 'changed': 0}
    migrate(path)
    result = publish(path, seed_document(), seed=True)
    if result['changed']:
        print('anticells_red_mcp: SQLite catalog initialized; existing edits preserved.', file=sys.stderr)
    return {'schema_version': SCHEMA_VERSION, **result}
