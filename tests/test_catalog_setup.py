import json
from pathlib import Path
import sqlite3
import sys
from contextlib import closing

import pytest

from anticells_red_mcp.catalog import CatalogError
from anticells_red_mcp.catalog import setup
from anticells_red_mcp.catalog.cli import parser, run
from anticells_red_mcp.catalog.model import encode
from anticells_red_mcp.catalog.repository import migrate, publish, read_sync, restore
from anticells_red_mcp.mcp_server.config import MCPConfig, load_config


def test_first_launch_needs_only_a_local_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('PATH', '')  # No external executable is required, including Docker.
    config = MCPConfig(catalog_state_dir=str(tmp_path / 'state'))
    assert setup.prepare_database(config) == {'schema_version': 1, 'revision': 1, 'changed': 496}
    assert Path(config.database_path) == tmp_path / 'state' / 'catalog.sqlite3'
    first = read_sync(config.database_path)
    assert len(first.records()) == 496
    assert setup.prepare_database(MCPConfig(catalog_state_dir=str(tmp_path / 'state')))['changed'] == 0
    assert read_sync(config.database_path).records() == first.records()
    assert capsys.readouterr().out == ''
    if sys.platform != 'win32':
        assert Path(config.database_path).stat().st_mode & 0o777 == 0o600


def test_manual_mode_never_creates_or_seeds(tmp_path, catalog_path):
    assert setup.prepare_database(MCPConfig(database_path=catalog_path, catalog_auto_setup=False))['changed'] == 0
    missing = tmp_path / 'missing' / 'catalog.sqlite3'
    with pytest.raises(CatalogError, match='database_unavailable'):
        setup.prepare_database(MCPConfig(database_path=str(missing), catalog_auto_setup=False))
    assert not missing.parent.exists()
    with closing(sqlite3.connect(catalog_path)) as conn, conn:
        conn.execute('DELETE FROM catalog_records')
    with pytest.raises(CatalogError, match='empty_catalog'):
        setup.prepare_database(MCPConfig(database_path=catalog_path, catalog_auto_setup=False))


def test_unrelated_or_corrupt_database_is_not_overwritten(tmp_path):
    path = tmp_path / 'private.sqlite3'
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute('CREATE TABLE unrelated(value TEXT)')
        conn.execute("INSERT INTO unrelated VALUES ('private-value')")
    before = path.read_bytes()
    with pytest.raises(CatalogError, match='unrecognized_database'):
        migrate(path)
    assert path.read_bytes() == before
    path.write_bytes(b'private-corrupt-file')
    with pytest.raises(CatalogError) as error:
        migrate(path)
    assert 'private' not in str(error.value)
    assert path.read_bytes() == b'private-corrupt-file'


@pytest.mark.parametrize('value', [':memory:', 'file:catalog?mode=memory', 'postgresql://user:secret@host/db', 'bad\0path'])
def test_database_path_rejects_transient_uris_and_connection_urls(value):
    with pytest.raises(CatalogError, match='invalid_database_path'):
        setup.resolve_database(MCPConfig(database_path=value))


def test_path_with_spaces_unicode_and_uri_punctuation(tmp_path):
    path = tmp_path / 'catalog # café.sqlite3'
    setup.prepare_database(MCPConfig(database_path=str(path)))
    assert read_sync(path).revision == 1


def test_invalid_state_directory_is_a_redacted_catalog_error():
    with pytest.raises(CatalogError, match='invalid_database_path') as error:
        setup.prepare_database(MCPConfig(catalog_state_dir='private-invalid\0directory'))
    assert 'private' not in str(error.value)


def test_old_postgres_configuration_requires_explicit_transfer(tmp_path):
    config = MCPConfig(database_url='postgresql://user:private@host/db', catalog_state_dir=str(tmp_path))
    with pytest.raises(CatalogError, match='postgres_migration_required') as error:
        setup.prepare_database(config)
    assert 'private' not in str(error.value)
    assert not list(tmp_path.iterdir())
    config.database_url = None
    (tmp_path / 'database.json').write_text('legacy-private-state')
    with pytest.raises(CatalogError, match='postgres_migration_required'):
        setup.prepare_database(config)
    # Explicitly selecting SQLite lets an operator transfer or start a fresh catalog.
    config.database_path = str(tmp_path / 'converted.sqlite3')
    assert setup.prepare_database(config)['changed'] == 496


def test_environment_path_and_explicit_env_file(tmp_path, monkeypatch):
    envfile = tmp_path / 'config.env'
    selected = str(tmp_path / 'selected.sqlite3')
    envfile.write_text('ANTICELLS_RED_MCP_DATABASE_PATH="' + selected.replace('\\', '/') + '"\n')
    monkeypatch.setenv('ANTICELLS_RED_MCP_ENV_FILE', str(envfile))
    monkeypatch.delenv('ANTICELLS_RED_MCP_DATABASE_PATH', raising=False)
    assert Path(load_config().database_path) == Path(selected)
    monkeypatch.setenv('ANTICELLS_RED_MCP_DATABASE_PATH', str(tmp_path / 'override.sqlite3'))
    assert load_config().database_path == str(tmp_path / 'override.sqlite3')


@pytest.mark.parametrize('value, expected', [('true', True), ('false', False), ('1', True), ('0', False)])
def test_auto_setup_environment(value, expected, monkeypatch):
    monkeypatch.setenv('ANTICELLS_RED_MCP_CATALOG_AUTO_SETUP', value)
    assert load_config().catalog_auto_setup is expected


def test_invalid_auto_setup_environment(monkeypatch):
    monkeypatch.setenv('ANTICELLS_RED_MCP_CATALOG_AUTO_SETUP', 'secret-invalid-value')
    with pytest.raises(CatalogError, match='invalid_auto_setup_setting'):
        load_config()


def test_full_export_restore_preserves_edits_order_and_revisions(catalog_path, tmp_path, monkeypatch):
    current = read_sync(catalog_path)
    record = next(r for r in current.records() if r['kind'] == 'technique' and 'content' in r)
    record['enabled'] = False
    record['content']['payload'] = 'An operator edit: quotes " and Unicode \u00e9'
    publish(catalog_path, {'format_version': 1, 'records': [record]}, update=True)
    monkeypatch.setenv('ANTICELLS_RED_MCP_DATABASE_PATH', catalog_path)
    backup = tmp_path / 'backup.json'
    run(parser().parse_args(['export', '--output', str(backup)]))
    restored_path = str(tmp_path / 'restored.sqlite3')
    monkeypatch.setenv('ANTICELLS_RED_MCP_DATABASE_PATH', restored_path)
    assert run(parser().parse_args(['restore', str(backup)])) == {'revision': 2, 'restored': 496}
    before, after = read_sync(catalog_path), read_sync(restored_path)
    assert before.revision == after.revision == 2
    assert encode(before.records()) == encode(after.records())
    assert setup.prepare_database(MCPConfig(database_path=restored_path))['changed'] == 0
    with pytest.raises(CatalogError, match='restore_requires_empty_database'):
        restore(restored_path, json.loads(backup.read_text()))
    assert encode(read_sync(restored_path).records()) == encode(before.records())


def test_restore_rejects_incomplete_catalog_before_creation(catalog_path, tmp_path):
    record = read_sync(catalog_path).records()[0]
    path = tmp_path / 'rejected.sqlite3'
    with pytest.raises(CatalogError, match='missing_required_asset'):
        restore(path, {'format_version': 1, 'records': [record]})
    assert not path.exists()
    record.pop('revision')
    with pytest.raises(CatalogError, match='incomplete_backup'):
        restore(path, {'format_version': 1, 'records': [record]})


def test_failed_sql_migration_rolls_back_all_ddl(tmp_path, monkeypatch):
    from anticells_red_mcp.catalog import repository
    class BrokenMigration:
        def joinpath(self, path): return self
        def read_text(self, **kwargs):
            return 'CREATE TABLE catalog_partial(value TEXT);\nINVALID SQL;\n'
    monkeypatch.setattr(repository, 'files', lambda package: BrokenMigration())
    path = tmp_path / 'migration.sqlite3'
    with pytest.raises(CatalogError):
        migrate(path)
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []


def test_separate_processes_share_first_launch(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import subprocess
    path = str(tmp_path / 'processes' / 'catalog.sqlite3')
    script = '''
import json, sys
from anticells_red_mcp.catalog.setup import prepare_database
from anticells_red_mcp.mcp_server.config import MCPConfig
print(json.dumps(prepare_database(MCPConfig(database_path=sys.argv[1]))))
'''
    def launch(_):
        completed = subprocess.run([sys.executable, '-c', script, path],
            capture_output=True, text=True, timeout=30)
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)
    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(launch, range(3)))
    assert sorted(result['changed'] for result in results) == [0, 0, 496]
    assert read_sync(path).revision == 1
