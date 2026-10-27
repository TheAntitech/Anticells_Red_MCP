"""SQLite transactions for reading and publishing complete catalog revisions."""
import asyncio
from contextlib import contextmanager
from importlib.resources import files
import os
from pathlib import Path
import sqlite3

from .._sqlite import sqlite_file_uri
from .model import CatalogError, CatalogSnapshot, decode, encode, export_content, import_content, read_document

SCHEMA_VERSION = 1
_SELECT = 'SELECT id,namespace,kind,position,enabled,revision,memberships,content FROM catalog_records ORDER BY namespace,position,id'


def require_path(path):
    """Only persistent filesystem paths; SQLite URI options are not configuration."""
    if not isinstance(path, (str, os.PathLike)) or not str(path).strip():
        raise CatalogError('database_path_required')
    value = str(path)
    if value == ':memory:' or value.startswith('file:') or '://' in value or '\0' in value:
        raise CatalogError('invalid_database_path')
    try:
        return Path(value).expanduser().resolve()
    except (OSError, ValueError, RuntimeError):
        raise CatalogError('invalid_database_path') from None


def row_record(row):
    keys = ('id', 'namespace', 'kind', 'position', 'enabled', 'revision')
    record = dict(zip(keys, row[:6]))
    record['enabled'] = bool(record['enabled'])
    record['memberships'] = decode(row[6])
    return {**record, **export_content(decode(row[7]))}


def _check_versions(conn):
    versions = conn.execute('SELECT version FROM catalog_schema_migrations ORDER BY version').fetchall()
    if [row[0] for row in versions] != list(range(1, SCHEMA_VERSION + 1)):
        raise CatalogError('incompatible_schema')


@contextmanager
def _connection(path, *, write=False, create=False):
    """Close every connection, including failed transactions. Reads never create files."""
    path = require_path(path)
    conn = None
    try:
        if create:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Reserve new files privately; a simultaneous initializer may get here first.
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        mode = 'rw' if write else 'ro'
        conn = sqlite3.connect(sqlite_file_uri(path) + '?mode=' + mode, uri=True, timeout=5, isolation_level=None)
        conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        yield conn
        conn.commit()
    except CatalogError:
        raise
    except sqlite3.OperationalError as exc:
        if str(exc).startswith('no such table: catalog_'):
            raise CatalogError('schema_not_initialized') from None
        raise CatalogError('database_unavailable') from None
    except Exception:
        raise CatalogError('database_unavailable') from None
    finally:
        if conn is not None:
            # Closing rolls back pending changes. SQLite context-manager exit alone doesn't close.
            conn.close()


def read_sync(path, cached=None):
    with _connection(path) as conn:
        _check_versions(conn)
        revision = conn.execute('SELECT revision FROM catalog_state WHERE singleton=1').fetchone()[0]
        if cached is not None and cached.revision == revision:
            return cached
        records = [row_record(row) for row in conn.execute(_SELECT)]
        return CatalogSnapshot.build(revision, records)


class CatalogRepository:
    def __init__(self, path):
        self._path = require_path(path)
        self._snapshot = None
        self._lock = asyncio.Lock()

    async def open(self):
        await self.snapshot()

    async def close(self):
        async with self._lock:
            self._snapshot = None

    async def snapshot(self):
        async with self._lock:
            # Transactions and validation run off the event loop. Connections belong
            # to one worker only and are closed before its snapshot is returned.
            worker = asyncio.create_task(asyncio.to_thread(read_sync, self._path, self._snapshot))
            try:
                candidate = await asyncio.shield(worker)
            except asyncio.CancelledError:
                # Wait for transaction cleanup before releasing the lock to close().
                try:
                    await worker
                finally:
                    raise
            self._snapshot = candidate
            return candidate


def migrate(path):
    with _connection(path, write=True, create=True) as conn:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='catalog_schema_migrations'").fetchone()
        applied = 0
        if exists:
            versions = conn.execute('SELECT version FROM catalog_schema_migrations ORDER BY version').fetchall()
            applied = len(versions)
            if applied > SCHEMA_VERSION or [v[0] for v in versions] != list(range(1, applied + 1)):
                raise CatalogError('incompatible_schema')
        elif conn.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone():
            raise CatalogError('unrecognized_database')
        migrations = {1: '001_catalog.sql'}
        for version in range(applied + 1, SCHEMA_VERSION + 1):
            sql = files(__package__).joinpath('migrations/' + migrations[version]).read_text(encoding='utf-8')
            # executescript() implicitly commits. Execute statements individually
            # so DDL and the version change share the writer transaction.
            statement = ''
            for line in sql.splitlines(keepends=True):
                statement += line
                if sqlite3.complete_statement(statement):
                    conn.execute(statement)
                    statement = ''
            if statement.strip():
                raise CatalogError('invalid_migration')
    return SCHEMA_VERSION


def _write_record(conn, record):
    conn.execute('''INSERT INTO catalog_records(id,namespace,kind,position,enabled,revision,memberships,content)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET position=excluded.position,enabled=excluded.enabled,
        revision=excluded.revision,memberships=excluded.memberships,content=excluded.content,updated_at=CURRENT_TIMESTAMP''',
        tuple(record[k] for k in ('id', 'namespace', 'kind', 'position', 'enabled', 'revision'))
        + (encode(record['memberships']), encode(import_content(record))))


def publish(path, document, *, update=False, seed=False):
    incoming = read_document(document)
    with _connection(path, write=True) as conn:
        _check_versions(conn)
        revision = conn.execute('SELECT revision FROM catalog_state WHERE singleton=1').fetchone()[0]
        current = {r['id']: r for r in map(row_record, conn.execute(_SELECT).fetchall())}
        changed = []
        for entry in incoming:
            entry = dict(entry)
            old = current.get(entry['id'])
            if old and seed:
                continue
            if old:
                if not update:
                    raise CatalogError('update_requires_flag')
                if entry.get('revision') != old['revision']:
                    raise CatalogError('stale_update')
                if (entry['namespace'], entry['kind']) != (old['namespace'], old['kind']):
                    raise CatalogError('immutable_record_identity')
            elif entry.get('revision', 0) != 0:
                raise CatalogError('stale_update')
            content = import_content(entry)
            entry.setdefault('enabled', old['enabled'] if old else True)
            entry.setdefault('position', old['position'] if old else 1 + max(
                (r['position'] for r in current.values() if r['namespace'] == entry['namespace']), default=-1))
            entry.setdefault('memberships', old['memberships'] if old else ([content['category']] if entry['kind'] == 'technique' else []))
            entry['revision'] = revision + 1
            current[entry['id']] = entry
            changed.append(entry)
        CatalogSnapshot.build(revision + bool(changed), current.values())
        for record in changed:
            _write_record(conn, record)
        if changed:
            conn.execute('UPDATE catalog_state SET revision=revision+1 WHERE singleton=1')
    return {'revision': revision + bool(changed), 'changed': len(changed)}


def restore(path, document):
    """Restore a complete JSON export into an empty database, retaining all revisions."""
    records = read_document(document)
    required = {'position', 'enabled', 'revision', 'memberships'}
    if any(not required <= r.keys() or r['revision'] < 1 for r in records):
        raise CatalogError('incomplete_backup')
    revision = max(r['revision'] for r in records)
    CatalogSnapshot.build(revision, records)
    migrate(path)
    with _connection(path, write=True) as conn:
        _check_versions(conn)
        if conn.execute('SELECT revision FROM catalog_state WHERE singleton=1').fetchone()[0] != 0 or conn.execute('SELECT 1 FROM catalog_records LIMIT 1').fetchone():
            raise CatalogError('restore_requires_empty_database')
        for record in records:
            _write_record(conn, record)
        conn.execute('UPDATE catalog_state SET revision=? WHERE singleton=1', (revision,))
    return {'revision': revision, 'restored': len(records)}
