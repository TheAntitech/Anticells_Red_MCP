"""Short SQLite transactions. All methods are synchronous worker-thread APIs."""
import base64
import hashlib
import os
import sqlite3
import contextlib
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path

from .model import ReportError, encode, decode, now, new_id, identifier, document, render


def reports_directory(config):
    from ..catalog.setup import state_directory
    return Path(config.reports_dir).expanduser().absolute() if config.reports_dir else state_directory(config) / 'reports'


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != 'nt':
        path.chmod(0o700)


class SessionLock:
    """Kernel locks are released on crashes; PIDs alone are not reliable leases."""
    def __init__(self, root, session_id):
        identifier(session_id)
        private_directory(root / 'locks')
        self.path = root / 'locks' / (session_id + '.lock')
        self.file = None

    def acquire(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        self.file = os.fdopen(fd, 'r+b', buffering=0)
        try:
            if os.name == 'nt':
                import msvcrt
                if self.path.stat().st_size == 0:
                    self.file.write(b'0')
                self.file.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.file.close()
            self.file = None
            return False

    def close(self):
        if self.file:
            if os.name == 'nt':
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            self.file.close()
            self.file = None


class ReportRepository:
    def __init__(self, directory):
        self.root = Path(directory).expanduser().absolute()
        self.path = self.root / 'reports.sqlite3'

    @contextmanager
    def connection(self, write=False, create=False):
        con = None
        try:
            if create:
                private_directory(self.root)
                try:
                    os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                except FileExistsError:
                    pass
            uri = self.path.as_uri() + ('?mode=rw' if write else '?mode=ro')
            con = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
            con.execute('PRAGMA foreign_keys=ON')
            con.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            yield con
            con.commit()
        except ReportError:
            raise
        except Exception:
            raise ReportError('storage_unavailable') from None
        finally:
            if con:
                con.close()

    @staticmethod
    def check(con):
        versions = [r[0] for r in con.execute('SELECT version FROM report_schema_migrations ORDER BY version')]
        if versions != [1]:
            raise ReportError('incompatible_schema')

    def initialize(self):
        with self.connection(write=True, create=True) as con:
            exists = con.execute("SELECT 1 FROM sqlite_master WHERE name='report_schema_migrations'").fetchone()
            if not exists:
                sql = files(__package__).joinpath('migrations/001_reports.sql').read_text(encoding='utf-8')
                statement = ''
                for line in sql.splitlines(True):
                    statement += line
                    if sqlite3.complete_statement(statement):
                        con.execute(statement)
                        statement = ''
            self.check(con)
        private_directory(self.root / 'exports')
        self.recover()

    def recover(self):
        with self.connection(write=True) as con:
            self.check(con)
            for sid, raw in con.execute("SELECT id, document FROM sessions WHERE status='active'").fetchall():
                lock = SessionLock(self.root, sid)
                if not lock.acquire():
                    continue
                try:
                    session = decode(raw)
                    session.update(status='interrupted', ended_at=now())
                    self._put(con, 'session', session)
                    for (data,) in con.execute("SELECT document FROM runs WHERE session_id=? AND status='running'", (sid,)).fetchall():
                        run = decode(data)
                        run.update(status='interrupted', ended_at=now(), persistence_status='unknown_after_interruption')
                        self._put(con, 'run', run)
                finally:
                    lock.close()

    @staticmethod
    def _put(con, kind, item):
        if kind == 'session':
            con.execute('INSERT INTO sessions VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, document=excluded.document',
                        (item['id'], item['created_at'], item['status'], encode(item)))
        elif kind == 'run':
            con.execute('INSERT INTO runs VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, document=excluded.document',
                        (item['id'], item['session_id'], item['created_at'], item['status'], encode(item)))
        elif kind == 'result':
            con.execute('INSERT INTO results VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document',
                        (item['id'], item['run_id'], item['created_at'], encode(item)))

    def write(self, events):
        with self.connection(write=True) as con:
            self.check(con)
            for kind, item in events:
                self._put(con, kind, item)

    def list_runs(self, session_id=None, limit=50, offset=0):
        if session_id:
            identifier(session_id)
        self.recover()
        with self.connection() as con:
            self.check(con)
            condition, params = (' WHERE session_id=?', [session_id]) if session_id else ('', [])
            total = con.execute('SELECT count(*) FROM runs' + condition, params).fetchone()[0]
            rows = con.execute('SELECT document FROM runs' + condition + ' ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?', params + [limit, offset])
            return dict(runs=[decode(r[0]) for r in rows], total=total, offset=offset,
                        next_offset=offset + limit if offset + limit < total else None)

    def snapshot(self, run_id=None, session_id=None):
        if bool(run_id) == bool(session_id):
            raise ReportError('selector_required')
        identifier(run_id or session_id)
        self.recover()
        with self.connection() as con:
            self.check(con)
            if run_id:
                row = con.execute('SELECT session_id FROM runs WHERE id=?', (run_id,)).fetchone()
                if not row:
                    raise ReportError('run_not_found')
                session_id = row[0]
            row = con.execute('SELECT document FROM sessions WHERE id=?', (session_id,)).fetchone()
            if not row:
                raise ReportError('session_not_found')
            condition, params = ('id=?', (run_id,)) if run_id else ('session_id=?', (session_id,))
            runs = [decode(r[0]) for r in con.execute('SELECT document FROM runs WHERE ' + condition + ' ORDER BY created_at,id', params)]
            results = []
            for run in runs:
                results.extend(decode(r[0]) for r in con.execute('SELECT document FROM results WHERE run_id=? ORDER BY created_at,id', (run['id'],)))
            incomplete = any(r.get('persistence_status') != 'saved' for r in runs)
            return document([decode(row[0])], runs, results,
                            {'status': 'incomplete' if incomplete else 'saved', 'pending_records': 0})

    def create_export(self, doc, fmt):
        ext, mime = {'json': ('json', 'application/json'), 'markdown': ('md', 'text/markdown'),
                     'html': ('html', 'text/html')}.get(fmt, (None, None))
        if ext is None:
            raise ReportError('invalid_export_format')
        eid = new_id()
        filename = f'report-{eid}.{ext}'
        path = self.root / 'exports' / filename
        temporary = path.with_suffix('.tmp')
        data = render(doc, fmt)
        info = dict(id=eid, export_id=eid, filename=filename, path=str(path), mime_type=mime,
                    byte_count=len(data), sha256=hashlib.sha256(data).hexdigest(), created_at=now(),
                    uri='anticells-report://exports/' + eid, partial=doc['partial'], persistence=doc['persistence'])
        reserved = temporary_created = False
        try:
            if path.parent.is_symlink():
                raise ReportError('invalid_export_path')
            private_directory(path.parent)
            with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                temporary_created = True
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # Unique UUIDs plus an exclusive final reservation prevent overwrites.
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            reserved = True
            os.replace(temporary, path)
            with self.connection(write=True) as con:
                con.execute('INSERT INTO exports VALUES (?,?,?,?)', (eid, filename, info['created_at'], encode(info)))
                for run in doc['runs']:
                    con.execute('INSERT INTO export_runs VALUES (?,?)', (eid, run['id']))
            return info
        except Exception:
            with contextlib.suppress(OSError):
                if temporary_created:
                    temporary.unlink(missing_ok=True)
                if reserved:
                    path.unlink(missing_ok=True)
            raise ReportError('export_failed') from None

    def list_exports(self, limit=50, offset=0):
        with self.connection() as con:
            self.check(con)
            return [decode(r[0]) for r in con.execute('SELECT document FROM exports ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?', (limit, offset))]

    def list_exports_for_session(self, session_id, limit=50, offset=0):
        """Exports whose runs all belong to a given MCP session.

        Scopes :meth:`list_exports` so one MCP client cannot enumerate another
        client's exports on the same user account.
        """
        from .model import identifier
        identifier(session_id)
        with self.connection() as con:
            self.check(con)
            rows = con.execute(
                'SELECT e.document FROM exports e '
                'WHERE EXISTS (SELECT 1 FROM export_runs er JOIN runs r ON r.id = er.run_id '
                '              WHERE er.export_id = e.id AND r.session_id = ?) '
                'ORDER BY e.created_at DESC, e.id DESC LIMIT ? OFFSET ?',
                (session_id, limit, offset),
            ).fetchall()
            return [decode(r[0]) for r in rows]

    def export_info(self, export_id):
        identifier(export_id)
        with self.connection() as con:
            row = con.execute('SELECT document FROM exports WHERE id=?', (export_id,)).fetchone()
            if not row:
                raise ReportError('export_not_found')
            info = decode(row[0])
        # Never trust a stored or user-supplied path, including after a backup restore.
        expected = {f'report-{export_id}.{ext}' for ext in ('json', 'md', 'html')}
        if info['filename'] not in expected:
            raise ReportError('invalid_export_path')
        path = self.root / 'exports' / info['filename']
        if path.is_symlink() or path.parent.is_symlink() or path.resolve().parent != (self.root / 'exports').resolve():
            raise ReportError('invalid_export_path')
        info['path'] = str(path)
        return info

    def read_export(self, export_id, offset=0, length=65536, whole=False):
        info = self.export_info(export_id)
        if type(offset) is not int or not 0 <= offset <= info['byte_count'] or type(length) is not int or not 1 <= length <= 65536:
            raise ReportError('invalid_chunk')
        if whole and info['byte_count'] > 1048576:
            raise ReportError('resource_too_large_use_chunked_read')
        try:
            with open(info['path'], 'rb') as stream:
                stream.seek(offset)
                data = stream.read(1048577 if whole else length)
            if whole:
                if len(data) > 1048576:
                    raise ReportError('resource_too_large_use_chunked_read')
                return data, info
            return dict(export_id=export_id, offset=offset, next_offset=offset + len(data),
                        eof=offset + len(data) >= info['byte_count'], encoding='base64',
                        data=base64.b64encode(data).decode('ascii'), byte_count=info['byte_count'], sha256=info['sha256'])
        except OSError:
            raise ReportError('export_unavailable') from None

    def delete(self, run_id=None, session_id=None):
        doc = self.snapshot(run_id, session_id)
        export_ids = set()
        paths = []
        with self.connection(write=True) as con:
            for run in doc['runs']:
                row = con.execute('SELECT status FROM runs WHERE id=?', (run['id'],)).fetchone()
                if row and row[0] == 'running':
                    raise ReportError('active_run')
                export_ids.update(r[0] for r in con.execute('SELECT export_id FROM export_runs WHERE run_id=?', (run['id'],)))
            for eid in export_ids:
                paths.append(Path(self.export_info(eid)['path']))
                con.execute('DELETE FROM exports WHERE id=?', (eid,))
            for run in doc['runs']:
                con.execute('DELETE FROM runs WHERE id=?', (run['id'],))
            if session_id:
                if con.execute("SELECT 1 FROM sessions WHERE id=? AND status='active'", (session_id,)).fetchone():
                    raise ReportError('active_session')
                con.execute('DELETE FROM sessions WHERE id=?', (session_id,))
        try:
            for path in paths:
                path.unlink(missing_ok=True)
        except OSError:
            raise ReportError('export_cleanup_failed') from None
        return dict(deleted_runs=len(doc['runs']), deleted_exports=len(paths))
