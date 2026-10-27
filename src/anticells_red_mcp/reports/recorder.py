"""Best-effort serialized persistence, with stable IDs and an in-memory retry queue."""
import asyncio
import copy
import contextlib
import sys

from .model import now, new_id, Sanitizer, document, ReportError
from .repository import SessionLock
from ..mcp_server.limits import trim as _trim_history


class Run:
    def __init__(self, recorder, tool, settings, config, revision):
        self.recorder = recorder
        self.sanitizer = Sanitizer(config)
        self.seen = {}
        self.data = dict(id=new_id(), session_id=recorder.session['id'], tool=tool,
                         created_at=now(), ended_at=None, status='running', catalog_revision=revision,
                         persistence_status='saved', settings=self.sanitizer.clean(settings))
        self.records = []

    def configure(self, config):
        from .model import endpoint
        self.sanitizer.configure(config)
        target = config.target.label if config.target else endpoint(config.target_api_url or 'local')
        self.data['target'] = self.sanitizer.clean(target)
        self.data['settings']['target_model'] = self.sanitizer.clean(config.target_model)

    async def record(self, result, evidence=None, *, refresh=False):
        from dataclasses import asdict, is_dataclass
        # Keep object references until this run ends, so Python cannot reuse an id.
        existing = self.seen.get(id(result))
        if existing is not None and not refresh:
            return
        raw = asdict(result) if is_dataclass(result) else copy.deepcopy(result)
        raw.setdefault('timestamp', now())
        if raw.get('module') == 'mutation':
            raw.update(success=False, confidence=0.0)
        item = dict(id=new_id(), run_id=self.data['id'], created_at=now(),
                    result=self.sanitizer.clean(raw), evidence=self.sanitizer.clean(evidence or {}))
        if 'module' in raw:
            item['result']['module'] = raw['module']
        # HTTP headers may contain Set-Cookie or echoed credentials; never archive them.
        item['result'].pop('headers', None)
        if self.data['tool'] == 'get_fingerprint_profile' and isinstance(item['result'].get('response_text'), str):
            item['result']['response_snippet'] = item['result']['response_text'][:300]
        if existing is not None:
            index = existing[1]
            previous = self.records[index]
            item.update(id=previous['id'], created_at=previous['created_at'], evidence=previous['evidence'])
            self.records[index] = item
        else:
            self.seen[id(result)] = (result, len(self.records))
            self.records.append(item)
            _trim_history(self.records)
        await self.recorder.enqueue('result', item)

    async def finish(self, status='completed', error=None):
        if self.data['status'] != 'running':
            return
        self.data.update(status=status, ended_at=now())
        if error:
            self.data['error'] = self.sanitizer.clean(error)
        await self.recorder.enqueue('run', self.data)
        self.seen.clear()

    def metadata(self):
        return dict(run_id=self.data['id'], session_id=self.data['session_id'],
                    persistence=self.recorder.persistence())


class Recorder:
    def __init__(self, repository):
        self.repository = repository
        self.session = dict(id=new_id(), created_at=now(), status='active')
        self.runs = {}
        self.pending = []
        self.lock = asyncio.Lock()
        self.lease = None
        self.ready = False
        self.task = None
        self.warning = False

    def persistence(self):
        return dict(status='pending' if self.pending or not self.ready else 'saved',
                    pending_records=sum(kind == 'result' for kind, _ in self.pending),
                    warning=('Saving reports is unavailable; testing continues. Unsaved evidence is held in memory '
                             'and may be lost if this process exits before recovery.' if self.pending or not self.ready else None))

    async def start(self):
        await self.enqueue('session', self.session)
        self.task = asyncio.create_task(self._retry())

    def _write(self, events):
        if not self.ready:
            self.repository.initialize()
            if self.lease is None:
                self.lease = SessionLock(self.repository.root, self.session['id'])
                if not self.lease.acquire():
                    self.lease = None
                    raise ReportError('session_lock_unavailable')
            self.ready = True
        self.repository.write(events)

    async def enqueue(self, kind, value):
        self.pending.append((kind, copy.deepcopy(value)))
        if not self.warning:
            await self.flush()

    async def flush(self):
        async with self.lock:
            if not self.pending:
                return
            events = list(self.pending)
            worker = asyncio.create_task(asyncio.to_thread(self._write, events))
            cancelled = False
            try:
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    cancelled = True
                    await worker
                del self.pending[:len(events)]
                self.warning = False
            except Exception:
                if not self.warning:
                    print('Report persistence unavailable; unsaved evidence remains in memory.', file=sys.stderr)
                    self.warning = True
            if cancelled:
                raise asyncio.CancelledError()

    async def _retry(self):
        while True:
            await asyncio.sleep(5)
            await self.flush()

    async def begin(self, tool, args, config, revision):
        # Do not save target definitions, arbitrary variable overrides, or auth settings.
        safe = dict({
            'fingerprint_llm': {'intensity': 3, 'techniques': []},
            'get_fingerprint_profile': {'intensity': 1},
            'jailbreak_attack': {'category': 'all', 'intensity': 3},
            'prompt_injection': {'injection_type': 'all'},
            'tool_abuse_exploit': {'exploit_category': 'all'},
            'creative_mutation': {'generations': 10, 'creativity_level': .9},
            'endless_attack_loop': {'mode': 'evolutionary', 'max_iterations': 1},
        }.get(tool, {}))
        safe.update({k: v for k, v in args.items() if k in {
            'intensity', 'techniques', 'category', 'injection_type', 'exploit_category',
            'generations', 'creativity_level', 'mode', 'max_iterations'}})
        if tool == 'execute_attack_template':
            safe.update({k: args[k] for k in ('template_id', 'catalog_revision') if k in args})
        if tool == 'get_fingerprint_profile':
            safe.update({k: args[k] for k in ('template_ids', 'catalog_revision') if k in args})
        run = Run(self, tool, safe, config, revision)
        run.configure(config)
        self.runs[run.data['id']] = run
        await self.enqueue('run', run.data)
        return run

    async def snapshot(self, run_id=None, session_id=None):
        from .model import identifier
        identifier(run_id or session_id)
        await self.flush()
        local = [r for r in self.runs.values() if (r.data['id'] == run_id if run_id else r.data['session_id'] == session_id)]
        try:
            saved = await asyncio.to_thread(self.repository.snapshot, run_id, session_id)
            if not self.pending:
                return saved
        except ReportError as exc:
            if exc.code in {'run_not_found', 'session_not_found'} and not self.pending:
                raise
            if not local and session_id != self.session['id']:
                raise
        if local or session_id == self.session['id']:
            # The current process includes pending evidence and is authoritative for its runs.
            return document([copy.deepcopy(self.session)], [copy.deepcopy(r.data) for r in local],
                            [copy.deepcopy(x) for r in local for x in r.records], self.persistence())
        return await asyncio.to_thread(self.repository.snapshot, run_id, session_id)

    async def export(self, fmt, run_id=None, session_id=None):
        doc = None
        if not run_id and not session_id:
            completed = [r for r in self.runs.values() if r.data['status'] == 'completed']
            for run in sorted(completed, key=lambda r: r.data['ended_at'], reverse=True):
                try:
                    doc = await self.snapshot(run_id=run.data['id'])
                    break
                except ReportError as exc:
                    if exc.code != 'run_not_found':
                        raise
            if doc is None:
                raise ReportError('no_completed_run')
        else:
            doc = await self.snapshot(run_id, session_id)
        return await asyncio.to_thread(self.repository.create_export, doc, fmt)

    async def close(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
        for run in self.runs.values():
            await run.finish('interrupted')
        self.session.update(status='closed', ended_at=now())
        await self.enqueue('session', self.session)
        await self.flush()
        if self.pending:
            print('Report shutdown warning: unsaved evidence could not be persisted.', file=sys.stderr)
        if self.lease:
            await asyncio.to_thread(self.lease.close)
