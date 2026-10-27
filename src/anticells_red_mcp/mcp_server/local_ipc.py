"""Wake asyncio's anonymous local self-pipe using file-descriptor writes.

Some managed environments reject socket.send even for anonymous local socket
pairs. asyncio normally ignores that error and its thread callbacks then wait
for an unrelated timer. os.write uses the same local descriptor and preserves
the event loop's wakeup protocol without changing network access or MCP I/O.
"""
import asyncio
import os


class LocalIPCEventLoop(asyncio.SelectorEventLoop):
    def _write_to_self(self) -> None:
        channel = self._csock
        if channel is None:
            return
        try:
            os.write(channel.fileno(), b"\0")
        except OSError:
            # Match asyncio: a closed/full self-pipe during shutdown is benign.
            pass


class LocalIPCPolicy(asyncio.DefaultEventLoopPolicy):
    def new_event_loop(self) -> asyncio.AbstractEventLoop:
        return LocalIPCEventLoop()
