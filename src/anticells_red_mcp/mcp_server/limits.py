# ♢ 𝓜𝖗𝚇₀𝚛𝚍 ⚡🖤  —  memory + request-amplification caps (F3, F4)
"""Runtime bounds that keep a long-lived MCP process from growing without end.

Three limits, all operator-configurable through the process environment:

``ANTICELLS_RED_MCP_MAX_HISTORY``
    Maximum number of in-memory session records retained for
    ``get_attack_report`` (current-process view). Older records are dropped
    from the head of the list; persisted saved records in SQLite are
    unaffected. Default: ``2000``.

``ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL``
    Hard ceiling on the number of outbound HTTP requests a single tool
    invocation is allowed to issue. Techniques beyond the cap are skipped
    with a stable reason. Default: ``20``. Set ``0`` to disable the cap for
    operators who need the original research throughput.

``ANTICELLS_RED_MCP_MAX_REQUESTS_PER_SESSION_PER_MIN``
    Rolling per-minute cap on outbound requests across the whole MCP
    session. Default: ``500``. Set ``0`` to disable.
"""
from __future__ import annotations

import os
import time
from collections import deque
from threading import Lock
from typing import Deque, MutableSequence


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


def max_history() -> int:
    return max(0, _int_env("ANTICELLS_RED_MCP_MAX_HISTORY", 2000))


def max_requests_per_call() -> int:
    return max(0, _int_env("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL", 20))


def max_requests_per_session_per_minute() -> int:
    return max(0, _int_env("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_SESSION_PER_MIN", 500))


def trim(records: MutableSequence) -> None:
    """Trim an in-memory record list to the configured history cap."""
    cap = max_history()
    if cap and len(records) > cap:
        del records[: len(records) - cap]


class SessionRateLimiter:
    """Thread-safe rolling-window request counter for the whole MCP session."""

    def __init__(self) -> None:
        self._events: Deque[float] = deque()
        self._lock = Lock()

    def check(self) -> None:
        cap = max_requests_per_session_per_minute()
        if cap <= 0:
            return
        now = time.monotonic()
        with self._lock:
            cutoff = now - 60.0
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            if len(self._events) >= cap:
                from .targets import TargetConfigurationError
                raise TargetConfigurationError("session_request_rate_limited")
            self._events.append(now)


session_limiter = SessionRateLimiter()
