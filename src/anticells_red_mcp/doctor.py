"""`anticells_red_mcp-doctor` — re-run the install self-checks on demand.

Useful when:

  * An MCP client reports the server is down and you want a one-command
    verdict without digging through logs.
  * You updated the catalog or dependencies and want to confirm the server
    still boots cleanly.
  * You suspect the egress policy was weakened by an environment override.

Each check prints one line. The exit code is zero iff every check passes.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path

try:
    from . import __version__  # type: ignore
except Exception:  # pragma: no cover - should never happen when installed
    __version__ = "unknown"


DEPS = ("mcp", "httpx", "jsonschema", "rich", "structlog", "dotenv")


def _ok(msg: str) -> None:
    print(f"[ok]   {msg}")


def _fail(msg: str) -> int:
    print(f"[FAIL] {msg}", file=sys.stderr)
    return 1


def check_python() -> int:
    if sys.version_info < (3, 10):
        return _fail(f"python {platform.python_version()} < 3.10")
    _ok(f"python {platform.python_version()} on {platform.system()}")
    return 0


def check_deps() -> int:
    missing: list[str] = []
    versions = {}
    for name in DEPS:
        module_name = "dotenv" if name == "dotenv" else name
        try:
            importlib.import_module(module_name)
            try:
                versions[name] = importlib.metadata.version(
                    "python-dotenv" if name == "dotenv" else name
                )
            except importlib.metadata.PackageNotFoundError:
                versions[name] = "?"
        except Exception:
            missing.append(name)
    if missing:
        return _fail(f"missing dependencies: {', '.join(missing)}")
    _ok("runtime deps: " + ", ".join(f"{k}={v}" for k, v in sorted(versions.items())))
    return 0


def check_catalog() -> int:
    from .catalog.setup import prepare_database
    from .mcp_server.config import load_config
    try:
        config = load_config()
        result = prepare_database(config)
    except Exception as exc:
        return _fail(f"catalog prepare failed: {exc!r}")
    _ok(f"catalog revision={result.get('revision')} schema_version={result.get('schema_version')}")
    return 0


def check_egress() -> int:
    from .mcp_server.endpoint_safety import self_test
    try:
        ok, reason = self_test()
    except Exception as exc:
        return _fail(f"egress self-test crashed: {exc!r}")
    if not ok:
        return _fail(f"egress policy defective: {reason}")
    _ok("egress policy rejects loopback by default")
    return 0


def check_limits() -> int:
    from .mcp_server.limits import (
        max_history, max_requests_per_call, max_requests_per_session_per_minute,
    )
    caps = {
        "max_history": max_history(),
        "max_requests_per_call": max_requests_per_call(),
        "max_requests_per_session_per_min": max_requests_per_session_per_minute(),
    }
    _ok("limits: " + ", ".join(f"{k}={v}" for k, v in caps.items()))
    return 0


def check_env_visibility() -> int:
    from .mcp_server.config import _template_env_default
    visible = sorted(_template_env_default())
    if not visible:
        _ok("template env visibility: EMPTY (good; set ANTICELLS_RED_MCP_TEMPLATE_ENV to opt in)")
        return 0
    _ok(f"template env visibility (operator-authorized): {', '.join(visible)}")
    return 0


def check_overrides() -> int:
    flags = {
        "ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS": os.environ.get("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", ""),
        "ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS": os.environ.get("ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS", ""),
        "ANTICELLS_RED_MCP_TARGET_DENY_HOSTS": os.environ.get("ANTICELLS_RED_MCP_TARGET_DENY_HOSTS", ""),
        "ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION": os.environ.get("ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION", ""),
    }
    active = {k: v for k, v in flags.items() if v}
    if not active:
        _ok("egress overrides: none active (production default)")
    else:
        _ok("egress overrides: " + json.dumps(active, sort_keys=True))
    return 0


def main(argv=None) -> int:
    print(f"anticells_red_mcp doctor {__version__}")
    checks = (check_python, check_deps, check_catalog, check_egress,
              check_limits, check_env_visibility, check_overrides)
    failures = 0
    for check in checks:
        failures += check()
    if failures:
        print(f"\n{failures} check(s) failed", file=sys.stderr)
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
