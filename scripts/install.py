"""Shared native Windows/macOS/Linux installer; standard library only.

Exit codes: 10 Python, 11 venv, 12 pip, 13 catalog, 14 egress, 15 MCP smoke.
Can also be run directly: python scripts/install.py --help.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


class InstallError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def run(command, code: int, description: str, verbose: bool, timeout=None) -> str:
    try:
        result = subprocess.run(
            [str(part) for part in command], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(code, f"{description}: {exc}") from exc
    if result.stdout and (verbose or result.returncode):
        say(result.stdout.rstrip())
    if result.stderr and (verbose or result.returncode):
        say(result.stderr.rstrip())
    if result.returncode:
        raise InstallError(code, description)
    return result.stdout.strip()


def client_configs(python: Path, lab: bool):
    # Keep the venv path: resolving its symlink on Unix selects the base Python.
    command = str(python.absolute())
    args = ["-m", "anticells_red_mcp.mcp_server.server"]
    env = {"ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS": "true"} if lab else {}
    return (
        {"mcp": {"anticells_red_mcp": {
            "type": "local", "command": [command, *args],
            "enabled": True, "environment": env,
        }}},
        {"mcpServers": {"anticells_red_mcp": {
            "command": command, "args": args, "env": env,
        }}},
    )


def install(options) -> None:
    say("==> 1/7  Checking Python >= 3.10")
    if sys.version_info < (3, 10):
        raise InstallError(10, "Python >= 3.10 is required")
    say(f"  [ok] {sys.executable} (Python {sys.version.split()[0]})")

    say("==> 2/7  Creating project-local virtual environment")
    venv = ROOT / ".venv"
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if options.reinstall and venv.exists():
        if Path(sys.prefix).resolve() == venv.resolve():
            raise InstallError(11, "cannot replace the running interpreter's .venv; use install.ps1 or install.sh")
        # Refuse a symlink/junction pointing outside this checkout before deletion.
        target = venv.resolve()
        if target != ROOT / ".venv":
            raise InstallError(11, "refusing to remove a linked .venv; remove the link manually")
        try:
            shutil.rmtree(target)
        except OSError as exc:
            raise InstallError(11, f"could not remove .venv: {exc}") from exc
    if not python.is_file():
        if venv.exists():
            raise InstallError(11, ".venv has no compatible interpreter; rerun with --reinstall")
        run([sys.executable, "-m", "venv", venv], 11, "venv creation failed", options.verbose)
    run([python, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"],
        11, ".venv is unusable; rerun with --reinstall", options.verbose)
    say(f"  [ok] {python}")

    say("==> 3/7  Installing dependencies and the package")
    run([python, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check",
         "pip", "wheel", "setuptools"], 12, "pip bootstrap failed", options.verbose)
    run([python, "-m", "pip", "install", "--disable-pip-version-check", ROOT],
        12, "package installation failed; rerun with --verbose", options.verbose)
    say("  [ok] package and runtime dependencies installed")

    say("==> 4/7  Initializing SQLite catalog (496 records)")
    output = run([python, "-m", "anticells_red_mcp.catalog.cli", "setup"],
                 13, "catalog initialization failed", options.verbose)
    try:
        catalog = json.loads(output)
        if catalog.get("schema_version") != 1:
            raise ValueError("unexpected schema_version")
    except (ValueError, AttributeError) as exc:
        raise InstallError(13, f"unexpected catalog response: {output}") from exc
    say(f"  [ok] catalog revision={catalog.get('revision')} changed={catalog.get('changed')}")

    say("==> 5/7  Running egress policy self-test")
    output = run([python, "-c",
                  "from anticells_red_mcp.mcp_server.endpoint_safety import self_test; "
                  "ok, reason = self_test(); print('OK' if ok else 'FAIL:' + reason)"],
                 14, "egress self-test crashed", options.verbose)
    if output != "OK":
        raise InstallError(14, f"egress self-test failed: {output}")
    say("  [ok] default egress policy")

    say("==> 6/7  Launching the real MCP server and checking its tools")
    output = run([python, ROOT / "scripts/post_install_smoke.py", ROOT],
                 15, "stdio smoke test failed", options.verbose, timeout=90)
    if not options.verbose:
        say(output)
    say("  [ok] stdio server, 12 tools, local mutation")

    say("==> 7/7  Ready. Merge the following into your client's configuration")
    opencode, claude = client_configs(python, options.lab)
    print("# OpenCode: merge the mcp key")
    print(json.dumps(opencode, indent=2))
    if os.name == "nt":
        claude_path = r"%APPDATA%\Claude\claude_desktop_config.json"
    elif sys.platform == "darwin":
        claude_path = "~/Library/Application Support/Claude/claude_desktop_config.json"
    else:
        claude_path = "~/.config/Claude/claude_desktop_config.json"
    print(f"\n# Claude Desktop ({claude_path}): merge mcpServers")
    print(json.dumps(claude, indent=2))
    say("  [ok] install complete; see docs/clients.md and SECURITY.md")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--lab", action="store_true", help="include private-network opt-in in client config")
    parser.add_argument("--reinstall", action="store_true", help="replace the project .venv")
    parser.add_argument("--venv", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    try:
        install(options)
    except InstallError as exc:
        say(f"  [FAIL] {exc}")
        return exc.code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
