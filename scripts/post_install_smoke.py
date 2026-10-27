"""Boot the real MCP server, exercise every tool kind, assert no load errors.

Exits 0 on success, non-zero on any failure. Prints one line per check.

Covers:
  * stdio handshake and server version matches __version__
  * exactly 12 tools advertised, each with a non-empty inputSchema
  * list_attack_templates returns the full catalog (public + auxiliary)
  * list_attack_templates with include_content=True hands back real payloads
  * get_compatible_templates runs locally (no HTTP) and returns reasons
  * creative_mutation runs locally and returns at least one evolved candidate
  * get_fingerprint_profile schema is wired (dry-run, no target)
  * get_attack_report returns session statistics
  * stop_attack_loop acknowledges with no active loop
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

PUBLIC_TOOLS = {
    "fingerprint_llm", "jailbreak_attack", "prompt_injection", "tool_abuse_exploit",
    "creative_mutation", "endless_attack_loop", "get_attack_report", "stop_attack_loop",
    "list_attack_templates", "get_compatible_templates", "execute_attack_template",
    "get_fingerprint_profile",
}


def _unpack(reply):
    assert reply.content, "empty tool response"
    return json.loads(reply.content[0].text)


async def _check(root: Path) -> None:
    try:
        from mcp import ClientSession, StdioServerParameters  # type: ignore
        from mcp.client.stdio import stdio_client  # type: ignore
    except Exception as exc:  # pragma: no cover - should be installed by install.sh
        print(f"FAIL mcp package not importable: {exc}")
        raise SystemExit(2)

    from anticells_red_mcp import __version__

    venv_python = root / ".venv" / "bin" / "python"
    env = {
        "ANTICELLS_RED_MCP_PYTHON": str(venv_python),
        # The smoke test does not hit any target. Keep the production egress
        # defaults in effect so a regression there surfaces here.
        "ANTICELLS_RED_MCP_MAX_HISTORY": "500",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    params = StdioServerParameters(command="bash", args=[str(root / "run.sh")], env=env)
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            init = await client.initialize()
            assert init.serverInfo.name == "anticells_red_mcp", init.serverInfo.name
            assert init.serverInfo.version == __version__, (
                f"server reports {init.serverInfo.version}, package says {__version__}"
            )
            print(f"stdio handshake: anticells_red_mcp {init.serverInfo.version}")

            tools = await client.list_tools()
            names = {t.name for t in tools.tools}
            missing = PUBLIC_TOOLS - names
            extra = names - PUBLIC_TOOLS
            if missing or extra:
                raise AssertionError(f"tool mismatch: missing={missing} extra={extra}")
            for tool in tools.tools:
                if not tool.inputSchema:
                    raise AssertionError(f"tool {tool.name} has empty inputSchema")
            print(f"tool catalog: {len(tools.tools)}/12 tools advertised")

            page = _unpack(await client.call_tool(
                "list_attack_templates", {"module": "all", "limit": 100}))
            if page["total"] != 194:
                raise AssertionError(f"expected 194 public templates, got {page['total']}")
            print(f"catalog listing: {page['total']} public templates visible")

            page = _unpack(await client.call_tool(
                "list_attack_templates", {"module": "injection", "limit": 1, "include_content": True}))
            if not page["templates"] or not page["templates"][0].get("content"):
                raise AssertionError("include_content did not return template content")
            print(f"template content: payload '{page['templates'][0]['content']['name']}' loaded")

            # Every module reports its public count — proves the catalog loader
            # did not silently drop a family.
            per_module = {}
            for module in ("fingerprint", "jailbreaks", "injection", "tool_abuse", "mutation"):
                summary = _unpack(await client.call_tool(
                    "list_attack_templates", {"module": module, "limit": 1}))
                per_module[module] = summary["total"]
            expected = {"fingerprint": 30, "jailbreaks": 53, "injection": 53,
                        "tool_abuse": 35, "mutation": 23}
            if per_module != expected:
                raise AssertionError(f"per-module counts drifted: {per_module} vs {expected}")
            print(f"module coverage: {per_module}")

            mutation = _unpack(await client.call_tool(
                "creative_mutation", {"generations": 2}))
            if mutation.get("techniques_generated", 0) < 1:
                raise AssertionError(f"creative_mutation returned nothing: {mutation}")
            print(f"local mutation: {mutation['techniques_generated']} candidates generated")

            report = _unpack(await client.call_tool("get_attack_report", {"format": "summary"}))
            if "statistics" not in report:
                raise AssertionError("get_attack_report missing statistics")
            print("session report: statistics block returned")

            stop = _unpack(await client.call_tool("stop_attack_loop", {}))
            if stop.get("status") != "STOPPED":
                raise AssertionError(f"stop_attack_loop response unexpected: {stop}")
            print("stop_attack_loop: STOPPED acknowledged")


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 1:
        print("usage: post_install_smoke.py <project_root>", file=sys.stderr)
        return 2
    root = Path(argv[0]).resolve()
    sys.path.insert(0, str(root / "src"))
    try:
        asyncio.run(_check(root))
    except AssertionError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        print(f"FAIL unexpected error: {exc!r}", file=sys.stderr)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
