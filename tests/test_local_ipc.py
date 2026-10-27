"""Exercise the thread wakeup and subprocess pipes required by MCP stdio."""
import asyncio
import sys


def test_thread_wakeup_and_subprocess_pipes():
    async def check():
        # The server reads stdio in worker threads. Their results must wake the
        # loop without waiting for an unrelated timer or network event.
        assert await asyncio.wait_for(asyncio.to_thread(lambda: "awake"), 2) == "awake"
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "print('stdio-ok')",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        output, errors = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0, errors
        assert output.strip() == b"stdio-ok"

    # conftest installs the same LocalIPCPolicy used by the server.
    asyncio.run(check())
