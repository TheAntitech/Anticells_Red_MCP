# Installation

Python 3.10+ and Git are required. Use PowerShell on native Windows and Bash on macOS/Linux. Commands below run from the repository root unless stated otherwise.

## Install with the guided script

On macOS/Linux:

```bash
git clone git@github.com:Wael-Rd/Anticells_Red_MCP-1.0.0.git Anticells_Red_MCP
cd Anticells_Red_MCP
bash install.sh
```

On native Windows, clone the repository, enter its directory, and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

The execution-policy setting applies only to that PowerShell process. Bash and WSL are unnecessary for native Windows installation and MCP connections. You can also run `py -3 scripts/install.py` directly with Python 3.10+.

The script creates or reuses `.venv`, installs the package, initializes the local catalog, checks the default egress policy, and exercises the MCP server. It prints configuration you can merge into your client.

| Bash/Python option | PowerShell option | Effect |
| :--- | :--- | :--- |
| `--verbose` | `-Verbose` | Show dependency installation and catalog output |
| `--lab` | `-Lab` | Include a private-network opt-in in the printed client configuration |
| `--reinstall` | `-Reinstall` | Remove and rebuild the existing project `.venv` |

Only use `--reinstall` when you intend to replace that virtual environment. It does not remove the separate application state directory.

To select an interpreter:

```bash
ANTICELLS_RED_MCP_PYTHON=/usr/bin/python3.12 bash install.sh
```

In PowerShell, set `$env:ANTICELLS_RED_MCP_PYTHON = 'C:\path\to\python.exe'` before running the installer. Otherwise it tries an existing project `.venv`, `py -3`, `python3`, and `python`, accepting Python 3.10+. The shell wrappers start the base interpreter so `--reinstall` / `-Reinstall` can replace the virtual environment safely.

## Install manually

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip wheel setuptools
.venv/bin/python -m pip install .
.venv/bin/anticells_red_mcp-catalog setup
.venv/bin/anticells_red_mcp-doctor
```

On Windows:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip wheel setuptools
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\anticells_red_mcp-catalog.exe setup
.venv\Scripts\anticells_red_mcp-doctor.exe
```

First-time setup seeds 496 records: 194 public templates and 302 supporting resources. Repeating setup preserves existing catalog data.

The project dependencies live in `.venv`. The catalog and reports use a separate per-user application data directory unless configured otherwise. See [.env.example](../.env.example) for storage settings; the example file is not loaded automatically.

## Verify the MCP connection

```bash
.venv/bin/python scripts/post_install_smoke.py "$PWD"
```

On Windows, run `.venv\Scripts\python.exe scripts/post_install_smoke.py .`.

The smoke test checks the stdio handshake, 12 tool schemas, catalog counts, local mutation, report statistics, and the stop-loop response. It does not contact a model target.

Directly running `.venv/bin/python -m anticells_red_mcp.mcp_server.server` (Windows: `.venv\Scripts\python.exe -m anticells_red_mcp.mcp_server.server`) waits for MCP input on stdin. Protocol messages use stdout; diagnostics use stderr. `bash run.sh` remains available on macOS/Linux.

## Update

```bash
git pull --ff-only
.venv/bin/python -m pip install --upgrade .
.venv/bin/anticells_red_mcp-catalog setup
.venv/bin/anticells_red_mcp-doctor
```

Restart the MCP client after updating. For development, install `.[dev]` in the virtual environment and run `python -m pytest -q` through that interpreter.

On Windows, use the executables under `.venv\Scripts\` for the update commands, or rerun `install.ps1` after pulling changes.

## Resolve setup errors

| Exit code | Check |
| :--- | :--- |
| `10` | Python is installed and at least version 3.10 |
| `11` | Python can create a virtual environment |
| `12` | Package and dependency installation completed |
| `13` | The catalog path is available and setup succeeds |
| `14` | The default egress policy passes its self-test |
| `15` | The real MCP smoke test completes |

Use `bash install.sh --verbose` or `powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Verbose` for diagnostic output. Continue with [client setup](clients.md) or [troubleshooting](troubleshooting.md).
