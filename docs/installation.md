# Installation

Python 3.10+, Git, and Bash are required. Use WSL on Windows. Commands below run from the repository root unless stated otherwise.

## Install with the guided script

```bash
git clone git@github.com:Wael-Rd/Anticells_Red_MCP-1.0.0.git Anticells_Red_MCP
cd Anticells_Red_MCP
bash install.sh
```

The script creates or reuses `.venv`, installs the package, initializes the local catalog, checks the default egress policy, and exercises the MCP server. It prints configuration you can merge into your client.

| Option | Effect |
| :--- | :--- |
| `--verbose` | Show dependency installation and catalog output |
| `--lab` | Include a private-network opt-in in the printed client configuration |
| `--reinstall` | Remove and rebuild the existing project `.venv` |

Only use `--reinstall` when you intend to replace that virtual environment. It does not remove the separate application state directory.

To select an interpreter:

```bash
ANTICELLS_RED_MCP_PYTHON=/usr/bin/python3.12 bash install.sh
```

## Install manually

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip wheel setuptools
.venv/bin/python -m pip install .
.venv/bin/anticells_red_mcp-catalog setup
.venv/bin/anticells_red_mcp-doctor
```

First-time setup seeds 496 records: 194 public templates and 302 supporting resources. Repeating setup preserves existing catalog data.

The project dependencies live in `.venv`. The catalog and reports use a separate per-user application data directory unless configured otherwise. See [.env.example](../.env.example) for storage settings; the example file is not loaded automatically.

## Verify the MCP connection

```bash
.venv/bin/python scripts/post_install_smoke.py "$PWD"
```

The smoke test checks the stdio handshake, 12 tool schemas, catalog counts, local mutation, report statistics, and the stop-loop response. It does not contact a model target.

Running `bash run.sh` directly waits for MCP input on stdin. Protocol messages use stdout; diagnostics use stderr.

## Update

```bash
git pull --ff-only
.venv/bin/python -m pip install --upgrade .
.venv/bin/anticells_red_mcp-catalog setup
.venv/bin/anticells_red_mcp-doctor
```

Restart the MCP client after updating. For development, install `.[dev]` in the virtual environment and run `python -m pytest -q` through that interpreter.

## Resolve setup errors

| Exit code | Check |
| :--- | :--- |
| `10` | Python is installed and at least version 3.10 |
| `11` | Python can create a virtual environment |
| `12` | Package and dependency installation completed |
| `13` | The catalog path is available and setup succeeds |
| `14` | The default egress policy passes its self-test |
| `15` | The real MCP smoke test completes |

Use `bash install.sh --verbose` for diagnostic output. Continue with [client setup](clients.md) or [troubleshooting](troubleshooting.md).
