# Contributing to Anticells Red MCP

Contributions are welcome from anyone, including people new to the project. Useful contributions include documentation, bug reports, tests, code fixes, and research templates. Read the [project guide](PROJECT_GUIDE.md) for an overview and the [ethical considerations](README.md#ethical-considerations) before running assessments.

## Security reports

**Security reports must follow [SECURITY.md](SECURITY.md#report-a-vulnerability), not public issues.** Do not publish vulnerabilities, exploit details, credentials, or private evidence in issues or pull requests. Use the private reporting process and any contact fallback described in that policy. Public issues are appropriate for ordinary bugs, documentation problems, and feature ideas.

## Start a contribution

Anyone can fork the repository and open a pull request. If you already have write access, you may use a branch in this repository instead. Target the `main` branch and keep each PR focused on one change.

For a fork, replace `YOUR_USERNAME` with your GitHub username:

```text
git clone https://github.com/YOUR_USERNAME/Anticells_Red_MCP.git
cd Anticells_Red_MCP
git remote add upstream https://github.com/TheAntitech/Anticells_Red_MCP.git
git switch -c your-change
```

Collaborators using a repository branch can clone `https://github.com/TheAntitech/Anticells_Red_MCP.git` directly. A linked issue is helpful when one exists, but is not required. For a substantial design change, an early discussion can help establish its scope. Keep discussion constructive and review the change rather than the person contributing it.

## Development setup

Use Python 3.10 or later with `venv`, `ensurepip`, and `sqlite3`, plus Git. Run commands from the repository root. Install the development extra in editable mode so application imports use your checkout.

On macOS/Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip wheel setuptools
.venv/bin/python -m pip install -e '.[dev]'
export ANTICELLS_RED_MCP_STATE_DIR="$HOME/.local/share/anticells_red_mcp-dev"
export ANTICELLS_RED_MCP_REPORTS_DIR="$ANTICELLS_RED_MCP_STATE_DIR/reports"
```

On native Windows, use PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip wheel setuptools
.venv\Scripts\python.exe -m pip install -e '.[dev]'
$env:ANTICELLS_RED_MCP_STATE_DIR = Join-Path $env:LOCALAPPDATA 'anticells_red_mcp-dev'
$env:ANTICELLS_RED_MCP_REPORTS_DIR = Join-Path $env:ANTICELLS_RED_MCP_STATE_DIR 'reports'
```

Select a Python 3.10+ interpreter explicitly if your default is older. The state settings above keep manual checks separate from the application's normal catalog and reports; directories are created when needed. Use synthetic data and a dedicated development environment. No model API key, external database, or live target is needed for the regression suite or MCP smoke test.

See [installation](docs/installation.md) for guided setup and troubleshooting. `.env` files are loaded only when explicitly selected; use [.env.example](.env.example) as a reference and follow its process-environment requirements for security controls.

## Testing and compatibility

Add focused regression coverage for bug fixes and tests for changed behavior. Use temporary SQLite databases and mocked HTTP rather than real services. Preserve the default egress policy, credential boundaries, request limits, and report isolation.

Run the full suite and the real local MCP smoke test before marking a PR ready for review.

On macOS/Linux:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m anticells_red_mcp.catalog.cli setup
.venv/bin/python scripts/post_install_smoke.py .
git diff --check
```

On Windows:

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m anticells_red_mcp.catalog.cli setup
.venv\Scripts\python.exe scripts/post_install_smoke.py .
git diff --check
```

Before merging, the full pytest suite and **all six jobs** in the [Installer compatibility workflow](.github/workflows/compatibility.yml) must pass: Windows, macOS, and Ubuntu, each with Python 3.10 and 3.12. Run local checks on your own platform; CI covers the complete matrix. A maintainer can help if a fork's workflow runs need approval. Investigate failures rather than removing regression coverage or weakening assertions to obtain a passing result.

## Pull-request expectations

- Explain the problem, the resulting behavior, and the scope of the change. Include reproduction steps for a bug when possible.
- Report the validation commands you ran, their results, and any platform limitations or remaining concerns.
- Include relevant tests, documentation, and changelog updates in the same PR. Keep unrelated refactoring and generated files out of the diff.
- Request maintainer review, respond to feedback, and keep the branch current with `main` when resolving conflicts.
- Keep credentials, private target configuration, local SQLite databases, reports, and captured user data out of commits and public discussion. Review staged files even when they match [.gitignore](.gitignore).

Use a clear PR title and description. Conventional commit titles, signed-off commits, and linked issues are not required. Maintainer review and the checks above are required before merging.

## Catalog and template contributions

Start with the [catalog authoring guide](docs/catalogs.md#add-a-technique), the [manifest](src/anticells_red_mcp/catalog/data/manifest.json), and [example technique](config/technique.example.json). Explain the research purpose, expected behavior, and limitations of a new template. Include provenance for third-party material and submit only content you are permitted to share under the repository's [license](LICENSE).

Create and validate reviewable JSON using the catalog CLI:

```bash
.venv/bin/anticells_red_mcp-catalog new --namespace injection.direct --category direct --name example_probe --output my-probe.json
.venv/bin/anticells_red_mcp-catalog validate my-probe.json
```

On Windows, use `.venv\Scripts\anticells_red_mcp-catalog.exe` with the same arguments.

- Use existing namespaces, categories, schemas, and memberships. A new engine, namespace, or category also needs the corresponding code, manifest, tests, and documentation.
- Preserve stable IDs when updating a published record, and retain the exported revision for updates. Follow the CLI's `--update` and stale-revision rules when testing local imports.
- Preserve existing ordering, duplicate-name distinctions, structured payloads, and exceptional Unicode. Retain `encoded_content` envelopes when ordinary JSON cannot preserve the original value exactly.
- Preserve the named placeholders declared for supporting templates. Do not add expressions or executable substitutions to those format templates.
- Submit JSON and source changes, not a local database or report export. Importing JSON changes only your local catalog; changing packaged defaults also requires an explicit change to the packaged seed and, where applicable, the manifest and regression fixtures.
- Existing catalog content has compatibility checks. Explain any intentional changes to baseline content, counts, fixtures, or digests; do not rewrite fixtures merely to hide a regression. Validate additions and updates in the isolated development catalog before submitting them.

## Documentation and changelog

Update affected guides whenever commands, environment settings, schemas, defaults, catalog content, or behavior change. Include native Windows and macOS/Linux instructions where they differ. Check relative links, heading anchors, JSON examples, and copy-paste commands. Use repository-relative links rather than paths tied to your own machine.

Add an **Unreleased** entry to [CHANGELOG.md](CHANGELOG.md) for user-visible changes and fixes, including significant catalog or documentation changes. Describe the resulting behavior and any compatibility or migration implications. Preserve historical release notes and dated verification records; record new validation separately rather than presenting older results as current checks.
