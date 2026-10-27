"""Inspect and export reports without starting MCP or loading the prompt catalog."""
import argparse
import os
import shutil
import sys
from pathlib import Path

from .model import ReportError, json_text, export_content
from .repository import ReportRepository, reports_directory


def configuration():
    from ..mcp_server.config import MCPConfig
    from dotenv import dotenv_values
    env = {}
    if os.environ.get('ANTICELLS_RED_MCP_ENV_FILE'):
        try:
            with open(os.environ['ANTICELLS_RED_MCP_ENV_FILE'], encoding='utf-8') as stream:
                env.update(dotenv_values(stream=stream, interpolate=False))
        except OSError:
            raise ReportError('environment_file_unavailable') from None
    env.update(os.environ)
    return MCPConfig(reports_dir=env.get('ANTICELLS_RED_MCP_REPORTS_DIR'),
                     catalog_state_dir=env.get('ANTICELLS_RED_MCP_STATE_DIR'), target_environment=env)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Saved anticells_red_mcp research reports')
    parser.add_argument('--reports-dir', help='Override the private report directory')
    commands = parser.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list')
    listing.add_argument('--session-id')
    listing.add_argument('--limit', type=int, default=50)
    listing.add_argument('--offset', type=int, default=0)
    for name in ('show', 'export', 'delete'):
        command = commands.add_parser(name)
        selector = command.add_mutually_exclusive_group(required=True)
        selector.add_argument('--run-id')
        selector.add_argument('--session-id')
        if name == 'export':
            command.add_argument('--format', choices=['json', 'markdown', 'html'], default='json')
            command.add_argument('--output', help='Copy to a new file; existing files are never overwritten')
    args = parser.parse_args(argv)
    try:
        config = configuration()
        repo = ReportRepository(args.reports_dir or reports_directory(config))
        repo.initialize()
        if args.command == 'list':
            if not 1 <= args.limit <= 100 or args.offset < 0:
                raise ReportError('invalid_pagination')
            result = repo.list_runs(args.session_id, args.limit, args.offset)
        elif args.command == 'delete':
            result = repo.delete(args.run_id, args.session_id)
        else:
            doc = repo.snapshot(args.run_id, args.session_id)
            if args.command == 'show':
                result = export_content(doc)
                result = result.get('content', result)
            else:
                if args.output and Path(args.output).exists():
                    raise ReportError('output_exists')
                result = repo.create_export(doc, args.format)
                if args.output:
                    try:
                        with open(result['path'], 'rb') as source:
                            with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as destination:
                                shutil.copyfileobj(source, destination)
                        result['copied_to'] = str(Path(args.output).absolute())
                    except FileExistsError:
                        raise ReportError('output_exists') from None
                    except OSError:
                        raise ReportError('output_copy_failed') from None
        print(json_text(result))
        return 0
    except ReportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError:
        print('Report error (storage_unavailable).', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
