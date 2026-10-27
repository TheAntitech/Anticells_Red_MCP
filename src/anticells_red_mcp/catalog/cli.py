"""Explicit database administration and JSON authoring; never part of MCP stdio."""
import argparse
import json
import sys
import uuid
from pathlib import Path

from .model import CatalogError, import_content, export_content, manifest, read_document
from .repository import migrate, publish, read_sync, restore
from .seed import seed_document


def read_file(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError):
        raise CatalogError('authoring_file_unavailable_or_invalid') from None


def output(value, path=None):
    text = json.dumps(value, ensure_ascii=True, indent=2) + '\n'
    if path:
        try:
            Path(path).write_text(text, encoding='utf-8')
        except OSError:
            raise CatalogError('output_file_unavailable') from None
    else:
        print(text, end='')


def parser():
    root = argparse.ArgumentParser(prog='anticells_red_mcp-catalog', description=__doc__)
    commands = root.add_subparsers(dest='command', required=True)
    commands.add_parser('setup', help='Create the local SQLite database and initialize the catalog')
    commands.add_parser('migrate')
    commands.add_parser('seed')
    create = commands.add_parser('new', help='Create a technique example or edit an existing template collection')
    group = create.add_mutually_exclusive_group(required=True)
    group.add_argument('--namespace')
    group.add_argument('--template', help='Existing template/data resource ID to edit')
    create.add_argument('--name', default='new_technique')
    create.add_argument('--category')
    create.add_argument('--output', required=True)
    for command in ('validate', 'import'):
        cmd = commands.add_parser(command)
        cmd.add_argument('file')
        if command == 'import': cmd.add_argument('--update', action='store_true')
    listing = commands.add_parser('list')
    listing.add_argument('--namespace')
    show = commands.add_parser('show')
    show.add_argument('id')
    export = commands.add_parser('export')
    export.add_argument('--namespace')
    export.add_argument('--id')
    export.add_argument('--output', required=True)
    restore_cmd = commands.add_parser('restore', help='Restore a complete JSON export into an empty SQLite database')
    restore_cmd.add_argument('file')
    for command in ('enable', 'disable'):
        cmd = commands.add_parser(command)
        cmd.add_argument('id')
        cmd.add_argument('--revision', type=int, required=True, help='Expected revision shown by list/show/export')
    return root


def run(args):
    if args.command == 'validate':
        entries = read_document(read_file(args.file))
        return {'valid': True, 'records': len(entries)}
    if args.command == 'new' and args.namespace:
        contract = manifest()['catalogs'].get(args.namespace)
        if not contract:
            raise CatalogError('unknown_namespace')
        category = args.category or contract['categories'][0]
        if category not in contract['categories']:
            raise CatalogError('invalid_category')
        prototypes = [r for r in seed_document()['records'] if r['namespace'] == args.namespace and r['kind'] == 'technique']
        prototype = next((r for r in prototypes if category in r['memberships']), prototypes[0])
        content = import_content(prototype)
        content.update(name=args.name, category=category)
        if isinstance(content['payload'], str):
            content['payload'] = 'Replace this with your test prompt.'
        if 'description' in content:
            content['description'] = 'Describe the purpose of this technique.'
        record = {'id': f'custom/{uuid.uuid4().hex}', 'namespace': args.namespace, 'kind': 'technique',
                  'enabled': True, 'memberships': [category], **export_content(content)}
        document = {'format_version': 1, 'records': [record]}
        read_document(document)
        output(document, args.output)
        return {'created': True}
    incoming = read_file(args.file) if args.command in {'import', 'restore'} else None
    if incoming is not None:
        read_document(incoming)
    from ..mcp_server.config import load_config
    from .setup import prepare_database, resolve_database
    config = load_config()
    if args.command == 'setup':
        return prepare_database(config)
    path = resolve_database(config)
    if args.command == 'migrate':
        return {'schema_version': migrate(path)}
    if args.command == 'seed':
        return publish(path, seed_document(), seed=True)
    if args.command == 'restore':
        return restore(path, incoming)
    if args.command == 'import':
        prepare_database(config)
        return publish(path, incoming, update=args.update)
    prepare_database(config)
    snapshot = read_sync(path)
    records = snapshot.records()
    if args.command == 'list':
        return {'revision': snapshot.revision, 'records': [
            {k: r[k] for k in ('id', 'namespace', 'kind', 'position', 'enabled', 'revision')}
            for r in records if not args.namespace or r['namespace'] == args.namespace]}
    if args.command == 'export':
        selected = [r for r in records if (not args.namespace or r['namespace'] == args.namespace)
                    and (not args.id or r['id'] == args.id)]
        if not selected: raise CatalogError('unknown_record')
        output({'format_version': 1, 'records': selected}, args.output)
        return {'exported': len(selected), 'revision': snapshot.revision}
    record_id = args.template if args.command == 'new' else args.id
    record = next((r for r in records if r['id'] == record_id), None)
    if record is None:
        raise CatalogError('unknown_record')
    if args.command == 'show': return record
    if args.command == 'new':
        if record['kind'] == 'technique': raise CatalogError('expected_template_or_data')
        output({'format_version': 1, 'records': [record]}, args.output)
        return {'created': True, 'requires_update': True}
    record['enabled'] = args.command == 'enable'
    record['revision'] = args.revision
    return publish(path, {'format_version': 1, 'records': [record]}, update=True)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        output(run(args))
    except CatalogError as exc:
        print(json.dumps({'error': 'catalog_error', 'code': exc.code}), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
