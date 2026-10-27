"""Lossless content encoding, authoring documents, and immutable snapshots."""
import base64
import copy
import hashlib
import json
import re
import string
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files

from jsonschema import Draft202012Validator


class CatalogError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(f"Catalog error ({code}).")


def encode(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8', 'surrogatepass')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CatalogError('invalid_content') from None


def decode(value):
    try:
        return json.loads(bytes(value).decode('utf-8', 'surrogatepass'))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CatalogError('invalid_content') from None


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def export_content(value):
    # Ordinary JSON parsers combine escaped surrogate pairs. Use an explicit
    # envelope only when that would change the original Python value.
    regular = json.loads(json.dumps(value, ensure_ascii=True))
    if regular != value:
        return {'encoded_content': {'encoding': 'json-utf8-surrogatepass-base64',
                                    'data': base64.b64encode(encode(value)).decode('ascii')}}
    return {'content': value}


def import_content(record):
    if ('content' in record) == ('encoded_content' in record):
        raise CatalogError('content_selector_required')
    if 'content' in record:
        encode(record['content'])
        return copy.deepcopy(record['content'])
    spec = record['encoded_content']
    try:
        if set(spec) != {'encoding', 'data'} or spec['encoding'] != 'json-utf8-surrogatepass-base64':
            raise ValueError()
        return decode(base64.b64decode(spec['data'], validate=True))
    except (ValueError, TypeError, KeyError):
        raise CatalogError('invalid_content_encoding') from None


@lru_cache(maxsize=1)
def manifest():
    # Contains contracts/hashes, never prompt text. Safe for runtime validation.
    return json.loads(files(__package__).joinpath('data/manifest.json').read_text(encoding='utf-8'))


def template_fields(template):
    try:
        result = []
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is not None:
                if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) or spec or conversion:
                    raise ValueError()
                result.append(name)
        return set(result)
    except (ValueError, TypeError):
        raise CatalogError('invalid_template') from None


def validate_tool_schema(schema):
    try:
        Draft202012Validator.check_schema(schema)
        pending = [schema]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                for key in ('$ref', '$dynamicRef'):
                    if key in item and (not isinstance(item[key], str) or not item[key].startswith('#')):
                        raise ValueError()
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
    except Exception:
        raise CatalogError('invalid_tool_schema') from None


def validate_record(record):
    allowed = {'id', 'namespace', 'kind', 'position', 'enabled', 'revision', 'memberships', 'content', 'encoded_content'}
    if (not isinstance(record, dict) or set(record) - allowed
            or not {'id', 'namespace', 'kind'} <= record.keys()
            or not isinstance(record['id'], str) or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,240}', record['id'])
            or not isinstance(record.get('enabled', True), bool)):
        raise CatalogError('invalid_record')
    for key in ('position', 'revision'):
        if key in record and (type(record[key]) is not int or record[key] < 0):
            raise CatalogError('invalid_record')
    value = import_content(record)
    contracts = manifest()
    namespace = record['namespace']
    if not isinstance(namespace, str) or not isinstance(record['kind'], str):
        raise CatalogError('invalid_record')
    if record['kind'] == 'technique':
        contract = contracts['catalogs'].get(namespace)
        if not contract or not Draft202012Validator(contract['schema']).is_valid(value):
            raise CatalogError('invalid_technique')
        memberships = record.get('memberships', [value['category']])
        if (not isinstance(memberships, list) or any(not isinstance(x, str) or x not in contract['categories'] for x in memberships)
                or len(memberships) != len(set(memberships))):
            raise CatalogError('invalid_category')
        if not memberships and record['id'] not in contract.get('legacy_empty_memberships', []):
            raise CatalogError('invalid_category')
        if namespace != 'jailbreaks.engine' and memberships != [value['category']]:
            raise CatalogError('invalid_category')
        if 'args' in value:
            for schema in value['args'].values():
                validate_tool_schema(schema)
    else:
        contract = contracts['assets'].get(record['id'])
        if (not contract or namespace != contract['namespace'] or record['kind'] != contract['kind']
                or not record.get('enabled', True)
                or not Draft202012Validator(contract['schema']).is_valid(value)):
            raise CatalogError('invalid_asset')
        if record['kind'] == 'template' and template_fields(value) != set(contract['inputs']):
            raise CatalogError('invalid_template_inputs')
        if 'item_template_inputs' in contract:
            if any(template_fields(item) != set(contract['item_template_inputs']) for item in value):
                raise CatalogError('invalid_template_inputs')
        if 'object_template_inputs' in contract:
            for item in value:
                if not template_fields(item['template']) <= set(contract['object_template_inputs']):
                    raise CatalogError('invalid_template_inputs')
                declared = contract['component_inputs']
                if any(component not in declared for component in item['components']):
                    raise CatalogError('invalid_template_inputs')
                available = {key for component in item['components'] for key in declared[component]}
                if not template_fields(item['template']) <= available:
                    raise CatalogError('invalid_template_inputs')
        if contract.get('tool_definitions'):
            for tool in value:
                validate_tool_schema(tool['function']['parameters'])
    return value


def read_document(document):
    if (not isinstance(document, dict) or set(document) != {'format_version', 'records'}
            or document['format_version'] != 1 or not isinstance(document['records'], list)
            or not document['records']):
        raise CatalogError('invalid_document')
    ids = set()
    records = copy.deepcopy(document['records'])
    for record in records:
        validate_record(record)
        if record['id'] in ids:
            raise CatalogError('duplicate_id')
        ids.add(record['id'])
    return records


@dataclass(frozen=True)
class CatalogSnapshot:
    revision: int
    _records: tuple = field(repr=False)

    def __deepcopy__(self, memo):
        return self

    @classmethod
    def build(cls, revision, records):
        documents = list(records)
        if not documents:
            raise CatalogError('empty_catalog')
        read_document({'format_version': 1, 'records': documents})
        ids = {r['id'] for r in documents}
        if not set(manifest()['assets']) <= ids:
            raise CatalogError('missing_required_asset')
        for namespace in manifest()['catalogs']:
            if not any(r['namespace'] == namespace and r['kind'] == 'technique' and r.get('enabled', True) for r in documents):
                raise CatalogError('empty_required_catalog')
        positions = [(r['namespace'], r['position']) for r in documents if r['kind'] == 'technique']
        if len(positions) != len(set(positions)):
            raise CatalogError('duplicate_position')
        return cls(revision, tuple(encode(r) for r in sorted(documents, key=lambda r: (r['namespace'], r['position'], r['id']))))

    def records(self):
        return [decode(r) for r in self._records]

    def techniques(self, namespace, category=None):
        return [import_content(r) for r in self.records()
                if r['namespace'] == namespace and r['kind'] == 'technique' and r.get('enabled', True)
                and (category is None or category in r.get('memberships', [import_content(r)['category']]))]

    def category_names(self, namespace, category):
        return [import_content(r)['name'] for r in self.records()
                if r['namespace'] == namespace and r['kind'] == 'technique' and r.get('enabled', True)
                and category in r.get('memberships', [import_content(r)['category']])]

    @lru_cache(maxsize=2048)
    def _asset_bytes(self, key):
        for raw in self._records:
            record = decode(raw)
            if record['id'] == key:
                return encode(import_content(record))
        raise CatalogError('missing_required_asset')

    def asset(self, key):
        return decode(self._asset_bytes(key))

    def render(self, key, **values):
        template = self.asset(key)
        if template_fields(template) != set(values):
            raise CatalogError('invalid_template_inputs')
        try:
            return template.format_map(values)
        except (KeyError, ValueError, TypeError):
            raise CatalogError('invalid_template_inputs') from None
