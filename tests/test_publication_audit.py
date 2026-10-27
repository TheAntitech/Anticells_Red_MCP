"""Ensure the fixture exception cannot conceal credentials or nested metadata."""

import importlib.util
from pathlib import Path
import subprocess


def _module():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'audit_publication.py'
    spec = importlib.util.spec_from_file_location('publication_audit', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reviewed_url_exceptions_are_exact_and_limited_to_fixture_paths(tmp_path):
    audit = _module()
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / 'tests').mkdir()
    prefix = 'postgresql://' + 'user:'
    (tmp_path / 'tests/test_catalog.py').write_text(
        prefix + 'secret-password@host/db\n' + prefix + 'unexpected-value@host/db\n')
    (tmp_path / 'application.py').write_text(prefix + 'secret-password@host/db\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    result = audit.audit(tmp_path)
    assert result['reviewed_dummy_test_urls'] == 1
    assert result['candidate_count'] == 2
    assert {item['path'] for item in result['findings']} == {
        'tests/test_catalog.py', 'application.py'}


def test_nested_git_metadata_and_authentication_files_are_sensitive():
    audit = _module()
    for path in ['vendor/.git/config', '.aws/credentials', '.ssh/id_rsa',
                 'config/credentials.json', '.netrc']:
        assert audit.sensitive_path(path), path
    assert not audit.sensitive_path('.env.example')
