"""SQLite connections must accept Windows extended drive paths."""
import os
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from anticells_red_mcp.reports.repository import ReportRepository
from anticells_red_mcp._sqlite import sqlite_file_uri


@pytest.mark.parametrize('path, expected', [
    (PurePosixPath('/tmp/catalog # café?.sqlite3'),
     'file:///tmp/catalog%20%23%20caf%C3%A9%3F.sqlite3'),
    (PureWindowsPath('C:/data/catalog # café.sqlite3'),
     'file:///C:/data/catalog%20%23%20caf%C3%A9.sqlite3'),
    (PureWindowsPath('//?/C:/data/catalog # café.sqlite3'),
     'file:///C:/data/catalog%20%23%20caf%C3%A9.sqlite3'),
    (PureWindowsPath('//server/share/catalog.sqlite3'),
     'file://server/share/catalog.sqlite3'),
])
def test_file_uri_preserves_paths_and_quotes_filename_characters(path, expected):
    assert sqlite_file_uri(path) == expected


@pytest.mark.skipif(os.name != 'nt', reason='native Windows drive paths')
def test_reports_accept_extended_drive_directory(tmp_path):
    directory = tmp_path / 'reports # café'
    extended = Path('\\\\?\\' + str(directory).removeprefix('\\\\?\\'))
    repository = ReportRepository(extended)
    repository.initialize()
    assert repository.list_runs()['total'] == 0
    assert (directory / 'reports.sqlite3').is_file()
