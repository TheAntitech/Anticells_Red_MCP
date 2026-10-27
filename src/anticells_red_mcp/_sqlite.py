"""Filesystem-path handling shared by the catalog and report stores."""
from pathlib import PurePath, PureWindowsPath


def sqlite_file_uri(path: PurePath) -> str:
    """Quote a file URI without treating a Windows drive prefix as a host."""
    if isinstance(path, PureWindowsPath) and path.drive.startswith('\\\\?\\') and path.drive.endswith(':'):
        # Windows resolve() can retain \\?\C:\ during concurrent creation.
        # as_uri() turns its '?' into an authority which SQLite rejects.
        # Normalize only the URI; retain the native path for filesystem work.
        path = PureWindowsPath(str(path)[4:])
    return path.as_uri()
