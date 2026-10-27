"""Separate local template work and skipped records from endpoint attempts."""


def _field(result, name, default=None):
    return result.get(name, default) if isinstance(result, dict) else getattr(result, name, default)


def is_local_result(result):
    metadata = _field(result, "metadata", {}) or {}
    return _field(result, "module") == "mutation" or metadata.get("evaluation") == "local_template"


def is_skipped_result(result):
    return (_field(result, "metadata", {}) or {}).get("status") == "skipped"


def is_target_attempt(result):
    return not is_local_result(result) and not is_skipped_result(result)
