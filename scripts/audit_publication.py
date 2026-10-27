"""Audit staged and reachable-history blobs without displaying secret values.

This bounded, standard-library pattern audit complements a dedicated secret
scanner. It does not validate credentials or contact external services.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


PATTERNS = {
    "private_key": rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    "aws_access_key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "github_token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b",
    "google_api_key": rb"\bAIza[A-Za-z0-9_-]{35}\b",
    "slack_token": rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
    "stripe_secret": rb"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b",
    "model_api_key": rb"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b",
    "authenticated_url": rb"\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s/:]+:[^\s/@]+@",
    "jwt": rb"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{20,}\b",
}
COMPILED = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
SENSITIVE_PARTS = {".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".kube",
                   ".codex", ".venv", "venv", ".runtime", "runtime", "logs", "validation"}
# Exact, reviewed redaction/migration fixtures only. A different credential in
# these tests, or the same value in application code, must still be reported.
REVIEWED_TEST_URLS = {
    "tests/test_catalog.py": {b"postgresql://" + b"user:secret-password@"},
    "tests/test_catalog_setup.py": {
        b"postgresql://" + b"user:secret@", b"postgresql://" + b"user:private@"},
}


def git(root, *args, check=True):
    return subprocess.run(["git", "-C", str(root), *args], check=check,
                          capture_output=True).stdout


def sensitive_path(path):
    p = PurePosixPath(path)
    name = p.name.lower()
    return (bool(set(p.parts) & SENSITIVE_PARTS)
            or name in {"targets.local.json", "mcp_credentials.json", "credentials.json",
                        ".env", ".netrc", ".pypirc", ".npmrc"}
            or (name.startswith(".env.") and name != ".env.example")
            or name.startswith(("id_rsa", "id_ed25519"))
            or name.endswith((".key", ".pem", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db", ".session.lock")))


def audit(root):
    findings, staged, objects = [], [], {}
    reviewed_fixtures = 0
    for entry in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, path_bytes = entry.split(b"\t", 1)
        mode, oid, stage = metadata.decode().split()
        path = path_bytes.decode()
        staged.append(path)
        if mode != "100644" and mode != "100755":
            findings.append({"path": path, "rule": "non_regular_staged_file"})
        if stage != "0":
            findings.append({"path": path, "rule": "unresolved_index"})
        if sensitive_path(path):
            findings.append({"path": path, "rule": "sensitive_filename"})
        objects.setdefault(oid, path)
    # Inspect every blob reachable through refs, not just the current tree.
    for line in git(root, "rev-list", "--objects", "--all").splitlines():
        oid, _, path_bytes = line.partition(b" ")
        if git(root, "cat-file", "-t", oid.decode()).strip() != b"blob":
            continue
        path = path_bytes.decode(errors="replace") or "(history blob)"
        objects.setdefault(oid.decode(), path)
        if sensitive_path(path):
            findings.append({"path": path, "rule": "sensitive_history_filename"})
    for oid, path in objects.items():
        raw = git(root, "cat-file", "blob", oid)
        for rule, pattern in COMPILED.items():
            for match in pattern.finditer(raw):
                if rule == "authenticated_url" and match.group() in REVIEWED_TEST_URLS.get(path, set()):
                    reviewed_fixtures += 1
                    continue
                line_number = raw[:match.start()].count(b"\n") + 1
                findings.append({"path": path, "line": line_number, "rule": rule})
    return {
        "scope": "exact staged blobs and all reachable Git-history blobs",
        "staged_files": len(staged), "unique_blobs_scanned": len(objects),
        "credential_values_printed": False, "candidate_count": len(findings),
        "reviewed_dummy_test_urls": reviewed_fixtures,
        "findings": findings,
        "limit": "pattern-based audit; does not certify every possible secret format",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = audit(args.root)
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["candidate_count"] else 0)


if __name__ == "__main__":
    main()
