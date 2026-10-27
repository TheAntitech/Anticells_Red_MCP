"""Regression tests covering the 1.1.0 hardening pass.

Every test here maps to one of the audit findings (F1..F7) and asserts the
specific behavior the fix introduced. The intent is that if a future change
re-opens the gap, the test fails loudly with a self-explanatory name.
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

import pytest


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """Keep each test from leaking policy env vars into the next."""
    for name in list(os.environ):
        if name.startswith("ANTICELLS_RED_MCP_") and name not in {
            "ANTICELLS_RED_MCP_DATABASE_PATH",
            "ANTICELLS_RED_MCP_STATE_DIR",
            "ANTICELLS_RED_MCP_REPORTS_DIR",
        }:
            monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# F1 -- SSRF deny-list
# ---------------------------------------------------------------------------


def test_f1_default_policy_rejects_loopback():
    from anticells_red_mcp.mcp_server.endpoint_safety import EgressPolicyError, check_host
    with pytest.raises(EgressPolicyError) as excinfo:
        check_host("127.0.0.1")
    assert excinfo.value.code == "address_loopback"


def test_f1_default_policy_rejects_imds():
    from anticells_red_mcp.mcp_server.endpoint_safety import EgressPolicyError, check_host
    with pytest.raises(EgressPolicyError) as excinfo:
        check_host("169.254.169.254")
    assert excinfo.value.code == "address_link_local"


def test_f1_default_policy_rejects_rfc1918():
    from anticells_red_mcp.mcp_server.endpoint_safety import EgressPolicyError, check_host
    for host in ("10.0.0.1", "172.16.1.1", "192.168.1.1"):
        with pytest.raises(EgressPolicyError) as excinfo:
            check_host(host)
        assert excinfo.value.code == "address_private"


def test_f1_default_policy_rejects_ipv6_loopback_and_mapped():
    from anticells_red_mcp.mcp_server.endpoint_safety import EgressPolicyError, check_host
    with pytest.raises(EgressPolicyError) as e1:
        check_host("::1")
    assert e1.value.code == "address_loopback"
    # IPv4-mapped ::ffff:127.0.0.1 is both reserved (always-unsafe) and maps
    # back to loopback. Either code is acceptable; both mean "rejected".
    with pytest.raises(EgressPolicyError) as e2:
        check_host("::ffff:127.0.0.1")
    assert e2.value.code in {"address_loopback", "address_reserved", "address_private"}


def test_f1_allow_private_opt_in(monkeypatch):
    from anticells_red_mcp.mcp_server.endpoint_safety import check_host
    monkeypatch.setenv("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", "true")
    assert check_host("127.0.0.1") == ["127.0.0.1"]


def test_f1_allow_host_wildcard(monkeypatch):
    from anticells_red_mcp.mcp_server.endpoint_safety import check_host
    # Literal IP: the allow-list is for hostnames; literal loopback stays denied.
    monkeypatch.setenv("ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS", "*.example.test,api.openai.com")
    # Hostname matches the wildcard, but DNS resolution still occurs; use a
    # host that resolves to something policy-safe to avoid network flakiness.
    # api.openai.com is a public hostname so this just needs to not raise on
    # the allow-list check path. Skip if DNS unavailable.
    import socket
    try:
        socket.getaddrinfo("api.openai.com", None)
    except OSError:
        pytest.skip("DNS unavailable")
    cleared = check_host("api.openai.com")
    assert cleared, "allow-listed public host should return at least one IP"


def test_f1_deny_host_wins(monkeypatch):
    from anticells_red_mcp.mcp_server.endpoint_safety import EgressPolicyError, check_host
    monkeypatch.setenv("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("ANTICELLS_RED_MCP_TARGET_DENY_HOSTS", "127.0.0.1")
    with pytest.raises(EgressPolicyError) as excinfo:
        check_host("127.0.0.1")
    assert excinfo.value.code == "target_host_denied"


def test_f1_self_test_passes():
    from anticells_red_mcp.mcp_server.endpoint_safety import self_test
    ok, reason = self_test()
    assert ok, reason


def test_f1_endpoint_origin_raises_target_configuration_error():
    from anticells_red_mcp.mcp_server.targets import TargetConfigurationError, endpoint_origin
    with pytest.raises(TargetConfigurationError) as excinfo:
        endpoint_origin("http://127.0.0.1/leak")
    assert excinfo.value.code == "address_loopback"


# ---------------------------------------------------------------------------
# F2 -- inline target cannot read ${env.*}
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> Any:
    """Build a minimal config object sufficient for resolve_target()."""
    from anticells_red_mcp.mcp_server.config import MCPConfig
    cfg = MCPConfig()
    cfg.target_profiles = {}
    cfg.target_environment = overrides.get("env", {})
    cfg.target_api_url = overrides.get("api_url")
    return cfg


def test_f2_inline_env_in_body_rejected(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", "true")
    from anticells_red_mcp.mcp_server.targets import TargetConfigurationError, resolve_target
    cfg = _make_config(env={"HOME": "/home/x"}, api_url="http://127.0.0.1:1/")
    inline = {"url": "http://127.0.0.1:1/", "method": "POST",
              "body": {"x": "${env.HOME}"}, "response": {"text": "/x"}}
    with pytest.raises(TargetConfigurationError) as excinfo:
        resolve_target(cfg, inline, None)
    assert excinfo.value.code == "inline_environment_reference_forbidden"


def test_f2_inline_env_in_header_rejected(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", "true")
    from anticells_red_mcp.mcp_server.targets import TargetConfigurationError, resolve_target
    cfg = _make_config(env={"HOME": "/home/x"}, api_url="http://127.0.0.1:1/")
    inline = {"url": "http://127.0.0.1:1/", "method": "POST",
              "headers": {"X-Leak": "${env.HOME}"}, "body": {"x": "y"},
              "response": {"text": "/x"}}
    with pytest.raises(TargetConfigurationError) as excinfo:
        resolve_target(cfg, inline, None)
    assert excinfo.value.code == "inline_environment_reference_forbidden"


def test_f2_default_target_environment_is_empty(monkeypatch):
    monkeypatch.setenv("TEST_SUPER_SECRET", "LEAK")
    monkeypatch.delenv("ANTICELLS_RED_MCP_TEMPLATE_ENV", raising=False)
    from anticells_red_mcp.mcp_server.config import _template_env_default
    assert _template_env_default() == {}


def test_f2_template_env_whitelist_is_honored(monkeypatch):
    monkeypatch.setenv("TEST_SUPER_SECRET", "LEAK")
    monkeypatch.setenv("ANTICELLS_RED_MCP_TEMPLATE_ENV", "TEST_SUPER_SECRET,OTHER")
    from anticells_red_mcp.mcp_server.config import _template_env_default
    assert _template_env_default() == {"TEST_SUPER_SECRET": "LEAK"}


# ---------------------------------------------------------------------------
# F3 -- in-memory history is bounded
# ---------------------------------------------------------------------------


def test_f3_history_is_ring_buffered(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_MAX_HISTORY", "10")
    from anticells_red_mcp.mcp_server.limits import trim
    data = [{"i": i} for i in range(100)]
    trim(data)
    assert len(data) == 10
    assert data[0]["i"] == 90 and data[-1]["i"] == 99


def test_f3_max_history_zero_disables():
    from anticells_red_mcp.mcp_server.limits import trim
    data = list(range(5000))
    os.environ.pop("ANTICELLS_RED_MCP_MAX_HISTORY", None)
    os.environ["ANTICELLS_RED_MCP_MAX_HISTORY"] = "0"
    try:
        trim(data)
    finally:
        os.environ.pop("ANTICELLS_RED_MCP_MAX_HISTORY", None)
    assert len(data) == 5000


# ---------------------------------------------------------------------------
# F4 -- per-call request cap
# ---------------------------------------------------------------------------


def test_f4_per_call_cap_blocks_over_limit(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL", "3")
    from anticells_red_mcp.reports.runtime import (
        bump_outbound_counter, clear_outbound_counter, reset_outbound_counter,
    )
    from anticells_red_mcp.mcp_server.limits import max_requests_per_call
    token = reset_outbound_counter()
    try:
        values = [bump_outbound_counter() for _ in range(5)]
    finally:
        clear_outbound_counter(token)
    cap = max_requests_per_call()
    over = [v for v in values if v > cap]
    assert cap == 3
    assert len(over) == 2  # 4th and 5th call go over


def test_f4_per_call_cap_zero_disables(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_CALL", "0")
    from anticells_red_mcp.mcp_server.limits import max_requests_per_call
    assert max_requests_per_call() == 0


def test_f4_session_rate_limiter_counts_and_resets(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_MAX_REQUESTS_PER_SESSION_PER_MIN", "4")
    from anticells_red_mcp.mcp_server.limits import SessionRateLimiter
    from anticells_red_mcp.mcp_server.targets import TargetConfigurationError
    limiter = SessionRateLimiter()
    for _ in range(4):
        limiter.check()
    with pytest.raises(TargetConfigurationError) as excinfo:
        limiter.check()
    assert excinfo.value.code == "session_request_rate_limited"


# ---------------------------------------------------------------------------
# F6 -- report listing scopes to current session by default
# ---------------------------------------------------------------------------


def test_f6_list_exports_for_session_scopes_rows(tmp_path):
    from anticells_red_mcp.reports.repository import ReportRepository
    from anticells_red_mcp.reports.model import new_id, now, encode
    repo = ReportRepository(tmp_path / "reports")
    repo.initialize()
    # Two sessions, two runs, two exports.
    with repo.connection(write=True) as con:
        ses_a, ses_b = new_id(), new_id()
        for session_id in (ses_a, ses_b):
            run_id = new_id()
            created = now()
            con.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                        (session_id, created, 'active', encode({'id': session_id})))
            con.execute("INSERT INTO runs VALUES (?,?,?,?,?)",
                        (run_id, session_id, created, 'completed', encode({'id': run_id})))
            export_id = new_id()
            info = {'id': export_id, 'filename': f'report-{export_id}.json',
                    'created_at': created, 'mime_type': 'application/json',
                    'byte_count': 0, 'uri': f'anticells-report://exports/{export_id}'}
            con.execute("INSERT INTO exports VALUES (?,?,?,?)",
                        (export_id, info['filename'], created, encode(info)))
            con.execute("INSERT INTO export_runs VALUES (?,?)", (export_id, run_id))
            if session_id == ses_a:
                marker_a = export_id
            else:
                marker_b = export_id
    rows = repo.list_exports_for_session(ses_a, 10, 0)
    ids = {row['id'] for row in rows}
    assert marker_a in ids
    assert marker_b not in ids


# ---------------------------------------------------------------------------
# F7 -- stable error codes, no free-form message leaks
# ---------------------------------------------------------------------------


def test_f7_target_url_with_private_ip_returns_stable_code():
    from anticells_red_mcp.mcp_server.targets import TargetConfigurationError
    from anticells_red_mcp.mcp_server import server as srv
    with pytest.raises(TargetConfigurationError) as excinfo:
        srv._target_config("http://127.0.0.1/leak")
    assert excinfo.value.code == "address_loopback"
    # Message is derived from the code; no free-form variable name reveal.
    assert "ANTICELLS_RED_MCP_TARGET_API_URL" not in str(excinfo.value)


def test_f7_authenticated_mismatch_returns_stable_code(monkeypatch):
    monkeypatch.setenv("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", "true")
    from anticells_red_mcp.mcp_server import server as srv
    from anticells_red_mcp.mcp_server.config import MCPConfig
    from anticells_red_mcp.mcp_server.targets import TargetConfigurationError
    original = srv._config
    swapped = MCPConfig()
    swapped.target_api_url = "http://127.0.0.1:18080"
    swapped.target_api_key = "k"
    srv._config = swapped
    try:
        with pytest.raises(TargetConfigurationError) as excinfo:
            srv._target_config("http://localhost:18080/x")
        assert excinfo.value.code == "authenticated_target_origin_mismatch"
    finally:
        srv._config = original
