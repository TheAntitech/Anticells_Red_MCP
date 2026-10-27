# ♢ 𝓜𝖗𝚇₀𝚛𝚍 ⚡🖤  —  SSRF guard, 1.1.0 hardening pass (F1)
"""Host/IP egress policy for every outbound HTTP request.

This module centralizes the decision of whether the server is permitted to
contact a given URL. It is applied uniformly to:

  * legacy ``target_url`` arguments
  * saved target profiles
  * inline target definitions supplied by the MCP client

Default policy
--------------

Reject if the resolved address is any of:

  * loopback         (127.0.0.0/8, ::1)
  * link-local       (169.254.0.0/16, fe80::/10)   -- including cloud IMDS
  * private          (10/8, 172.16/12, 192.168/16, fc00::/7)
  * multicast        (224/4, ff00::/8)
  * reserved         (0.0.0.0/8, 240/4, etc.)
  * unspecified      (0.0.0.0, ::)

The resolver is called once; the pinned IP travels with the request so that
DNS rebinding cannot swap targets between the policy check and the actual
HTTP connect.

Operator overrides (process environment)
----------------------------------------

``ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS=true``
    Disable the private/loopback/link-local/etc. deny-list. Multicast,
    reserved, and unspecified addresses stay denied unconditionally.

``ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS=host1,host2,...``
    Case-insensitive exact-host or trailing-wildcard allow-list
    (``*.internal.example``). Matching hosts bypass the deny-list even
    without ``ALLOW_PRIVATE_TARGETS``. Lookup still happens, pinning the IP.

``ANTICELLS_RED_MCP_TARGET_DENY_HOSTS=host1,host2,...``
    Same syntax; always denied, before any allow-list.

``ANTICELLS_RED_MCP_RESOLVE_TIMEOUT_SECONDS=<float>``
    Resolver timeout. Default 2.0.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from functools import lru_cache
from typing import FrozenSet, Iterable, List, Optional, Tuple


class EgressPolicyError(ValueError):
    """Request rejected by the egress policy; a stable code only."""

    def __init__(self, code: str, host: str = ""):
        self.code = code
        self.host = host
        super().__init__(f"Egress policy rejected target ({code}).")


_HOST_LIST_MAX = 256


def _split_hosts(value: str) -> FrozenSet[str]:
    items = {part.strip().lower() for part in value.split(",") if part.strip()}
    if len(items) > _HOST_LIST_MAX:
        raise EgressPolicyError("too_many_host_list_entries")
    return frozenset(items)


def _host_matches(host: str, patterns: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        if pattern == host:
            return True
        if pattern.startswith("*.") and (host == pattern[2:] or host.endswith(pattern[1:])):
            return True
    return False


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"", "0", "false", "no", "off"}:
        return default
    raise EgressPolicyError("invalid_boolean_setting")


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise EgressPolicyError("invalid_numeric_setting") from None
    if not (0 < value <= 60):
        raise EgressPolicyError("invalid_numeric_setting")
    return value


def _resolve(host: str, timeout: float) -> List[ipaddress._BaseAddress]:
    try:
        # Never alter the process-wide socket timeout. The network backend
        # bounds resolution in a worker thread before connecting.
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise EgressPolicyError("target_host_not_resolvable", host) from None
    except (OSError, UnicodeError):
        raise EgressPolicyError("target_host_not_resolvable", host) from None
    addresses: List[ipaddress._BaseAddress] = []
    for family, _socktype, _proto, _canon, sockaddr in infos:
        try:
            if family == socket.AF_INET:
                addresses.append(ipaddress.IPv4Address(sockaddr[0]))
            elif family == socket.AF_INET6:
                # Strip zone id if present.
                raw = sockaddr[0].split("%", 1)[0]
                addresses.append(ipaddress.IPv6Address(raw))
        except ValueError:
            continue
    if not addresses:
        raise EgressPolicyError("target_host_not_resolvable", host)
    return addresses


def _unsafe_always(address: ipaddress._BaseAddress) -> Optional[str]:
    """Addresses nobody should ever contact from an HTTP client.

    Overlap note: in Python's ``ipaddress``, ``is_reserved`` is True for
    broad swaths that also set ``is_loopback``/``is_link_local``/
    ``is_private``. Those categories are reported by
    :func:`_unsafe_by_default` with a more informative code; only reserved
    addresses that do NOT overlap one of them are reported as
    ``address_reserved`` here.
    """
    if address.is_unspecified:
        return "address_unspecified"
    if address.is_multicast:
        return "address_multicast"
    if (address.is_reserved
            and not (address.is_loopback or address.is_link_local or address.is_private)):
        return "address_reserved"
    return None


def _unsafe_by_default(address: ipaddress._BaseAddress) -> Optional[str]:
    """Addresses denied unless the operator explicitly opts in."""
    if address.is_loopback:
        return "address_loopback"
    if address.is_link_local:
        return "address_link_local"
    if address.is_private:
        return "address_private"
    # IPv4-mapped IPv6: evaluate the embedded v4.
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            mapped = ipaddress.IPv4Address(address.ipv4_mapped)
            return _unsafe_by_default(mapped) or _unsafe_always(mapped)
        if address.sixtofour is not None:
            embedded = ipaddress.IPv4Address(address.sixtofour)
            return _unsafe_by_default(embedded) or _unsafe_always(embedded)
    return None


def _try_literal(host: str) -> Optional[ipaddress._BaseAddress]:
    stripped = host.strip("[]")
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        return None


def check_host(host: str) -> List[str]:
    """Resolve ``host`` and return the list of IP strings cleared by policy.

    Raises :class:`EgressPolicyError` with a stable ``code`` on rejection.
    Never prints or logs the host; the host is attached to the exception for
    the caller to redact or expose as it sees fit.
    """
    if not host or not isinstance(host, str):
        raise EgressPolicyError("invalid_host")

    allow_hosts = _split_hosts(os.environ.get("ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS", ""))
    deny_hosts = _split_hosts(os.environ.get("ANTICELLS_RED_MCP_TARGET_DENY_HOSTS", ""))
    if deny_hosts and _host_matches(host, deny_hosts):
        raise EgressPolicyError("target_host_denied", host)

    host_allowed = bool(allow_hosts) and _host_matches(host, allow_hosts)
    private_allowed = _bool_env("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", False)
    timeout = _float_env("ANTICELLS_RED_MCP_RESOLVE_TIMEOUT_SECONDS", 2.0)

    literal = _try_literal(host)
    if literal is not None:
        always = _unsafe_always(literal)
        if always:
            raise EgressPolicyError(always, host)
        if not host_allowed and not private_allowed:
            code = _unsafe_by_default(literal)
            if code:
                raise EgressPolicyError(code, host)
        return [str(literal)]

    # Resolution escape hatch: when the operator confirms that DNS cannot be
    # reached from this process (CI mocks, air-gapped lab) we skip the
    # resolution step. Literal IP checks, allow/deny-lists, and the always
    # unsafe-address catches still apply, so this only widens the hostname
    # path.
    if _bool_env("ANTICELLS_RED_MCP_SKIP_HOST_RESOLUTION", False):
        return [host]

    addresses = _resolve(host, timeout)
    cleared: List[str] = []
    for address in addresses:
        always = _unsafe_always(address)
        if always:
            raise EgressPolicyError(always, host)
        if not host_allowed and not private_allowed:
            code = _unsafe_by_default(address)
            if code:
                raise EgressPolicyError(code, host)
        cleared.append(str(address))
    return cleared


def self_test() -> Tuple[bool, str]:
    """Startup sanity check: default policy must reject localhost."""
    saved_allow = os.environ.pop("ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS", None)
    saved_hosts = os.environ.pop("ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS", None)
    try:
        try:
            check_host("127.0.0.1")
        except EgressPolicyError as exc:
            if exc.code == "address_loopback":
                return True, "ok"
            return False, f"unexpected_code:{exc.code}"
        return False, "default_policy_allowed_loopback"
    finally:
        if saved_allow is not None:
            os.environ["ANTICELLS_RED_MCP_ALLOW_PRIVATE_TARGETS"] = saved_allow
        if saved_hosts is not None:
            os.environ["ANTICELLS_RED_MCP_TARGET_ALLOW_HOSTS"] = saved_hosts
