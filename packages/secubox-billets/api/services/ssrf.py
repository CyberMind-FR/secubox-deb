# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SSRF-hardened outbound HTTP for oEmbed / OpenGraph fetches.

Rules enforced before and during every fetch:
- https only (no http, no file:, no gopher…);
- the host is DNS-resolved and EVERY resolved address must be a public unicast
  IP — private / loopback / link-local / reserved / multicast / unspecified are
  refused (blocks metadata endpoints, LAN, 127.0.0.1, etc.);
- redirects are not auto-followed; each hop's Location is re-validated (so a
  redirect to a private IP or to http is refused);
- 5 s timeout and a hard response-size cap (streamed, not buffered blindly).

Residual: this validates DNS at request time but a determined active
DNS-rebinding attacker could flip the record between check and connect. The
input here is admin-only (authenticated author), which bounds that risk; noted
as a known limitation rather than pinning the socket to the resolved IP."""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

DEFAULT_MAX_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 5.0
MAX_REDIRECTS = 3
Resolver = Callable[[str, int], list]


class SSRFError(Exception):
    """A URL/host/IP failed the SSRF policy."""


def _default_resolver(host: str, port: int) -> list:
    return socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified)


def validate_url(url: str, *, resolver: Resolver = _default_resolver) -> str:
    """Return the host after enforcing https + all-public-IP. Raise SSRFError."""
    p = urlparse(url)
    if p.scheme != "https":
        raise SSRFError(f"scheme not allowed: {p.scheme!r} (https only)")
    host = p.hostname
    if not host:
        raise SSRFError("missing host")
    port = p.port or 443
    try:
        infos = resolver(host, port)
    except (socket.gaierror, OSError) as e:
        raise SSRFError(f"DNS resolution failed for {host}: {e}")
    ips = [i[4][0] for i in infos]
    if not ips:
        raise SSRFError(f"no address for {host}")
    for ip in ips:
        if not is_public_ip(ip):
            raise SSRFError(f"non-public address {ip} for {host}")
    return host


async def fetch(url: str, *, client: httpx.AsyncClient,
                resolver: Resolver = _default_resolver,
                max_bytes: int = DEFAULT_MAX_BYTES,
                timeout: float = DEFAULT_TIMEOUT) -> tuple[str, str, bytes]:
    """Validated GET with manual, re-validated redirects and a size cap.

    Returns (final_url, content_type, body). Raises SSRFError on any policy
    violation. The caller passes the httpx client (so tests inject a transport)."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(current, resolver=resolver)
        async with client.stream("GET", current, follow_redirects=False,
                                 timeout=timeout) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if not loc:
                    raise SSRFError("redirect without Location")
                current = urljoin(current, loc)  # re-validated next iteration
                continue
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    raise SSRFError(f"response exceeds {max_bytes} bytes")
            return current, resp.headers.get("content-type", ""), body
    raise SSRFError("too many redirects")
