# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: annuaire_client

Thin client to the LOCAL secubox-annuaire over its own unix socket
(/run/secubox/annuaire.sock — never the aggregator). Subscribes AS THE NODE
using the 0600 node key shared by the secubox user. Never raises into the
request path: every call returns (data, error).
"""
from __future__ import annotations

import hashlib
import http.client
import json
import socket as _socket
from typing import Any, Dict, List, Optional, Tuple

ANNUAIRE_SOCK = "/run/secubox/annuaire.sock"
NODE_KEY_PATH = "/etc/secubox/secrets/annuaire/node.key"
_TIMEOUT = 3.0


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects via a unix domain socket."""

    def __init__(self, sock_path: str, timeout: float = _TIMEOUT):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = sock_path

    def connect(self):
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._sock_path)
        self.sock = s


def _service_token() -> Optional[str]:
    """Mint a short service JWT so we can call annuaire's JWT-gated endpoints.

    annuaire and secubox-p2p run on the same host and share the same
    secubox_core JWT secret, so a token minted here validates there. Used for
    mutating calls (subscribe); the read endpoints (/services, /subscriptions)
    are public and need no token. Returns None if secubox_core is unavailable
    (e.g. in unit tests) — the caller then sends no Authorization header.
    """
    try:
        from secubox_core.auth import create_token  # noqa: PLC0415
        return create_token("secubox-p2p")
    except Exception:  # noqa: BLE001
        return None


def _request(
    method: str,
    path: str,
    sock: str,
    body: Optional[dict] = None,
    auth_token: Optional[str] = None,
) -> Tuple[Optional[Any], Optional[str]]:
    """Issue a single HTTP request over the given unix socket.

    Returns (parsed_json_or_None, error_string_or_None). Never raises.
    When auth_token is set, an Authorization: Bearer header is attached (needed
    for annuaire's JWT-gated mutating endpoints).
    """
    try:
        conn = _UnixHTTPConnection(sock)
        headers: Dict[str, str] = {"Accept": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        if resp.status >= 400:
            return None, f"annuaire {method} {path} -> HTTP {resp.status}"
        return (json.loads(raw) if raw else {}), None
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def did_from_pubkey_hex(pub_hex: str) -> str:
    """Derive a did:plc identifier from a raw ed25519 public key (hex).

    Mirrors annuaire/crypto.did_from_pubkey exactly:
        "did:plc:" + sha256(pubkey_bytes).hexdigest()[:32]
    """
    return "did:plc:" + hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def node_identity(
    key_path: str = NODE_KEY_PATH,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (did, priv_hex) derived from the node's ed25519 key file.

    The key file must contain exactly 32 bytes encoded as 64 lowercase hex
    characters (optionally followed by a newline). Returns (None, None) if the
    file is absent, unreadable, or malformed.
    """
    try:
        with open(key_path, "r", encoding="ascii") as fh:
            priv_hex = fh.read().strip()
        priv = bytes.fromhex(priv_hex)
        if len(priv) != 32:
            return None, None
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return did_from_pubkey_hex(pub_bytes.hex()), priv_hex
    except Exception:  # noqa: BLE001
        return None, None


def get_catalog(
    sock: str = ANNUAIRE_SOCK,
) -> Tuple[List[Dict], Optional[str]]:
    """Fetch the full service catalog from the local annuaire.

    Returns (list_of_service_dicts, None) on success, or ([], error_string).
    """
    data, err = _request("GET", "/api/v1/annuaire/services", sock)
    if err:
        return [], err
    return (data or {}).get("services", []), None


def get_subscriptions(
    mine_did: Optional[str] = None,
    sock: str = ANNUAIRE_SOCK,
) -> Tuple[List[Dict], Optional[str]]:
    """Fetch subscriptions, optionally filtered to `mine_did`.

    Returns (list_of_subscription_dicts, None) on success, or ([], error_string).
    """
    path = "/api/v1/annuaire/subscriptions"
    if mine_did:
        path += f"?mine={mine_did}"
    data, err = _request("GET", path, sock)
    if err:
        return [], err
    return (data or {}).get("subscriptions", []), None


def subscribe(
    service_id: str,
    did: str,
    priv_hex: str,
    sock: str = ANNUAIRE_SOCK,
) -> Tuple[Optional[Dict], Optional[str]]:
    """Subscribe this node (identified by `did`) to a service.

    Returns (response_dict, None) on success, or (None, error_string).
    The `priv_hex` is forwarded to the annuaire so it can verify the
    subscriber's identity (annuaire validates the ed25519 key pair). annuaire's
    subscribe endpoint is JWT-gated, so a service token is also attached.
    """
    return _request(
        "POST",
        f"/api/v1/annuaire/service/{service_id}/subscribe",
        sock,
        body={"subscriber_did": did, "subscriber_priv_hex": priv_hex},
        auth_token=_service_token(),
    )
