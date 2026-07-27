# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.escalate — multi-layer bootstrap for total-reach join.

Layer 1: an EPHEMERAL identity (throwaway Ed25519 key + DID), flagged
ephemeral, NEVER promoted to a persistent gondwana member. Layer 2: a
session-scoped WireGuard peer in EPHEMERAL_RANGE (10.11.0.0/24) on the
wg-ephemeral iface (established via secubox-p2p). teardown() removes both.
These builders return argv LISTS (shell=False); the privileged exec is done by
secubox-assistctl under a scoped sudoers entry — never in the web daemon.
"""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import List

EPHEMERAL_RANGE = "10.11.0.0/24"
EPHEMERAL_IFACE = "wg-ephemeral"
_P2P = "/usr/sbin/secubox-p2pctl"  # secubox-p2p control CLI


class EscalateError(Exception):
    """Bad range, or a layer that cannot be established (fail-closed)."""


def mint_ephemeral_identity() -> dict:
    # Local, self-contained: annuaire.crypto is a runtime dep in prod.
    from annuaire.crypto import public_from_private, did_from_pubkey
    priv = os.urandom(32)
    did = did_from_pubkey(public_from_private(priv))
    return {"did": did, "priv_hex": priv.hex(), "ephemeral": True,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _in_range(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(EPHEMERAL_RANGE)
    except ValueError:
        return False


def add_ephemeral_peer(pubkey: str, endpoint: str, ip: str, did: str = "") -> List[str]:
    if not _in_range(ip):
        raise EscalateError(f"ip {ip!r} outside ephemeral range {EPHEMERAL_RANGE}")
    return [_P2P, "peer-add", "--iface", EPHEMERAL_IFACE, "--ephemeral",
            "--pubkey", pubkey, "--endpoint", endpoint,
            "--ip", ip, "--allowed-ip", f"{ip}/32", "--did", did]


def teardown(ip: str, did: str) -> List[List[str]]:
    return [
        [_P2P, "peer-del", "--iface", EPHEMERAL_IFACE, "--allowed-ip", f"{ip}/32"],
        [_P2P, "ephemeral-revoke", "--did", did],
    ]
