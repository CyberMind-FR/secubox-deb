# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-p2p :: macro_grant

Provider-side authorization + invocation for macro grants.  A consumer presents
its self-signed Subscription; we authorize self-certifyingly against an ``auto``
offer, then run ``sudo secubox-macroctl <kind> grant``.

No federated state is needed: the Subscription is self-certifying (the
subscriber's public key hashes to their DID, and they signed the payload).

Public API
----------
authorize_grant(offer, sub, verify_fn) -> (ok, reason)
    Pure function — sig verification is injected so unit tests need no crypto.

run_grant(kind, sub_did, src_ip, params) -> (credential_dict | None, error | None)
    Calls ``sudo -n /usr/sbin/secubox-macroctl <kind> grant`` and parses JSON.
    Never raises.
"""
from __future__ import annotations

import json
import subprocess
from typing import Callable, Dict, Optional, Tuple


def authorize_grant(
    offer: Dict,
    sub: Dict,
    verify_fn: Callable[[Dict], bool],
) -> Tuple[bool, str]:
    """Authorize a macro grant request.

    This is a PURE function: all I/O (crypto, network) is injected via
    ``verify_fn`` so the logic is unit-testable without any real keys or
    network calls.

    Args:
        offer:     Local ServiceOffer dict from the catalog.  Must have
                   ``approval_mode`` and ``macro`` fields for a grantable offer.
        sub:       Presented Subscription dict including ``subscriber``,
                   ``service_id``, ``sig``, ``signer_did``, and
                   ``subscriber_pubkey``.
        verify_fn: Callable(sub) -> bool.  Injected verifier that (a) checks
                   subscriber_pubkey hashes to sub["subscriber"] via
                   did_from_pubkey_hex, and (b) verifies the Ed25519 sig over
                   the canonical Subscription payload.

    Returns:
        (True, "ok") on success, or (False, human-readable reason) on rejection.
    """
    # 1. Offer must carry a macro descriptor.
    if not offer or not offer.get("macro"):
        return False, "offer has no macro"

    # 2. Increment-1 restriction: only auto-mode offers are supported.
    if offer.get("approval_mode") != "auto":
        return False, "only auto-mode macro offers are grantable (pending unsupported)"

    # 3. Subscription must be for this specific service.
    if sub.get("service_id") != offer.get("service_id"):
        return False, "subscription service_id mismatch"

    # 4. Self-certifying signature check (injected so the function stays pure).
    if not verify_fn(sub):
        return False, "subscription signature invalid (self-cert failed)"

    return True, "ok"


def run_grant(
    kind: str,
    sub_did: str,
    src_ip: str,
    params: Dict,
) -> Tuple[Optional[Dict], Optional[str]]:
    """Invoke ``sudo secubox-macroctl <kind> grant`` and return the credential.

    The subprocess is run with ``-n`` (non-interactive, no password prompt)
    so it fails cleanly if the sudoers entry is missing instead of hanging.

    Args:
        kind:    Macro kind string (e.g. ``"tor-exit"``).
        sub_did: Subscriber DID (passed as ``--sub``).
        src_ip:  Source mesh IP (passed as ``--src-ip``).
        params:  Macro params dict (passed as ``--params`` JSON).

    Returns:
        (credential_dict, None) on success, or (None, error_str) on failure.
        Never raises.
    """
    cmd = [
        "sudo", "-n", "/usr/sbin/secubox-macroctl",
        kind, "grant",
        "--sub", sub_did,
        "--src-ip", src_ip,
        "--params", json.dumps(params),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"

    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or "macroctl grant failed").strip()

    try:
        return json.loads(proc.stdout), None
    except ValueError:
        return None, "grant produced non-JSON output"
