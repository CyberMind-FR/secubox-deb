# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: registry

Pure merge logic for the Service Registry: combines the annuaire catalog, my
subscriptions, the local activation overlay, and legacy p2p-local services into
the rows the UI renders. No network I/O lives here (see annuaire_client.py) so
the merge is fully unit-testable.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Service kinds that (in Milestone 2) carry an executable access macro. In M1
# this only drives a cosmetic "automatable" badge.
MACRO_KINDS = {"tor-exit", "wg-relay", "dns-resolver", "http-mirror"}

_PORT_RE = re.compile(r":(\d{1,5})(?:/|$)")


def port_from_endpoint(endpoint: str) -> Optional[int]:
    """Best-effort extract a TCP port from a host:port or URL endpoint."""
    if not endpoint:
        return None
    m = _PORT_RE.search(endpoint)
    if not m:
        return None
    try:
        p = int(m.group(1))
    except ValueError:
        return None
    return p if 0 < p < 65536 else None


def load_overlay(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_overlay(path: str, data: Dict[str, Any]) -> None:
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def set_active(path: str, service_id: str, local_port: Optional[int],
               subscription_id: Optional[str] = None,
               endpoint: Optional[str] = None) -> Dict[str, Any]:
    data = load_overlay(path)
    entry = data.get(service_id, {})
    entry["active"] = True
    entry["local_port"] = local_port
    if subscription_id is not None:
        entry["subscription_id"] = subscription_id
    entry.setdefault("subscription_id", None)
    if endpoint is not None:
        entry["endpoint"] = endpoint
    entry["activated_at"] = datetime.now(timezone.utc).isoformat()
    data[service_id] = entry
    save_overlay(path, data)
    return data


def set_subscription(path: str, service_id: str, subscription_id: str) -> Dict[str, Any]:
    data = load_overlay(path)
    entry = data.get(service_id, {})
    entry["subscription_id"] = subscription_id
    entry.setdefault("active", False)
    entry.setdefault("local_port", None)
    data[service_id] = entry
    save_overlay(path, data)
    return data


def merge_services(catalog: List[Dict], subscriptions: List[Dict],
                   overlay: Dict[str, Any], legacy: List[Dict],
                   local_did: Optional[str]) -> List[Dict]:
    sub_state = {}
    for s in subscriptions or []:
        sid = s.get("service_id")
        if sid:
            sub_state[sid] = s.get("state", "pending")

    rows: List[Dict] = []
    for offer in catalog or []:
        sid = offer.get("service_id")
        if not sid:
            continue
        provider = offer.get("provider")
        is_local = bool(local_did) and provider == local_did
        ov = overlay.get(sid, {})
        kind = offer.get("kind", "")
        row: Dict = {
            "service_id": sid,
            "name": offer.get("name", ""),
            "type": kind,
            "provider": provider,
            "provider_label": "local" if is_local else _short_did(provider),
            "port": ov.get("local_port") or port_from_endpoint(offer.get("endpoint", "")),
            "approval_mode": offer.get("approval_mode", "auto"),
            "subscription_state": sub_state.get(sid, "not-subscribed"),
            "active": bool(ov.get("active", False)),
            "source": "annuaire",
            "automatable": kind in MACRO_KINDS,
        }
        if ov.get("endpoint"):
            row["endpoint"] = ov["endpoint"]
        rows.append(row)

    for svc in legacy or []:
        rows.append({
            "service_id": None,
            "name": svc.get("name", ""),
            "type": svc.get("protocol", svc.get("type", "")),
            "provider": None,
            "provider_label": "local",
            "port": svc.get("port"),
            "approval_mode": None,
            "subscription_state": "n/a",
            "active": bool(svc.get("active", True)),
            "source": "p2p-local",
            "automatable": False,
        })

    rows.sort(key=lambda r: (r["provider_label"] != "local", r["name"].lower()))
    return rows


def _short_did(did: Optional[str]) -> str:
    if not did:
        return "unknown"
    return did[:20] + "…" if len(did) > 21 else did
