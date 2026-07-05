# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — local (LAN/WG) presence collector (Project B,
#820, Task 4).

`collect_local(store, device_store)` mirrors Project A's canonical
`DeviceStore` (`api/store.py`) into `PresenceStore` rows — NO new discovery,
just a link/projection of devices A already knows about.

Plane rule (simplest deterministic mapping, per the plan): a device's
`source` column decides its plane. `source == "mesh"` (the WireGuard mesh
peers synced by `/mesh/sync`, see `api/main.py`'s `mesh_sync()`) is
tunnel-family -> plane `"wg"`, `provenance="tunnel"`. Every other source
(`dnsmasq`, `isc`, `arp`, `dhcp`, `scan`, legacy `mac-guard`/`device-intel`/
`iot-guard`, ...) is LAN-family -> plane `"lan"`, `provenance="lan"`.

Each row links back to A's device via `device_mac` (the same canonicalized
`mac` A's `DeviceStore` keys on) so the webui can deep-link a `lan:`/`wg:`
presence to its Project A client record. `client_type` prefers the device's
`device_type` (e.g. `"mesh_node"`) and falls back to the generic `"peer"`
when A hasn't classified the device yet. `hostname`/`device_type`/
`risk_level` are folded into `extra` (JSON) for display — no new PII beyond
what A already stores.

Fail-safe throughout: a `device_store.list()` that raises (missing store,
closed connection, ...) degrades to 0 collected, never raises out of
`collect_local`; a single malformed device row (no usable `mac`, or an
`upsert` failure) is skipped without aborting the rest of the batch.

Pure stdlib + `.store` (`pid`). No I/O at import time — only
`collect_local()` touches the device store.
"""
from __future__ import annotations

import json
import time

from .store import pid

DEFAULT_LIMIT = 5000

# Device `source` values that are tunnel-family (WireGuard mesh) rather
# than plain LAN discovery (dnsmasq/isc/arp/dhcp/scan/legacy-migrated).
_WG_SOURCES = ("mesh",)


def _plane_for_source(source) -> str:
    """Map a device's `source` column to a presence plane. Never raises."""
    if source in _WG_SOURCES:
        return "wg"
    return "lan"


def collect_local(store, device_store, *, limit: int = DEFAULT_LIMIT) -> int:
    """Mirror Project A's devices into `lan:`/`wg:` presences in `store`.

    Returns the number of devices projected into presences. Fail-safe: a
    raising `device_store.list()` (or a non-iterable/unexpected return
    value) yields 0 rather than propagating.
    """
    try:
        devices = device_store.list(limit=limit)
    except Exception:
        return 0

    if not devices:
        return 0

    count = 0
    for dev in devices:
        try:
            mac = dev.get("mac")
        except AttributeError:
            continue
        if not mac:
            continue

        plane = _plane_for_source(dev.get("source"))
        provenance = "tunnel" if plane == "wg" else "lan"
        client_type = dev.get("device_type") or "peer"
        last_seen = dev.get("last_seen") or int(time.time())
        extra = json.dumps({
            "hostname": dev.get("hostname"),
            "device_type": dev.get("device_type"),
            "risk_level": dev.get("risk_level"),
        })

        try:
            store.upsert({
                "id": pid(plane, mac),
                "plane": plane,
                "identity": mac,
                "device_mac": mac,
                "provenance": provenance,
                "client_type": client_type,
                "last_seen": last_seen,
                "extra": extra,
            })
        except Exception:
            # Fail-safe: a single bad upsert must not abort the collect.
            continue
        count += 1

    return count
