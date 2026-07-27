# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: fleet_store
Atomic local IO for this node's own signed MetricSnapshot (self.json).

PURE local storage — no network, no signing, no subprocess. The publisher
(T4) writes its freshly-signed snapshot here after fleet.sign_snapshot();
a puller/UI reads it back to serve/display the node's own fleet record.

Atomicity: write() writes to `<path>.tmp` then os.replace()s it onto `path`.
os.replace is a single filesystem rename — a reader can never observe a
partially-written file, and a crash mid-write leaves the previous self.json
(or nothing) intact, never a truncated one.

Runtime path:
  /var/lib/secubox/annuaire/fleet/self.json  (production; parent dir created
  by postinst, T5 — this module does NOT mkdir, matching the "assumes parent
  dir exists" contract).
  Override via FLEET_SELF_PATH env (tests, alternate deployments).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

SELF_PATH = os.environ.get(
    "FLEET_SELF_PATH",
    "/var/lib/secubox/annuaire/fleet/self.json",
)


def write(rec: Dict[str, Any], path: str = SELF_PATH) -> None:
    """Atomically persist `rec` as JSON at `path`.

    Writes to `path + ".tmp"` then os.replace()s it onto `path` — a reader
    never observes a partial write. Assumes the parent directory already
    exists (created by postinst).
    """
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(rec, f)
    os.replace(tmp_path, path)


def read(path: str = SELF_PATH) -> Optional[Dict[str, Any]]:
    """Return the parsed dict at `path`, or None on missing/corrupt file.

    Fail-safe: any OSError (missing file, permission) or ValueError
    (malformed JSON) is swallowed and treated as "no record yet".
    """
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
