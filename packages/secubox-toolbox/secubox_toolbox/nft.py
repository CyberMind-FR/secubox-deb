# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""nftables wrappers — validated_macs / consented_r2_macs / quarantine_macs sets."""
from __future__ import annotations

import logging
import subprocess

log = logging.getLogger("secubox.toolbox")

NFT = "/usr/sbin/nft"
TABLE = "inet toolbox"


def _run(*argv: str) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            argv, capture_output=True, text=True, timeout=2, check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def add_validated(mac: str, ttl: str = "24h") -> bool:
    rc, _, err = _run(NFT, "add", "element", "inet", "toolbox",
                      "validated_macs", "{ " + mac + " timeout " + ttl + " }")
    if rc:
        log.error("nft add validated_macs %s failed: %s", mac, err)
    return rc == 0


def add_consented(mac: str, ttl: str = "24h") -> bool:
    rc, _, err = _run(NFT, "add", "element", "inet", "toolbox",
                      "consented_r2_macs", "{ " + mac + " timeout " + ttl + " }")
    if rc:
        log.error("nft add consented_r2_macs %s failed: %s", mac, err)
    return rc == 0


def add_quarantine(mac: str, ttl: str = "1h") -> bool:
    rc, _, err = _run(NFT, "add", "element", "inet", "toolbox",
                      "quarantine_macs", "{ " + mac + " timeout " + ttl + " }")
    return rc == 0


def del_validated(mac: str) -> bool:
    rc, _, _ = _run(NFT, "delete", "element", "inet", "toolbox",
                    "validated_macs", "{ " + mac + " }")
    return rc == 0


def is_validated(mac: str) -> bool:
    rc, out, _ = _run(NFT, "list", "set", "inet", "toolbox", "validated_macs")
    return rc == 0 and mac.lower() in out.lower()


def is_consented(mac: str) -> bool:
    rc, out, _ = _run(NFT, "list", "set", "inet", "toolbox", "consented_r2_macs")
    return rc == 0 and mac.lower() in out.lower()
