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


def add_r2_banner(mac: str, ttl: str = "24h") -> bool:
    """Phase 3 (#492) : R2 explicit opt-in subset (banner inject + QUIC drop)."""
    rc, _, err = _run(NFT, "add", "element", "inet", "toolbox",
                      "r2_banner_macs", "{ " + mac + " timeout " + ttl + " }")
    if rc:
        log.error("nft add r2_banner_macs %s failed: %s", mac, err)
    return rc == 0


def del_r2_banner(mac: str) -> bool:
    rc, _, _ = _run(NFT, "delete", "element", "inet", "toolbox",
                    "r2_banner_macs", "{ " + mac + " }")
    return rc == 0


def del_consented(mac: str) -> bool:
    """Remove MAC from consented_r2_macs (used for R0 downgrade)."""
    rc, _, _ = _run(NFT, "delete", "element", "inet", "toolbox",
                    "consented_r2_macs", "{ " + mac + " }")
    return rc == 0


def is_r2_banner(mac: str) -> bool:
    rc, out, _ = _run(NFT, "list", "set", "inet", "toolbox", "r2_banner_macs")
    return rc == 0 and mac.lower() in out.lower()


# Phase 6 (#496) : R3 WireGuard consented set

def add_r3_wg(mac: str, ttl: str = "24h") -> bool:
    rc, _, err = _run(NFT, "add", "element", "inet", "toolbox",
                      "consented_r3_wg_macs", "{ " + mac + " timeout " + ttl + " }")
    if rc:
        log.error("nft add consented_r3_wg_macs %s failed: %s", mac, err)
    return rc == 0


def del_r3_wg(mac: str) -> bool:
    rc, _, _ = _run(NFT, "delete", "element", "inet", "toolbox",
                    "consented_r3_wg_macs", "{ " + mac + " }")
    return rc == 0


def is_r3_wg(mac: str) -> bool:
    rc, out, _ = _run(NFT, "list", "set", "inet", "toolbox", "consented_r3_wg_macs")
    return rc == 0 and mac.lower() in out.lower()
