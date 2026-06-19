# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: Tor control-port helpers (#683)
CyberMind — https://cybermind.fr

Thin, dependency-free Tor control-port client, mirrored from the proven
``secubox-tor`` package (api/main.py ``tor_control``). The kbin Tor switch
reads status (bootstrap / circuits / exit IP) and requests a new identity
(NEWNYM) directly over the control port — no cross-service JWT, no root.

The control cookie is group-readable by ``debian-tor``; the toolbox postinst
adds ``secubox-toolbox`` to that group so the FastAPI portal can authenticate.
All functions are best-effort and never raise — a dead/absent Tor daemon
yields ``running=False`` rather than a 500, so the UI degrades gracefully.
"""
from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Dict

CONTROL_PORT = 9051
SOCKS_PORT = 9050
CONTROL_SOCKET = Path("/run/tor/control")
COOKIE_FILE = Path("/run/tor/control.authcookie")


def _connect() -> socket.socket:
    if CONTROL_SOCKET.exists():
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(str(CONTROL_SOCKET))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", CONTROL_PORT))
    return sock


def tor_control(command: str) -> str:
    """Authenticate (cookie if present) and run one control-port command.
    Returns the raw reply, or "" on any failure."""
    try:
        sock = _connect()
        try:
            if COOKIE_FILE.exists():
                cookie = COOKIE_FILE.read_bytes().hex()
                sock.send(f"AUTHENTICATE {cookie}\r\n".encode())
            else:
                sock.send(b"AUTHENTICATE\r\n")
            if "250 OK" not in sock.recv(1024).decode(errors="replace"):
                return ""
            sock.send(f"{command}\r\n".encode())
            return sock.recv(4096).decode(errors="replace")
        finally:
            sock.close()
    except Exception:
        return ""


def tor_running() -> bool:
    try:
        r = subprocess.run(["pgrep", "-x", "tor"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and r.stdout.strip() != ""
    except Exception:
        return False


def bootstrap_progress(reply: str | None = None) -> int:
    """Parse ``GETINFO status/bootstrap-phase`` PROGRESS=NN (0..100)."""
    resp = reply if reply is not None else tor_control("GETINFO status/bootstrap-phase")
    if "PROGRESS=" in resp:
        try:
            return int(resp.split("PROGRESS=")[1].split()[0])
        except Exception:
            pass
    return 0


def circuit_count(reply: str | None = None) -> int:
    """Count BUILT circuits from ``GETINFO circuit-status``."""
    resp = reply if reply is not None else tor_control("GETINFO circuit-status")
    return sum(1 for line in resp.splitlines() if " BUILT " in f" {line} ")


def new_identity() -> bool:
    """Request a fresh Tor circuit (SIGNAL NEWNYM). True on 250 OK."""
    return "250 OK" in tor_control("SIGNAL NEWNYM")


def status() -> Dict:
    """Best-effort consolidated status for the kbin Tor card."""
    if not tor_running():
        return {"running": False, "bootstrap": 0, "circuits": 0}
    boot = bootstrap_progress()
    circ = circuit_count()
    return {"running": True, "bootstrap": boot, "circuits": circ}
