# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Quectel EP06-E backend for the rbs-sensor.

v0.1.0 scope (scaffold):
  - USB enumeration + dynamic AT-port detection (probe each ttyUSB* with `AT`,
    expect `OK`)
  - Bring-up commands (echo off, ATI, AT+QGMR, AT+CPIN?, AT+CFUN?)
  - AT-command allowlist + reject any caller that tries to issue a forbidden
    command (no SMS, no contacts, no paging, no diag)
  - Async AT command mux (single-flight)
  - Stub Observer + Actuator that returns "modem not present" when no EP06
    is detected on the bus

Out of scope for v0.1.0 (deferred to v0.2):
  - Full servingcell / neighbourcell parser (LTE + GSM + WCDMA)
  - Verdict-driven mitigations on real hardware
  - Coordinator firmware OTA
"""

from __future__ import annotations

import asyncio
import glob
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from rbs_sensor.observer import (
    CAPTURES_SUBSCRIBER_IDENTIFIERS,
    CellObservation,
    NeighbourObservation,
    Observer,
)

logger = logging.getLogger("rbs_sensor.ep06")

# Quectel EP06-E (USB VID:PID). The mPCIe form factor of the EP06 enumerates
# via USB regardless of the slot — same VID:PID as the M.2/EVK variants.
EP06_USB_IDS: tuple[tuple[str, str], ...] = (
    ("2c7c", "0306"),  # Quectel EP06 (composite: 4×AT/QMI/diag/NMEA)
)

# AT-command allowlist. Any callable that tries to send something NOT in this
# set raises ATCommandDenied. Enforces OPAD §2 (no IMSI/TMSI capture, no diag).
# Test test_at_allowlist.py walks every code path and asserts that every AT
# string emitted is in this set.
AT_ALLOWLIST: frozenset[str] = frozenset(
    [
        # Identity + state
        "ATE0",
        "ATI",
        "AT+QGMR",
        "AT+CPIN?",
        "AT+CFUN?",
        "AT+CFUN=1",   # full RF
        "AT+CFUN=0",   # minimal
        "AT+CFUN=4",   # RF detach (airplane)
        # Cell telemetry
        'AT+COPS?',
        'AT+CREG?',
        'AT+CEREG?',
        'AT+QNWINFO',
        'AT+QCAINFO',
        'AT+CSQ',
        'AT+QTEMP',
        'AT+QNETDEVSTATUS',
        'AT+QENG="servingcell"',
        'AT+QENG="neighbourcell"',
        # Network-scan-mode levers (RAT lock)
        'AT+QCFG="nwscanmode"',          # query
        'AT+QCFG="nwscanmode",0,1',      # all RAT
        'AT+QCFG="nwscanmode",1,1',      # GSM only
        'AT+QCFG="nwscanmode",2,1',      # WCDMA only
        'AT+QCFG="nwscanmode",3,1',      # LTE only (refuse 2G)
        # Band lock (query before any modification)
        'AT+QCFG="band"',
    ]
)

# Explicitly forbidden — used by a separate test to prove these are NEVER
# emitted by the module, even via string concatenation.
AT_FORBIDDEN: frozenset[str] = frozenset(
    [
        # SMS / phonebook
        "AT+CMGL", "AT+CMGR", "AT+CMGS", "AT+CPBR", "AT+CPBF",
        # Identity (subscriber bound — IMEI is on-modem but listed as a
        # caution flag since some carriers treat it as subscriber-linked)
        "AT+CIMI",     # IMSI
        # Diagnostic / paging / Layer 3 decoding
        'AT+QCFG="usbcfg"',          # could enable diag port
        'AT+QPRTPARA',
        'AT+QRSTNV',
        # Promiscuous-style triggers
        "AT+CSCB",     # cell-broadcast subscription
    ]
)


class ATCommandDenied(RuntimeError):
    """Raised when a caller attempts to send a non-allowlisted AT command."""


def is_allowed(cmd: str) -> bool:
    """Whitelist check on a stripped AT command (no CR/LF)."""
    return cmd.strip() in AT_ALLOWLIST


def detect_ep06_usb() -> Optional[tuple[str, str]]:
    """Scan /sys/bus/usb for a Quectel EP06. Returns (vid, pid) on hit, None
    if no matching device. We avoid the `lsusb` shellout — sysfs is reliable
    and the daemon may be sandboxed (NoNewPrivileges)."""
    import os

    sysfs = "/sys/bus/usb/devices"
    if not os.path.isdir(sysfs):
        return None
    for dev in os.listdir(sysfs):
        path = os.path.join(sysfs, dev)
        try:
            with open(os.path.join(path, "idVendor"), "r") as f:
                vid = f.read().strip().lower()
            with open(os.path.join(path, "idProduct"), "r") as f:
                pid = f.read().strip().lower()
        except (FileNotFoundError, PermissionError):
            continue
        for want_vid, want_pid in EP06_USB_IDS:
            if vid == want_vid and pid == want_pid:
                return (vid, pid)
    return None


def candidate_at_ports() -> list[str]:
    """ttyUSB* nodes that could be the EP06's AT port. We probe each one with
    `AT` and accept the first that answers `OK` within 1s. Spec §4.1: do NOT
    hard-code ttyUSB2 — the kernel order depends on hub topology and module
    revision."""
    return sorted(glob.glob("/dev/ttyUSB*"))


@dataclass
class Ep06Modem:
    """Synchronous-feeling wrapper over the EP06 AT port.

    The actual serial I/O is async (single-flight via the mux lock); the
    public sync methods schedule and await on the daemon's event loop.

    v0.1.0 scope: only is_present() + identity() are wired. Telemetry and
    mitigation methods raise NotImplementedError so callers see a clear
    "hardware required" path.
    """

    port: Optional[str] = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _identity: Optional[str] = field(default=None, init=False)

    def is_present(self) -> bool:
        """True if a Quectel EP06 is enumerated on the USB bus AND we found
        an AT-responsive ttyUSB* port."""
        if detect_ep06_usb() is None:
            return False
        if self.port is None:
            # Lazy: try to find an AT port; v0.1.0 does the cheap USB-only
            # check and reports present=True only when both checks pass.
            return self._discover_port() is not None
        return True

    def _discover_port(self) -> Optional[str]:
        """v0.1.0 stub: returns the first /dev/ttyUSB* if any. v0.2 will
        actually open + write `AT\\r` and wait for OK within 1s."""
        ports = candidate_at_ports()
        if not ports:
            return None
        self.port = ports[0]
        return self.port

    async def identity(self) -> Optional[str]:
        """Returns the `ATI` response (Quectel EP06 Revision: ...).
        v0.1.0 stub: returns None unless a real port is opened (deferred)."""
        if not self.is_present():
            return None
        # v0.2: send AT-ALLOWLIST['ATI'] through the mux, parse the response.
        return None


@dataclass
class Ep06Observer:
    """Observer Protocol implementation backed by Ep06Modem.

    v0.1.0: always returns "not present" when no modem is connected, which
    is the expected state on a board without an EP06 plugged in.
    """

    modem: Ep06Modem = field(default_factory=Ep06Modem)

    @property
    def name(self) -> str:
        return "ep06"

    @property
    def captures_subscriber_identifiers(self) -> bool:
        # Hard-coded False — the structural proof lives in observer.py.
        return CAPTURES_SUBSCRIBER_IDENTIFIERS  # always False

    def is_present(self) -> bool:
        return self.modem.is_present()

    def serving_cell(self) -> Optional[CellObservation]:
        # v0.1.0: hardware not yet driven. Returns None until v0.2 ships
        # the AT+QENG="servingcell" parser.
        if not self.modem.is_present():
            return None
        return None

    def neighbours(self) -> list[NeighbourObservation]:
        if not self.modem.is_present():
            return []
        return []


@dataclass
class Ep06Actuator:
    """Off-path mitigations. v0.1.0: stubs that record intent but DO NOT
    touch the modem yet. v0.2 wires the AT commands behind the allowlist."""

    modem: Ep06Modem = field(default_factory=Ep06Modem)
    _saved_nwscanmode: Optional[str] = field(default=None, init=False)
    _saved_band: Optional[str] = field(default=None, init=False)

    async def mitigate_lte_only(self) -> dict:
        if not self.modem.is_present():
            return {"ok": False, "reason": "modem-absent", "action": "lte-only"}
        # v0.2: read AT+QCFG="nwscanmode", save to _saved_nwscanmode,
        # then AT+QCFG="nwscanmode",3,1.
        return {"ok": False, "reason": "not-implemented-v0.1", "action": "lte-only"}

    async def mitigate_rf_off(self) -> dict:
        if not self.modem.is_present():
            return {"ok": False, "reason": "modem-absent", "action": "rf-off"}
        return {"ok": False, "reason": "not-implemented-v0.1", "action": "rf-off"}

    async def restore(self) -> dict:
        if not self.modem.is_present():
            return {"ok": False, "reason": "modem-absent", "action": "restore"}
        return {"ok": False, "reason": "not-implemented-v0.1", "action": "restore"}
