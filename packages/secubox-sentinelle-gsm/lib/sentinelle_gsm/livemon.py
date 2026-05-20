# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
RTL-SDR + grgsm_livemon_headless orchestration.

The actual demodulator (gr-gsm) runs in a separate systemd unit
(secubox-gsm-livemon@<freq>.service, templated) and dumps GSMTAP to
lo:4729/udp. This module's job:

  1. Detect RTL-SDR presence on the USB bus.
  2. Open a UDP socket on 127.0.0.1:4729 (no root, no suid — spec §5.1
     hard requirement).
  3. Parse incoming GSMTAP frames (scapy) and feed GsmCellObservation
     into the scoring engine.

v0.1.0: USB detection only. UDP listener + scapy parser stubbed —
the live frame stream lands in v0.2 once an RTL-SDR is plugged in
and gr-gsm is feeding lo:4729.
"""

from __future__ import annotations

import os
from typing import Optional


# RTL-SDR USB IDs (vendor:product). The original DVB-T sticks + the
# RTL-SDR Blog v3/v4 official units. Other clones with the same chipset
# enumerate the same way.
RTLSDR_USB_IDS: tuple[tuple[str, str], ...] = (
    ("0bda", "2832"),  # Realtek RTL2832U (DVB-T/RTL-SDR Blog v3)
    ("0bda", "2838"),  # Realtek RTL2832U + R820T2 (RTL-SDR Blog v4)
    ("1d50", "604b"),  # OpenMoko RTL-SDR
    ("1f4d", "0001"),  # GTek WinFast DTV
)


def detect_rtlsdr_usb() -> Optional[tuple[str, str]]:
    """Scan /sys/bus/usb for any RTL-SDR-compatible dongle. Returns
    (vid, pid) on first match, None otherwise. Sysfs (not lsusb) so the
    daemon can run sandboxed (no shell-out)."""
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
        for want_vid, want_pid in RTLSDR_USB_IDS:
            if vid == want_vid and pid == want_pid:
                return (vid, pid)
    return None


def listen_gsmtap_udp(host: str = "127.0.0.1", port: int = 4729):
    """v0.1.0 stub. The real implementation will:
      - bind UDP socket on (host, port)
      - parse incoming bytes as GSMTAP (scapy.layers.gsmtap)
      - feed each frame into scoring.score()

    Spec §5.1 hard requirement: NO sniff/suid mode. We bind a plain UDP
    port to receive frames from grgsm_livemon_headless on the same host.
    """
    raise NotImplementedError("listen_gsmtap_udp: scaffold v0.1.0; lands in v0.2")
