# packages/secubox-eye-square/kiosk/tests/test_transport_manager.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for transport_manager.py — OTG/WiFi/SIM probing + JWT renewal."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from secubox_eye_square_kiosk.transport_manager import TransportManager


def test_initial_state_is_sim():
    tm = TransportManager(simulate=True)
    assert tm.active == "SIM"


def test_probe_otg_first_then_wifi_then_sim():
    """When SIMULATE=False, probe order is OTG, WiFi, SIM."""
    tm = TransportManager(simulate=False, otg_base="http://10.55.0.1:8000",
                          wifi_base="http://secubox.local:8000")
    # First probe — OTG succeeds
    with patch("secubox_eye_square_kiosk.transport_manager.httpx.Client.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        tm.probe()
    assert tm.active == "OTG"


def test_probe_falls_back_to_wifi_on_otg_failure():
    tm = TransportManager(simulate=False, otg_base="http://10.55.0.1:8000",
                          wifi_base="http://secubox.local:8000")
    def fake_get(url, **kw):
        if "10.55.0.1" in url:
            raise Exception("OTG unreachable")
        return MagicMock(status_code=200)
    with patch("secubox_eye_square_kiosk.transport_manager.httpx.Client.get",
               side_effect=fake_get):
        tm.probe()
    assert tm.active == "WiFi"


def test_probe_falls_back_to_sim_on_both_failures():
    tm = TransportManager(simulate=False, otg_base="http://10.55.0.1:8000",
                          wifi_base="http://secubox.local:8000")
    with patch("secubox_eye_square_kiosk.transport_manager.httpx.Client.get",
               side_effect=Exception("network down")):
        tm.probe()
    assert tm.active == "SIM"


def test_simulate_true_forces_sim():
    tm = TransportManager(simulate=True)
    tm.probe()
    assert tm.active == "SIM"


def test_on_transport_change_hook_fires_on_transition():
    tm = TransportManager(simulate=False, otg_base="http://x", wifi_base="http://y")
    received = []
    tm.on_transport_change = lambda active: received.append(active)
    tm._set_active("WiFi")
    tm._set_active("WiFi")  # dedupe
    tm._set_active("OTG")
    assert received == ["WiFi", "OTG"]
