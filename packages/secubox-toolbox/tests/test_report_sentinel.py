# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from secubox_toolbox import reports
from secubox_toolbox import sentinel_link as sl


def test_build_report_data_folds_sentinel_active(monkeypatch):
    monkeypatch.setattr(sl, "fetch_detections", lambda mh, limit=50: [
        {"class": "spyware_pegasus", "severity": 95, "confidence": 95,
         "action": "report", "evidence": {}, "mac_hash": "aa", "ts": 1, "report": "R"},
    ])
    rep = reports.build_report_data("aa", {"device_type": "phone"})
    assert rep["sentinel"]["active"] is True
    assert rep["sentinel"]["assess"]["tier"] == "suspicious"
    assert len(rep["sentinel"]["detections"]) == 1


def test_build_report_data_sentinel_inactive_when_daemon_down(monkeypatch):
    monkeypatch.setattr(sl, "fetch_detections", lambda mh, limit=50: [])
    rep = reports.build_report_data("aa", {})
    assert rep["sentinel"]["active"] is False
    assert rep["sentinel"]["assess"]["tier"] == "clean"
    assert rep["sentinel"]["detections"] == []
