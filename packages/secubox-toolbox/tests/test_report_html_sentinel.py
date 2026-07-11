# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#823 regression — the live HTML report (/report/me/html) must actually feed
the "🛡️ Compromission" tab from Sentinel data, not render it Undefined/inert.

report_me_html() previously rendered report-live.html.j2 with **session and a
pile of named kwargs but never a `report=` kwarg, while the template's
Compromission pane reads `report.sentinel`. Since build_report_data() is the
one place that folds sentinel_link.fetch_detections()+assess() into a
`sentinel` key (already used by the PDF routes), the fix threads that same
dict into the HTML render too.
"""
from fastapi.testclient import TestClient

from secubox_toolbox import api
from secubox_toolbox import sentinel_link as sl
from secubox_toolbox.app import app

client = TestClient(app)

MH = "aabbccdd11223344"


def test_report_me_html_surfaces_sentinel_detection(monkeypatch):
    # Local test env has no /etc/secubox/toolbox.toml — the route resolves
    # identity via _get_salt() even on the ?mh= bypass path, so stub it
    # rather than touching real config (unrelated to what's under test).
    monkeypatch.setattr(api, "_get_salt", lambda: "testsalt")
    monkeypatch.setattr(sl, "fetch_detections", lambda mac_hash, limit=50: [
        {"class": "spyware_pegasus", "action": "report", "severity": 95,
         "confidence": 95, "ts": 1234567890, "report": "RPT", "mac_hash": MH},
    ])

    r = client.get(f"/report/me/html?mh={MH}")

    assert r.status_code == 200
    body = r.text
    # The tab button itself is always rendered (static markup)...
    assert "Compromission" in body
    # ...but the fix under test is that it's now FED: the detection class
    # text must appear in the rendered pane, proving report.sentinel is a
    # real dict (not Undefined degrading to the "inactive" branch).
    assert "spyware_pegasus" in body
    assert "Sentinelle inactive" not in body


def test_report_me_html_stays_inactive_when_daemon_dark(monkeypatch):
    """Fail-safe: no detections → tab still renders, just says 'inactive'."""
    monkeypatch.setattr(api, "_get_salt", lambda: "testsalt")
    monkeypatch.setattr(sl, "fetch_detections", lambda mac_hash, limit=50: [])

    r = client.get(f"/report/me/html?mh={MH}")

    assert r.status_code == 200
    assert "Sentinelle inactive" in r.text
    assert "spyware_pegasus" not in r.text
