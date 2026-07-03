# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Smoke tests: PDF renders with media_exfil + dpi_exfil donut grids (ref #785)."""
from secubox_toolbox import reports


def _donut(label="video", pct=100):
    return [{"label": label, "emoji": "📺", "count": 1, "pct": pct, "start": 0, "end": pct}]


def _base(**extra):
    d = {"mac_hash": "deadbeef", "device_type": "phone", "generated_at": "2026-07-03",
         "indicators": [], "recommendations": [], "pinned_apps": []}
    d.update(extra)
    return d


def test_pdf_renders_with_media_and_dpi():
    data = _base(
        dpi_exfil={
            "me": {"present": True, "flows": 3, "up": 2048, "down": 4096, "alert_count": 1,
                   "categories": _donut("cloud"), "protocols": _donut("tls"),
                   "alerts": _donut("exfil"), "destinations": _donut("aws")},
            "all": {"devices": 2, "flows": 9, "alert_count": 1,
                    "categories": _donut("media"), "protocols": _donut("quic"),
                    "alerts": _donut("beacon"), "destinations": _donut("yt")},
        },
        media_exfil={
            "me": {"present": True, "flows": 4, "bytes": 5_000_000,
                   "kinds": _donut("video", 60) + _donut("audio", 40),
                   "ctypes": _donut("video/mp4", 100),
                   "top_hosts": [{"host": "v.example", "kind": "video", "bytes": 3_000_000}]},
            "all": {"present": True, "flows": 8, "bytes": 9_000_000,
                    "kinds": _donut("manifest", 100), "ctypes": _donut("x/y", 100),
                    "top_hosts": []},
        },
    )
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 1000  # a real PDF, not the text stub


def test_pdf_renders_empty_media_no_raise():
    data = _base(dpi_exfil={"me": {"present": False}, "all": {}},
                 media_exfil={"me": {"present": False}, "all": {"present": False}})
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 500


def test_donut_grid_captions_not_mislabeled(monkeypatch):
    """Each donut grid must carry its own caption — not all stamped 'STATS DE TON APPAREIL'
    (ref #785 review: DPI-me/DPI-all/media grids were reusing the device-stats caption)."""
    titles = []
    orig_section = reports._section

    def _spy_section(pdf, title):
        titles.append(title)
        return orig_section(pdf, title)

    monkeypatch.setattr(reports, "_section", _spy_section)

    data = _base(
        dpi_exfil={
            "me": {"present": True, "flows": 3, "up": 2048, "down": 4096, "alert_count": 1,
                   "categories": _donut("cloud"), "protocols": _donut("tls"),
                   "alerts": _donut("exfil"), "destinations": _donut("aws")},
            "all": {"devices": 2, "flows": 9, "alert_count": 1,
                    "categories": _donut("media"), "protocols": _donut("quic"),
                    "alerts": _donut("beacon"), "destinations": _donut("yt")},
        },
        media_exfil={
            "me": {"present": True, "flows": 4, "bytes": 5_000_000,
                   "kinds": _donut("video", 60) + _donut("audio", 40),
                   "ctypes": _donut("video/mp4", 100),
                   "top_hosts": [{"host": "v.example", "kind": "video", "bytes": 3_000_000}]},
            "all": {"present": True, "flows": 8, "bytes": 9_000_000,
                    "kinds": _donut("manifest", 100), "ctypes": _donut("x/y", 100),
                    "top_hosts": []},
        },
    )
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 1000

    device_caption = "📊 STATS DE TON APPAREIL (graphiques)"
    assert titles.count(device_caption) <= 1, (
        f"device-stats caption appeared {titles.count(device_caption)} times: {titles}")

    for expected in (
        "🛰️ DPI — sorties de cet appareil",
        "🌍 DPI — réseau (tous appareils)",
        "🎬 Types de médias — graphiques",
    ):
        assert expected in titles, f"missing caption {expected!r} in {titles}"
