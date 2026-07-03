# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""The report template renders the media-type block (me + overall) (ref #785)."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

CONF = Path(__file__).resolve().parents[1] / "conf"


def _render(media_exfil):
    env = Environment(loader=FileSystemLoader(str(CONF)))
    tpl = env.get_template("report-live.html.j2")
    return tpl.render(
        metrics={}, graph_stats={}, exposure_score=0, charts={}, graph={"edges": []},
        persona={}, dpi_exfil={"me": {}, "all": {}}, media_exfil=media_exfil,
        mac_hash="deadbeef", ip="10.99.0.2", device_type="phone",
        current_level="r3", indicators=[], recommendations=[], avatar_analysis={},
        cookies_providers=[], geo_top_hosts=[], pinned_apps=[], transparency={},
        request_args={},
    )


def test_media_block_present_when_data():
    html = _render({
        "me": {"present": True, "kinds": [{"label": "video", "emoji": "📺", "pct": 100, "start": 0, "end": 100}],
               "ctypes": [{"label": "video/mp4", "emoji": "🏷️", "pct": 100, "start": 0, "end": 100}],
               "top_hosts": [{"host": "v.example", "kind": "video", "bytes": 3000000}]},
        "all": {"present": True, "kinds": [{"label": "manifest", "emoji": "🎞️", "pct": 100, "start": 0, "end": 100}],
                "ctypes": [], "top_hosts": []},
    })
    assert "Types de médias captés" in html
    assert "video/mp4" in html
    assert "v.example" in html


def test_media_block_fail_empty_no_error():
    html = _render({"me": {"present": False}, "all": {"present": False}})
    assert "Types de médias captés" in html  # card title still there
    assert "Aucun média" in html             # fail-empty message
