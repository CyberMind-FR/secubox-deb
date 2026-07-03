# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""The report template renders the media-type block (me + overall) (ref #785)."""
from html.parser import HTMLParser
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

CONF = Path(__file__).resolve().parents[1] / "conf"

PANE_IDS = ("pane-pistage", "pane-dpi", "pane-overall")


class _DivDepthParser(HTMLParser):
    """Tracks <div> nesting depth and records the depth at which each
    tab-pane <div id="pane-..."> opens. Stdlib-only (no bs4/html5lib)."""

    def __init__(self):
        super().__init__()
        self.depth = 0
        self.pane_depths = {}

    def handle_starttag(self, tag, attrs):
        if tag != "div":
            return
        attrs_dict = dict(attrs)
        div_id = attrs_dict.get("id")
        if div_id in PANE_IDS:
            self.pane_depths[div_id] = self.depth
        self.depth += 1

    def handle_endtag(self, tag):
        if tag == "div":
            self.depth -= 1


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


def test_tab_panes_are_siblings_not_nested():
    """Regression for #785 Task-4 review fix: each new media <div class="card">
    inside #pane-dpi / #pane-overall must close itself before the pane's own
    closing </div>. If it doesn't, the extra card </div> closes the PANE
    instead, and #pane-overall (plus everything after it) ends up nested
    inside #pane-dpi — hidden on every tab except "DPI"."""
    html = _render({
        "me": {"present": True, "kinds": [{"label": "video", "emoji": "📺", "pct": 100, "start": 0, "end": 100}],
               "ctypes": [{"label": "video/mp4", "emoji": "🏷️", "pct": 100, "start": 0, "end": 100}],
               "top_hosts": [{"host": "v.example", "kind": "video", "bytes": 3000000}]},
        "all": {"present": True, "kinds": [{"label": "manifest", "emoji": "🎞️", "pct": 100, "start": 0, "end": 100}],
                "ctypes": [], "top_hosts": []},
    })
    parser = _DivDepthParser()
    parser.feed(html)

    for pane_id in PANE_IDS:
        assert pane_id in parser.pane_depths, f"{pane_id} not found in rendered HTML"

    depths = {pane_id: parser.pane_depths[pane_id] for pane_id in PANE_IDS}
    assert len(set(depths.values())) == 1, (
        f"tab panes are not siblings at the same DOM depth: {depths}"
    )
