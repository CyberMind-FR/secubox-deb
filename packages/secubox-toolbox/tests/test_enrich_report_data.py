# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""_enrich_report_data populates every report enrichment key (#790 parity)."""
from secubox_toolbox import api, store


def test_enrich_populates_all_keys(monkeypatch):
    monkeypatch.setattr(api, "_dpi_stats", lambda mh: {"me": {"present": False}, "all": {}})
    monkeypatch.setattr(api, "_media_stats", lambda mh: {"me": {"present": False}, "all": {"present": False}})
    monkeypatch.setattr(api, "_build_pdf_donuts", lambda mh, d: [])
    monkeypatch.setattr(api, "_build_report_charts", lambda g: {"trackers": [{"label": "x", "count": 3}]})
    monkeypatch.setattr(api, "_persona_sheet", lambda *a, **k: {"tag": "T", "ua_seen": a[-1]})
    monkeypatch.setattr(store, "get_client_level", lambda mh: "r1")
    # social.fetch_graph is imported inside the helper via `from . import social`
    import secubox_toolbox.social as social
    monkeypatch.setattr(social, "fetch_graph",
                        lambda mh, since_seconds=0: {"stats": {"total_trackers": 4}, "nodes": [{"n": 1}], "by_country": [{"c": "FR"}]})

    data = {"device_type": "phone"}
    out = api._enrich_report_data("aabbccdd", data, ua="Mozilla/5.0")

    assert out is data  # mutates in place
    for k in ("dpi_exfil", "media_exfil", "pdf_donuts", "persona", "charts",
              "graph_stats", "bestiary", "carto_nodes", "carto_country"):
        assert k in out, f"missing {k}"
    assert out["persona"]["tag"] == "T"
    assert out["persona"]["ua_seen"] == "Mozilla/5.0"   # ua threaded through
    assert out["bestiary"] == [{"label": "x", "count": 3}]
    assert out["graph_stats"] == {"total_trackers": 4}
    assert out["carto_nodes"] == [{"n": 1}]


def test_enrich_survives_graph_failure(monkeypatch):
    monkeypatch.setattr(api, "_dpi_stats", lambda mh: {"me": {}, "all": {}})
    monkeypatch.setattr(api, "_media_stats", lambda mh: {"me": {}, "all": {}})
    monkeypatch.setattr(api, "_build_pdf_donuts", lambda mh, d: [])
    monkeypatch.setattr(api, "_build_report_charts", lambda g: {"trackers": []})
    monkeypatch.setattr(api, "_persona_sheet", lambda *a, **k: {"tag": "T"})
    monkeypatch.setattr(store, "get_client_level", lambda mh: "r1")
    import secubox_toolbox.social as social

    def _boom(*a, **k):
        raise RuntimeError("graph down")
    monkeypatch.setattr(social, "fetch_graph", _boom)

    out = api._enrich_report_data("aabbccdd", {"device_type": "pc"})
    assert out["graph_stats"] == {}          # fell back to empty graph
    assert out["bestiary"] == []
