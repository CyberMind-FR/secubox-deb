# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#646 — adaptive Accept-Encoding strip.

The loader stream-inject needs an identity-encoded body, but forcing identity on
EVERY document pulls CSP-strict/heavy pages uncompressed for no benefit. We only
strip Accept-Encoding for hosts proven streaming-eligible on a prior visit;
unknown/ineligible hosts keep gzip/br.
"""
import sys
import pathlib
import importlib
import json

ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))

from mitmproxy.test import tflow, tutils      # noqa: E402
from secubox_toolbox import filters           # noqa: E402


def _addon(monkeypatch, tmp_path):
    fp = tmp_path / "filters.json"
    fp.write_text(json.dumps({"banner": True, "stream_inject": True}))
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp))
    filters.get_filters(force=True)
    import inject_banner
    importlib.reload(inject_banner)
    monkeypatch.setattr(inject_banner, "_client_level", lambda flow: "r3")
    inject_banner._STREAM_VERDICT.clear()
    return inject_banner


def _doc_request(host="example.com"):
    f = tflow.tflow()
    f.request.host = host
    f.request.headers["accept"] = "text/html,application/xhtml+xml"
    f.request.headers["accept-encoding"] = "gzip, br"
    f.request.headers["sec-fetch-dest"] = "document"
    return f


def _html_response(host="example.com"):
    f = tflow.tflow(resp=tutils.tresp())
    f.request.host = host
    f.response.headers["content-type"] = "text/html; charset=utf-8"
    f.response.status_code = 200
    f.request.headers["sec-fetch-dest"] = "document"
    return f


def test_unknown_host_keeps_compression(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _doc_request()
    ib.InjectBanner().request(f)
    assert f.request.headers["accept-encoding"] == "gzip, br"  # NOT stripped


def test_eligible_host_strips_identity(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    ib._STREAM_VERDICT["example.com"] = True
    f = _doc_request()
    ib.InjectBanner().request(f)
    assert f.request.headers["accept-encoding"] == "identity"


def test_ineligible_host_keeps_compression(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    ib._STREAM_VERDICT["example.com"] = False
    f = _doc_request()
    ib.InjectBanner().request(f)
    assert f.request.headers["accept-encoding"] == "gzip, br"


def test_responseheaders_records_eligible(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html_response()
    ib.InjectBanner().responseheaders(f)
    assert ib._STREAM_VERDICT.get("example.com") is True


def test_responseheaders_records_ineligible_for_csp_strict(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    monkeypatch.setattr(ib, "_detect_csp_strict", lambda flow: True)
    f = _html_response(host="strict.example.com")
    ib.InjectBanner().responseheaders(f)
    assert ib._STREAM_VERDICT.get("strict.example.com") is False
    assert not f.metadata.get("sbx_streamed")  # CSP-strict → buffer path, not stream


def test_learn_then_strip_end_to_end(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    # First visit: unknown host → not stripped.
    r1 = _doc_request()
    ib.InjectBanner().request(r1)
    assert r1.request.headers["accept-encoding"] == "gzip, br"
    # Response observed → host learned eligible.
    ib.InjectBanner().responseheaders(_html_response())
    assert ib._STREAM_VERDICT.get("example.com") is True
    # Second visit: now stripped → streaming will engage.
    r2 = _doc_request()
    ib.InjectBanner().request(r2)
    assert r2.request.headers["accept-encoding"] == "identity"


def test_verdict_cache_self_heals_on_overflow(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    monkeypatch.setattr(ib, "_STREAM_VERDICT_MAX", 4)
    for i in range(4):
        ib._record_stream_verdict(f"h{i}", True)
    assert len(ib._STREAM_VERDICT) == 4
    ib._record_stream_verdict("h4", True)  # overflow → clear then add
    assert len(ib._STREAM_VERDICT) == 1
    assert ib._STREAM_VERDICT.get("h4") is True
