# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, json
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))
from mitmproxy.test import tflow, tutils   # noqa: E402


def _ib():
    import inject_banner
    importlib.reload(inject_banner)
    return inject_banner


def test_loader_js_served_inline_any_origin():
    ib = _ib()
    f = tflow.tflow()
    f.request.host = "peertube.gk2.secubox.in"
    f.request.path = "/__toolbox/loader.js"
    ib.InjectBanner().request(f)
    assert f.response is not None
    assert f.response.status_code == 200
    assert "javascript" in f.response.headers.get("content-type", "")
    body = f.response.get_text()
    assert "__SBX_LOADER__" in body          # the loader IIFE body


def test_bundle_served_inline_with_wg():
    ib = _ib()
    f = tflow.tflow()
    f.request.host = "lite.cnn.com"
    f.request.path = "/__toolbox/bundle"
    f.request.query["mh"] = "abcd"
    f.request.query["wg"] = "1"
    ib.InjectBanner().request(f)
    assert f.response is not None and f.response.status_code == 200
    assert "json" in f.response.headers.get("content-type", "")
    data = json.loads(f.response.get_text())
    assert data["report_url"].startswith("https://kbin.gk2.secubox.in")  # wg → public


def test_non_toolbox_request_not_intercepted():
    ib = _ib()
    f = tflow.tflow()
    f.request.host = "example.com"
    f.request.path = "/index.html"
    ib.InjectBanner().request(f)
    assert f.response is None                 # passes through
