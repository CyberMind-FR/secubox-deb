# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, json
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
    return inject_banner


def _html(dest=None):
    f = tflow.tflow(resp=tutils.tresp())
    f.response.headers["content-type"] = "text/html; charset=utf-8"
    f.response.status_code = 200
    if dest is not None:
        f.request.headers["sec-fetch-dest"] = dest
    return f


def test_iframe_not_streamed(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html(dest="iframe")
    ib.InjectBanner().responseheaders(f)
    assert not f.metadata.get("sbx_streamed")      # iframe → no banner


def test_document_streamed(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html(dest="document")
    ib.InjectBanner().responseheaders(f)
    assert f.metadata.get("sbx_streamed") is True   # top-level → banner


def test_missing_dest_streamed(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html(dest=None)
    ib.InjectBanner().responseheaders(f)
    assert f.metadata.get("sbx_streamed") is True   # absent → assume top-level
