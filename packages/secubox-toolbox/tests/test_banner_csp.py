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


def _html_resp(csp=None):
    f = tflow.tflow(resp=tutils.tresp())
    f.response.headers["content-type"] = "text/html; charset=utf-8"
    f.response.status_code = 200
    if csp:
        f.response.headers["content-security-policy"] = csp
    return f


def test_strict_csp_does_not_stream(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html_resp(csp="script-src 'self'; object-src 'none'")
    ib.InjectBanner().responseheaders(f)
    assert not f.metadata.get("sbx_streamed")


def test_no_csp_streams(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html_resp(csp=None)
    ib.InjectBanner().responseheaders(f)
    assert f.metadata.get("sbx_streamed") is True
