# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, json

# addons import 'from secubox_toolbox...' and sibling '_common'
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))

from mitmproxy.test import tflow            # noqa: E402
from secubox_toolbox import privacy, filters  # noqa: E402


def _mk_addon(monkeypatch, tmp_path, **toggles):
    fp = tmp_path / "filters.json"
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp))
    base = {"privacy_enforce": True, "privacy_poison": True,
            "privacy_anonymize": True, "fortknox_sites": []}
    base.update(toggles)
    fp.write_text(json.dumps(base))
    filters.get_filters(force=True)
    key = tmp_path / "jar.key"; key.write_text("k" * 32)
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None
    import privacy_guard
    importlib.reload(privacy_guard)
    monkeypatch.setattr(privacy_guard, "_client_hash", lambda flow: "clientHASH")
    return privacy_guard.PrivacyGuard()


def test_pure_tracker_blocked_with_204(monkeypatch, tmp_path):
    addon = _mk_addon(monkeypatch, tmp_path)
    f = tflow.tflow()
    f.request.host = "google-analytics.com"
    f.request.path = "/collect?v=2"
    f.request.headers["accept"] = "*/*"          # beacon hint
    addon.request(f)
    assert f.response is not None and f.response.status_code == 204


def test_loadbearing_tracker_cookie_forged_not_dropped(monkeypatch, tmp_path):
    addon = _mk_addon(monkeypatch, tmp_path)
    f = tflow.tflow()
    f.request.host = "criteo.com"
    f.request.path = "/js/loader.js"
    f.request.headers["accept"] = "text/html"
    f.request.headers["cookie"] = "_ga=GA1.2.111.222"
    addon.requestheaders(f)
    assert f.response is None                      # not blocked
    assert "cookie" in f.request.headers           # forged, not dropped
    assert f.request.headers["cookie"] != "_ga=GA1.2.111.222"
    assert "DNT" in f.request.headers


def test_observe_only_does_not_act(monkeypatch, tmp_path, privacy_enforce=False):
    addon = _mk_addon(monkeypatch, tmp_path, privacy_enforce=False)
    f = tflow.tflow()
    f.request.host = "google-analytics.com"
    f.request.path = "/collect"
    f.request.headers["accept"] = "*/*"
    addon.request(f)
    assert f.response is None                       # observe-only: never blocks
