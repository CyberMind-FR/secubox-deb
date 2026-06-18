# tests/test_tls_splice_addon.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, json, types
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))
from secubox_toolbox import filters


def _addon(monkeypatch, tmp_path, mode):
    fp = tmp_path / "f.json"; fp.write_text(json.dumps({"tls_splice": mode}))
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp)); filters.get_filters(force=True)
    import tls_splice; importlib.reload(tls_splice)
    a = tls_splice.TlsSplice()
    a._seed = {"googlevideo.com"}; a._learned = set(); a._never = set()
    monkeypatch.setattr(a, "_refresh_sets", lambda: None)
    return tls_splice, a


def _ch(sni):
    d = types.SimpleNamespace()
    d.client_hello = types.SimpleNamespace(sni=sni)
    d.context = types.SimpleNamespace(client=types.SimpleNamespace(peername=("10.99.1.2", 5)))
    d.ignore_connection = False
    return d


def test_on_splices_seed_host(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "on")
    d = _ch("r1.googlevideo.com"); a.tls_clienthello(d)
    assert d.ignore_connection is True


def test_observe_does_not_splice(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "observe")
    d = _ch("r1.googlevideo.com"); a.tls_clienthello(d)
    assert d.ignore_connection is False


def test_off_returns_early(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "off")
    d = _ch("r1.googlevideo.com"); a.tls_clienthello(d)
    assert d.ignore_connection is False


def test_non_seed_not_spliced(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "on")
    d = _ch("news.example.com"); a.tls_clienthello(d)
    assert d.ignore_connection is False


def test_no_sni_not_spliced(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "on")
    d = _ch(None); a.tls_clienthello(d)
    assert d.ignore_connection is False
