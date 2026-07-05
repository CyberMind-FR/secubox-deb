# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""kbin Tor switch (#683): filters flags + control-port parsing."""
import importlib
import json

import pytest


@pytest.fixture()
def filters_mod(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_FILTERS_PATH", str(tmp_path / "filters.json"))
    import secubox_toolbox.filters as f
    importlib.reload(f)
    return f


def test_tor_defaults_off(filters_mod):
    cur = filters_mod.get_filters(force=True)
    assert cur["tor_mode"] is False
    assert cur["tor_preset"] == "anonymous"


def test_tor_mode_is_bool_coerced(filters_mod):
    out = filters_mod.set_filters({"tor_mode": 1})
    assert out["tor_mode"] is True
    on_disk = json.loads((filters_mod.FILTERS_PATH and open(filters_mod.FILTERS_PATH).read()))
    assert on_disk["tor_mode"] is True


def test_tor_preset_enum_guarded(filters_mod):
    out = filters_mod.set_filters({"tor_preset": "bogus"})
    assert out["tor_preset"] == "anonymous"  # rejected, default kept
    out = filters_mod.set_filters({"tor_preset": "stealth"})
    assert out["tor_preset"] == "stealth"


def test_set_filters_persists_when_dir_not_writable(tmp_path, monkeypatch):
    """Regression (#683): aggregator runs as a user that can't create a tmp file
    in the 0750 /etc/secubox/toolbox — set_filters must still persist in-place."""
    import os
    d = tmp_path / "ro"
    d.mkdir()
    fpath = d / "filters.json"
    fpath.write_text('{"banner": true}\n')
    monkeypatch.setenv("SECUBOX_FILTERS_PATH", str(fpath))
    import secubox_toolbox.filters as f
    importlib.reload(f)
    os.chmod(d, 0o555)  # dir read-only → tmp+rename fails, in-place must work
    try:
        out = f.set_filters({"tor_mode": True})
        assert out["tor_mode"] is True
        assert json.loads(fpath.read_text())["tor_mode"] is True  # actually persisted
    finally:
        os.chmod(d, 0o755)


def test_get_filters_clamps_bad_preset_on_disk(filters_mod):
    with open(filters_mod.FILTERS_PATH, "w") as fh:
        json.dump({"tor_preset": "evil"}, fh)
    assert filters_mod.get_filters(force=True)["tor_preset"] == "anonymous"


def test_bootstrap_progress_parse():
    from secubox_toolbox import tor_ctl
    reply = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"
    assert tor_ctl.bootstrap_progress(reply) == 100
    assert tor_ctl.bootstrap_progress("garbage") == 0


def test_circuit_count_parse():
    from secubox_toolbox import tor_ctl
    reply = (
        "250+circuit-status=\r\n"
        "1 BUILT $AAA~a,$BBB~b PURPOSE=GENERAL\r\n"
        "2 BUILT $CCC~c PURPOSE=GENERAL\r\n"
        "3 LAUNCHED PURPOSE=GENERAL\r\n"
        ".\r\n250 OK\r\n"
    )
    assert tor_ctl.circuit_count(reply) == 2


class _FakeReq:
    def __init__(self, host="admin.gk2.secubox.in", body=None):
        self.headers = {"host": host}
        self._body = body or {}

    async def json(self):
        return self._body


@pytest.fixture()
def api_mod(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_FILTERS_PATH", str(tmp_path / "filters.json"))
    import secubox_toolbox.filters as f
    importlib.reload(f)
    import secubox_toolbox.api as api
    return api


@pytest.mark.asyncio
async def test_tor_on_off_flips_flag(api_mod):
    out = await api_mod.admin_tor_on(_FakeReq(body={"tor_preset": "stealth"}))
    assert out["tor_mode"] is True and out["tor_preset"] == "stealth"
    out = await api_mod.admin_tor_off(_FakeReq())
    assert out["tor_mode"] is False


@pytest.mark.asyncio
async def test_tor_actions_blocked_on_public_kbin(api_mod):
    from fastapi import HTTPException
    for fn in (api_mod.admin_tor_on, api_mod.admin_tor_off,
               api_mod.admin_tor_newnym, api_mod.admin_tor_check_leaks):
        with pytest.raises(HTTPException) as ei:
            await fn(_FakeReq(host="kbin.gk2.secubox.in"))
        assert ei.value.status_code == 403


@pytest.mark.asyncio
async def test_tor_state_shape_offline(api_mod, monkeypatch):
    from secubox_toolbox import tor_ctl
    monkeypatch.setattr(tor_ctl, "tor_running", lambda: False)
    st = await api_mod.admin_tor_state()
    assert st["tor_mode"] is False
    assert st["running"] is False
    assert "bootstrap" in st and "circuits" in st and "exit_ip" in st


def _banner_ctx(tor_mode):
    return {
        "status_icon": "\U0001F50D", "status": "inspected", "flag": "", "app_emoji": "",
        "app": "example.com", "asn": "", "grade": "A", "grade_color": "#0f0",
        "cookies_set": 0, "cookies_sent": 0, "is_tracker_host": False,
        "utiq_recent_count": 0, "ghost_blocked": 0, "ghost_kb": 0, "tor_mode": tor_mode,
    }


def _inject_banner_mod():
    import sys, pathlib, importlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"))
    import inject_banner
    importlib.reload(inject_banner)
    return inject_banner


def test_banner_shows_tor_chip_when_armed():
    inject_banner = _inject_banner_mod()
    on = inject_banner._banner_html_dynamic("sha", _banner_ctx(True), True, "https://kbin/r", "R3", "r3")
    off = inject_banner._banner_html_dynamic("sha", _banner_ctx(False), True, "https://kbin/r", "R3", "r3")
    assert b"&#x1F9C5; Tor" in on        # 🧅 chip present when armed
    assert b"&#x1F9C5;" not in off       # absent when off


def test_inject_banner_output_is_ascii_encodable():
    # #620 invariant — both render paths must stay ASCII-encodable (NCR-encoded
    # emoji). The csp_strict path html.encode("ascii") and the JS-path
    # js.encode("ascii") are exercised here; a raw non-ASCII byte would raise.
    inject_banner = _inject_banner_mod()
    for csp_strict in (True, False):
        out = inject_banner._banner_html_dynamic(
            "3A:9F:C1", _banner_ctx(True), csp_strict, "https://kbin/r", "R3", "r3")
        assert isinstance(out, bytes)
        out.decode("ascii")                         # must not raise
        assert b"__GONDWANA_MITM_BANNER__" in out   # _GUARD idempotency marker
        assert b"gondwana-mitm-banner" in out       # banner id preserved


def test_inject_banner_three_cluster_and_close():
    # Structural responsive fix — left rank+grade pinned, middle chips scroll,
    # right report+close pinned. The JS (dismissible) path carries the close ✕
    # in the right-pinned cluster; the csp_strict path has NO close (non-dismiss).
    inject_banner = _inject_banner_mod()
    js = inject_banner._banner_html_dynamic(
        "sha", _banner_ctx(False), False, "https://kbin/r", "R3", "r3").decode("ascii")
    assert "box-sizing:border-box" in js
    assert "flex:0 0 auto" in js and "flex:1 1 auto" in js  # pinned + growing clusters
    assert "min-width:0" in js and "overflow-x:auto" in js  # middle scrolls
    assert 'aria-label="dismiss"' in js                    # close control present
    assert "&#x2715;" in js                                 # ✕ glyph
    # csp_strict path is non-dismissible → no close control.
    strict = inject_banner._banner_html_dynamic(
        "sha", _banner_ctx(False), True, "https://kbin/r", "R3", "r3").decode("ascii")
    assert "&#x2715;" not in strict and "aria-label" not in strict


def test_nft_tunnel_failclosed_invariants():
    """The nft tunnel MUST keep its fail-closed safety net — guard against
    accidental removal of the kill-switch / redirect / v6-leak rules."""
    import pathlib
    nft = pathlib.Path(__file__).resolve().parents[1] / "conf" / "nft-toolbox-tor.nft"
    text = nft.read_text()
    # redirect into Tor TransPort + DNSPort
    assert "redirect to :9040" in text
    assert "redirect to :5353" in text
    # kill-switch drops (fail-closed) for v4 escape + v6 leak
    assert "ip daddr != 127.0.0.0/8 drop" in text
    assert "meta nfproto ipv6" in text and "drop" in text
    # only the worker uid is torified (not a blanket rule)
    assert text.count('meta skuid "secubox-toolbox"') >= 4
    # own-services exemption: the reconciler-populated set must exist and be
    # consulted before the redirect/drop (so the box reaches itself directly)
    assert "set tor_exempt" in text
    assert text.count("ip daddr @tor_exempt return") >= 2


def test_bundle_banner_has_tor_indicator(tmp_path, monkeypatch):
    """The LIVE injected banner is the stream-inject bundle (bundle.py), not the
    server-side inject_banner chip. Its render() must show the 🧅 span and the
    decision bundle must carry tor_mode."""
    import importlib
    monkeypatch.setenv("SECUBOX_FILTERS_PATH", str(tmp_path / "filters.json"))
    import secubox_toolbox.filters as f
    importlib.reload(f)
    f.set_filters({"tor_mode": True})
    import secubox_toolbox.bundle as b
    importlib.reload(b)
    assert b.build_bundle("abc", True)["tor_mode"] is True
    assert b.build_bundle("abc", True) is not None
    # the banner render() (shared by loader + inline) emits the 🧅 span
    assert "b.tor_mode" in b.LOADER_JS
    assert "\U0001F9C5" in b.LOADER_JS  # 🧅


def test_reconcile_populates_exempt_and_excludes_automap():
    """The reconciler must fill tor_exempt with loopback + own public IP and
    must NOT exempt the Tor automap range (10.192/10) or transparent proxy breaks."""
    import pathlib
    sh = (pathlib.Path(__file__).resolve().parents[1]
          / "sbin" / "secubox-toolbox-tor-reconcile").read_text()
    assert "tor_exempt" in sh and "127.0.0.0/8" in sh
    assert "api.ipify.org" in sh          # own public IP detected direct
    assert "scope link" in sh             # board-local subnets
    assert "10.19" in sh                   # explicit automap-range guard
