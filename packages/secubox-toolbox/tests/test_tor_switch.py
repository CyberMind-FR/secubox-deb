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


def test_banner_shows_tor_chip_when_armed():
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"))
    import importlib, inject_banner
    importlib.reload(inject_banner)
    on = inject_banner._banner_html_dynamic("sha", _banner_ctx(True), True, "https://kbin/r", "R3", "r3")
    off = inject_banner._banner_html_dynamic("sha", _banner_ctx(False), True, "https://kbin/r", "R3", "r3")
    assert b"&#x1F9C5; Tor" in on        # 🧅 chip present when armed
    assert b"&#x1F9C5;" not in off       # absent when off


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
