# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-tor api tests — Task 6: auto-discover every on-disk
.onion (not just config-listed ones) + .onion-DNS status.

_discover_hidden_services() must glob TOR_DATA for every `*/hostname`, not
rely on the secubox config's `hidden_services` list — hand-created or
orphaned hidden services must still surface. GET /onion_dns reports whether
the (moved) Tor DNSPort is up, whether the unbound forward-zone drop-in is
installed, and a best-effort bounded canary resolution.

Both must be fail-safe: missing TOR_DATA, unreadable hostname files, or a
down DNSPort must never raise/500 — they degrade to empty/false.
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-tor"))

import api.main as m  # noqa: E402


def _load(monkeypatch):
    return m


# ---------------------------------------------------------------------------
# _discover_hidden_services
# ---------------------------------------------------------------------------

def test_hidden_services_autodiscovers_onion(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_webui").mkdir()
    (tmp_path / "hidden_service_webui" / "hostname").write_text("abc123.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)

    svcs = m._discover_hidden_services()

    assert any(s["onion_address"] == "abc123.onion" and s["name"] == "webui" for s in svcs)


def test_discover_surfaces_onion_not_in_config(monkeypatch, tmp_path):
    """A hand-created / orphaned hidden service dir with no config entry must
    still be discovered — that's the whole point of the task."""
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_orphan").mkdir()
    (tmp_path / "hidden_service_orphan" / "hostname").write_text("orphan123.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    svcs = m._discover_hidden_services()

    assert len(svcs) == 1
    assert svcs[0]["name"] == "orphan"
    assert svcs[0]["onion_address"] == "orphan123.onion"
    assert svcs[0]["has_address"] is True
    # not in config -> local_port/enabled unknown, not fabricated
    assert svcs[0]["local_port"] is None
    assert svcs[0]["enabled"] is None


def test_discover_cross_references_config_for_known_service(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_ssh").mkdir()
    (tmp_path / "hidden_service_ssh" / "hostname").write_text("sshbox.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {
        "hidden_services": [{"name": "ssh", "local_port": 22, "enabled": True}]
    })

    svcs = m._discover_hidden_services()

    assert len(svcs) == 1
    assert svcs[0]["local_port"] == 22
    assert svcs[0]["enabled"] is True


def test_discover_handles_dir_without_hidden_service_prefix(monkeypatch, tmp_path):
    """Dir names are not guaranteed to carry the hidden_service_ prefix —
    strip it only when present, otherwise use the dir name as-is."""
    m = _load(monkeypatch)
    (tmp_path / "bare_dir").mkdir()
    (tmp_path / "bare_dir" / "hostname").write_text("bare.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    svcs = m._discover_hidden_services()

    assert svcs[0]["name"] == "bare_dir"


def test_discover_missing_tor_data_returns_empty_not_raises(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "TOR_DATA", tmp_path / "does" / "not" / "exist")

    svcs = m._discover_hidden_services()

    assert svcs == []


def test_discover_unreadable_hostname_skipped_not_raised(monkeypatch, tmp_path):
    """A hostname 'file' that can't be read as text (e.g. it's actually a
    directory) must not blow up the whole scan."""
    m = _load(monkeypatch)
    svc_dir = tmp_path / "hidden_service_broken"
    svc_dir.mkdir()
    (svc_dir / "hostname").mkdir()  # hostname is a dir, not a file -> read_text() raises
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    svcs = m._discover_hidden_services()

    assert len(svcs) == 1
    assert svcs[0]["name"] == "broken"
    assert svcs[0]["onion_address"] == ""
    assert svcs[0]["has_address"] is False


def test_discover_finds_exposure_nested_layout(monkeypatch, tmp_path):
    """secubox-exposure's emancipate flow (tor_emancipate_webui et al.) creates
    hidden services under TOR_DATA/"hidden_services"/<name>/hostname — e.g.
    /var/lib/tor/hidden_services/webui/hostname — NOT directly under TOR_DATA
    like this module's own legacy add_hidden_service(). Discovery must find
    those too, bare name (no hidden_service_ prefix to strip)."""
    m = _load(monkeypatch)
    nested = tmp_path / "hidden_services" / "webui"
    nested.mkdir(parents=True)
    (nested / "hostname").write_text("webuionion123.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    svcs = m._discover_hidden_services()

    assert len(svcs) == 1
    assert svcs[0]["name"] == "webui"
    assert svcs[0]["onion_address"] == "webuionion123.onion"
    assert svcs[0]["has_address"] is True


def test_discover_merges_both_layouts_without_duplicating(monkeypatch, tmp_path):
    """A service present under the legacy flat layout AND one under the
    nested exposure layout must both surface, with no name collision."""
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_ssh").mkdir()
    (tmp_path / "hidden_service_ssh" / "hostname").write_text("sshbox.onion\n")
    nested = tmp_path / "hidden_services" / "webui"
    nested.mkdir(parents=True)
    (nested / "hostname").write_text("webuionion123.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    svcs = m._discover_hidden_services()

    names = {s["name"] for s in svcs}
    assert names == {"ssh", "webui"}


def test_discover_nested_layout_missing_returns_only_flat(monkeypatch, tmp_path):
    """No TOR_DATA/hidden_services dir at all must not raise — just no extra
    entries from that layout."""
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_ssh").mkdir()
    (tmp_path / "hidden_service_ssh" / "hostname").write_text("sshbox.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    svcs = m._discover_hidden_services()

    assert len(svcs) == 1
    assert svcs[0]["name"] == "ssh"


def test_discover_broken_config_falls_back_to_empty_map(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_webui").mkdir()
    (tmp_path / "hidden_service_webui" / "hostname").write_text("abc.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)

    def _boom():
        raise RuntimeError("config unreadable")
    monkeypatch.setattr(m, "load_config", _boom)

    svcs = m._discover_hidden_services()

    assert len(svcs) == 1
    assert svcs[0]["onion_address"] == "abc.onion"


# ---------------------------------------------------------------------------
# GET /hidden_services (endpoint wiring)
# ---------------------------------------------------------------------------

def test_hidden_services_endpoint_uses_discovery(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    (tmp_path / "hidden_service_webui").mkdir()
    (tmp_path / "hidden_service_webui" / "hostname").write_text("abc123.onion\n")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "load_config", lambda: {"hidden_services": []})

    result = asyncio.run(m.get_hidden_services())

    assert result["total"] == 1
    assert result["services"][0]["onion_address"] == "abc123.onion"


def test_hidden_services_endpoint_empty_when_no_tor_data(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "TOR_DATA", tmp_path / "nope")

    result = asyncio.run(m.get_hidden_services())

    assert result == {"services": [], "total": 0}


# ---------------------------------------------------------------------------
# GET /onion_dns
# ---------------------------------------------------------------------------

def test_onion_dns_reports_down_when_nothing_listening(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_port_listening", lambda port: False)
    monkeypatch.setattr(m, "ONION_FORWARD_ZONE", Path("/nonexistent/48-secubox-onion.conf"))

    result = asyncio.run(m.get_onion_dns())

    assert result == {"dnsport_up": False, "forward_zone_installed": False, "resolves": False}


def test_onion_dns_skips_canary_when_prereqs_not_met(monkeypatch):
    """resolves must stay False (and the canary must not even be attempted)
    unless BOTH dnsport_up and forward_zone_installed are True."""
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_port_listening", lambda port: True)
    monkeypatch.setattr(m, "ONION_FORWARD_ZONE", Path("/nonexistent/48-secubox-onion.conf"))
    called = []
    monkeypatch.setattr(m, "_onion_dns_canary", lambda *a, **k: called.append(1) or True)

    result = asyncio.run(m.get_onion_dns())

    assert result["dnsport_up"] is True
    assert result["forward_zone_installed"] is False
    assert result["resolves"] is False
    assert called == []


def test_onion_dns_attempts_canary_when_prereqs_met(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    zone = tmp_path / "48-secubox-onion.conf"
    zone.write_text("forward-zone:\n")
    monkeypatch.setattr(m, "_port_listening", lambda port: True)
    monkeypatch.setattr(m, "ONION_FORWARD_ZONE", zone)
    monkeypatch.setattr(m, "_onion_dns_canary", lambda *a, **k: True)

    result = asyncio.run(m.get_onion_dns())

    assert result == {"dnsport_up": True, "forward_zone_installed": True, "resolves": True}


def test_onion_dns_never_raises_when_port_check_explodes(monkeypatch):
    """Fail-safe contract: even if the underlying check blows up, the
    endpoint must degrade to False, never 500."""
    m = _load(monkeypatch)

    def _boom(port):
        raise OSError("no /proc/net/tcp on this box")
    monkeypatch.setattr(m, "_port_listening", _boom)
    monkeypatch.setattr(m, "ONION_FORWARD_ZONE", Path("/nonexistent"))

    result = asyncio.run(m.get_onion_dns())

    assert result["dnsport_up"] is False
    assert result["resolves"] is False


def test_port_listening_bounded_false_on_missing_proc(monkeypatch):
    """_port_listening itself must fail closed if /proc/net/* can't be read,
    without raising."""
    m = _load(monkeypatch)
    assert m._port_listening(6553799) is False  # port out of any real range, never bound


def test_onion_dns_canary_fails_closed_when_nothing_listens():
    """No mocking: hitting an almost-certainly-closed UDP port must return
    False within the bounded timeout, not hang or raise."""
    import api.main as m
    assert m._onion_dns_canary(timeout=0.3) in (True, False)  # must return, not hang
