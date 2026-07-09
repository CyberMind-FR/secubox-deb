# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.api tests — Task 5: emancipate the webui itself as a
standalone Tor hidden service + boot-time persist reconcile.

Mirrors tests/test_exposure_tor.py style: stub the blocking `_tor_add_sync`
mechanic (torrc edit + reload + onion poll) rather than touching real
torrc/systemctl, and stub `_publish` (annuaire federation) so federation is
verifiably best-effort / opt-in and never a real network call.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-exposure"))

import api.main as m  # noqa: E402


def _load(monkeypatch, tmp_path):
    """Point config + HS storage at an isolated tmp tree for this test."""
    monkeypatch.setattr(m, "CONFIG_FILE", tmp_path / "exposure.json")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path / "hidden_services")
    return m


def test_emancipate_webui_uses_9080_80(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        m, "_tor_add_sync",
        lambda name, local_port, onion_port: calls.append((name, local_port, onion_port))
        or {"success": True, "onion": "abc.onion"},
    )

    m.emancipate_webui(federate=False)

    assert calls == [("webui", 9080, 80)]


def test_emancipate_webui_standalone_skips_federation(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    fed = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda **k: {"success": True, "onion": "abc.onion"})
    monkeypatch.setattr(m, "_publish", lambda *a, **k: fed.append(a))

    m.emancipate_webui(federate=False)

    assert fed == []  # standalone: no annuaire publish


def test_emancipate_webui_records_active_entry(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "_tor_add_sync", lambda **k: {"success": True, "onion": "abc.onion"})

    m.emancipate_webui(federate=False)

    services = m._load_emancipated()
    webui = [s for s in services if s["name"] == "webui"]
    assert len(webui) == 1
    assert webui[0]["local_port"] == 9080
    assert webui[0]["onion_port"] == 80
    assert webui[0]["active"] is True


def test_emancipate_webui_federate_true_publishes_when_mesh_present(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "_tor_add_sync", lambda **k: {"success": True, "onion": "abc.onion"})
    monkeypatch.setattr(m, "_mesh_present", lambda: True)
    fed = []
    monkeypatch.setattr(m, "_publish", lambda *a, **k: fed.append(a))

    m.emancipate_webui(federate=True)

    assert fed  # federated when explicitly requested and mesh is present


def test_emancipate_webui_federation_never_raises(monkeypatch, tmp_path):
    """Federation is best-effort — a mesh/annuaire hiccup must not fail the
    (already-succeeded) webui emancipation."""
    m = _load(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "_tor_add_sync", lambda **k: {"success": True, "onion": "abc.onion"})
    monkeypatch.setattr(m, "_mesh_present", lambda: True)

    def _boom(*a, **k):
        raise RuntimeError("annuaire down")

    monkeypatch.setattr(m, "_publish", _boom)

    result = m.emancipate_webui(federate=True)  # must not raise
    assert result["success"] is True


def test_reconcile_reapplies_active_only(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    added = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: added.append(name))
    monkeypatch.setattr(m, "_hs_dir_exists", lambda n: False)
    m._save_emancipated([
        {"name": "webui", "local_port": 9080, "onion_port": 80, "active": True},
        {"name": "old", "local_port": 80, "onion_port": 80, "active": False},
    ])

    m.tor_reconcile_persist()

    assert added == ["webui"]  # inactive 'old' not re-added


def test_reconcile_never_recreates_existing_hs_dir(monkeypatch, tmp_path):
    """Idempotency: an existing HS dir must never be re-added — the .onion
    address must survive across reboots unchanged."""
    m = _load(monkeypatch, tmp_path)
    added = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: added.append(name))
    monkeypatch.setattr(m, "_hs_dir_exists", lambda n: True)  # already present
    m._save_emancipated([
        {"name": "webui", "local_port": 9080, "onion_port": 80, "active": True},
    ])

    m.tor_reconcile_persist()

    assert added == []


def test_reconcile_is_noop_on_empty_config(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    added = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: added.append(name))

    result = m.tor_reconcile_persist()

    assert added == []
    assert result["applied"] == []
