# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import json

import pytest

_TOML = """
mode = "both"
region = "EU_868"
serial = "auto"
[[channel]]
name = "family"
grid = ["off", "shared"]
psk_secret = "family-psk"
[shared_grid]
broker = "10.10.0.1:1883"
[on_grid]
broker = "mqtt.example.org:8883"
enabled = false
[passive]
role = "CLIENT_MUTE"
packet_log = "/var/log/secubox/meshtastic/packets.jsonl"
"""


@pytest.fixture()
def root(tmp_path):
    (tmp_path / "meshtastic.toml").write_text(_TOML)
    return tmp_path


@pytest.fixture(autouse=True)
def _as_root(monkeypatch):
    import api.ctl as ctl
    monkeypatch.setattr(ctl, "_running_as_root", lambda: True)


def _load(root):
    from api import config
    return config.load(root / "meshtastic.toml")


# ── set-grid ─────────────────────────────────────────────────────────────

def test_set_grid_updates_known_channel(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-grid", "family", "--grid", "off,on"])
    assert rc == 0
    cfg = _load(root)
    assert cfg.channels[0].grid == ("off", "on")


def test_set_grid_rejects_unknown_grid_value(root):
    from api.ctl import main
    before = _load(root)
    rc = main(["--root", str(root), "set-grid", "family", "--grid", "warp"])
    assert rc != 0
    after = _load(root)
    assert after.channels[0].grid == before.channels[0].grid


def test_set_grid_rejects_unknown_channel(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-grid", "ghost", "--grid", "off"])
    assert rc != 0


# ── set-mode ─────────────────────────────────────────────────────────────

def test_set_mode_valid_value_applies(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-mode", "passive-listener"])
    assert rc == 0
    assert _load(root).mode == "passive-listener"


def test_set_mode_turbo_rejected_before_any_write(root, capsys):
    from api.ctl import main
    before = root.joinpath("meshtastic.toml").read_text()
    with pytest.raises(SystemExit):
        main(["--root", str(root), "set-mode", "turbo"])
    assert root.joinpath("meshtastic.toml").read_text() == before


# ── set-role / set-region / set-psk ─────────────────────────────────────

def test_set_role_applies(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-role", "ROUTER"])
    assert rc == 0
    assert _load(root).passive.role == "ROUTER"


def test_set_region_applies(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-region", "US_915"])
    assert rc == 0
    assert _load(root).region == "US_915"


def test_set_psk_updates_known_channel_reference(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-psk", "family", "--secret", "new-name"])
    assert rc == 0
    assert _load(root).channels[0].psk_secret == "new-name"


def test_set_psk_rejects_unknown_channel(root):
    from api.ctl import main
    rc = main(["--root", str(root), "set-psk", "ghost", "--secret", "x"])
    assert rc != 0


# ── apply-egress ─────────────────────────────────────────────────────────

def test_apply_egress_no_broker_writes_no_accept_rule(root):
    from api.ctl import main
    rc = main(["--root", str(root), "apply-egress"])
    assert rc == 0
    dropin = root / "nftables.d" / "secubox-meshtastic-egress.nft"
    text = dropin.read_text()
    # The base chain declares "policy accept" (its own terminology, unrelated
    # to any allow rule) — what matters is that no broker allow RULE is
    # present: no destination-match rule was added to the chain body.
    assert "ip daddr" not in text and "meshtastic-on-grid" not in text
    assert "table inet secubox_meshtastic" in text


def test_apply_egress_with_enabled_broker_writes_allow_rule(root):
    from api.ctl import main
    (root / "meshtastic.toml").write_text(_TOML.replace(
        "[on_grid]\nbroker = \"mqtt.example.org:8883\"\nenabled = false",
        "[on_grid]\nbroker = \"mqtt.example.org:8883\"\nenabled = true"))
    rc = main(["--root", str(root), "apply-egress"])
    assert rc == 0
    dropin = root / "nftables.d" / "secubox-meshtastic-egress.nft"
    text = dropin.read_text()
    assert "accept" in text
    assert "mqtt.example.org" in text


# ── root guard ───────────────────────────────────────────────────────────

def test_root_guard_refuses_and_does_not_write(root, monkeypatch):
    import api.ctl as ctl
    monkeypatch.setattr(ctl, "_running_as_root", lambda: False)
    before = root.joinpath("meshtastic.toml").read_text()
    rc = ctl.main(["--root", str(root), "set-mode", "active-node"])
    assert rc == 1
    assert root.joinpath("meshtastic.toml").read_text() == before


# ── _dump round-trip ───────────────────────────────────────────────────────

def test_dump_round_trips_edit(root):
    from api import config
    from api.ctl import main
    main(["--root", str(root), "set-grid", "family", "--grid", "on"])
    cfg = config.load(root / "meshtastic.toml")
    assert cfg.channels[0].grid == ("on",)
    assert cfg.mode == "both"  # untouched fields survive the round-trip
    assert cfg.shared_grid.broker == "10.10.0.1:1883"
    assert cfg.on_grid.broker == "mqtt.example.org:8883"
    assert cfg.on_grid.enabled is False
    assert cfg.passive.role == "CLIENT_MUTE"


def test_audit_log_written_under_root(root):
    from api.ctl import main
    main(["--root", str(root), "set-mode", "passive-listener"])
    audit = root / "audit.log"
    assert audit.exists()
    entry = json.loads(audit.read_text().splitlines()[-1])
    assert entry["verb"] == "set-mode"
    assert entry["args"]["mode"] == "passive-listener"
