# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
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


def test_load_parses_all_sections(tmp_path):
    from api import config
    p = tmp_path / "meshtastic.toml"
    p.write_text(_TOML)
    c = config.load(p)
    assert c.mode == "both" and c.region == "EU_868"
    assert c.channels[0].name == "family" and c.channels[0].grid == ("off", "shared")
    assert c.shared_grid.broker == "10.10.0.1:1883"
    assert c.on_grid.enabled is False
    assert c.passive.role == "CLIENT_MUTE"


def test_rejects_bad_mode(tmp_path):
    from api import config
    p = tmp_path / "m.toml"
    p.write_text('mode="turbo"\nregion="EU_868"\n')
    with pytest.raises(config.ConfigError):
        config.load(p)


def test_rejects_unknown_grid(tmp_path):
    from api import config
    p = tmp_path / "m.toml"
    p.write_text('mode="active-node"\nregion="EU_868"\n[[channel]]\nname="x"\ngrid=["warp"]\npsk_secret="x"\n')
    with pytest.raises(config.ConfigError):
        config.load(p)


def test_missing_file_yields_safe_default(tmp_path):
    from api import config
    c = config.load(tmp_path / "nope.toml")
    assert c.mode == "active-node" and c.channels == [] and c.on_grid is None


def test_rejects_channel_without_name(tmp_path):
    from api import config
    p = tmp_path / "m.toml"
    p.write_text('mode="active-node"\n[[channel]]\ngrid=["off"]\npsk_secret="x"\n')
    with pytest.raises(config.ConfigError, match="missing required field 'name'"):
        config.load(p)


def test_rejects_broker_section_without_broker(tmp_path):
    from api import config
    p = tmp_path / "m.toml"
    p.write_text('mode="active-node"\n[shared_grid]\nenabled=true\n')
    with pytest.raises(config.ConfigError, match="missing required field 'broker'"):
        config.load(p)
