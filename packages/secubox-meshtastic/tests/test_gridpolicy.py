# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — grid policy tests."""
from api.config import Config, ChannelCfg, BrokerCfg


def _cfg(grid, on_enabled=False):
    return Config(channels=[ChannelCfg("c", tuple(grid), "psk")],
                  shared_grid=BrokerCfg("10.10.0.1:1883"),
                  on_grid=BrokerCfg("mqtt.x.org:8883", on_enabled))


def test_offgrid_only_bridges_nowhere():
    from api.gridpolicy import targets_for
    assert targets_for("c", _cfg(["off"])) == set()


def test_shared_and_on_targets():
    from api.gridpolicy import targets_for
    assert targets_for("c", _cfg(["off", "shared", "on"], on_enabled=True)) == {"shared", "on"}


def test_on_target_dropped_when_broker_disabled():
    from api.gridpolicy import targets_for
    assert targets_for("c", _cfg(["off", "on"], on_enabled=False)) == set()


def test_nft_rules_empty_when_no_on_grid():
    from api.gridpolicy import nft_egress_rules
    assert nft_egress_rules(_cfg(["off"], on_enabled=False)) == []


def test_nft_rules_allow_only_enabled_broker():
    from api.gridpolicy import nft_egress_rules
    rules = nft_egress_rules(_cfg(["on"], on_enabled=True))
    assert any("8883" in r and "mqtt.x.org" in r and "accept" in r for r in rules)
