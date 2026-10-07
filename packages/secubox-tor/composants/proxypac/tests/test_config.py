# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.config tests."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proxypac import config


def test_socks_endpoint_prefers_toml_override(tmp_path):
    t = tmp_path / "proxypac.toml"
    t.write_text('socks_endpoint = "192.168.5.9:9050"\nrole = "auto"\n')
    c = config.load(str(t))
    assert c["socks_endpoint"] == "192.168.5.9:9050"
    assert c["role"] == "auto"


def test_onion_rule_uses_placeholder_not_hardcoded_mesh():
    r = (ROOT / "conf/rules.d/00-onion.rules").read_text()
    assert "__LAN_SOCKS__" in r
    assert "10.10.0.1:9050" not in r, "plus de SOCKS mesh injoignable en dur"


def test_defaults_when_no_toml(tmp_path):
    c = config.load(str(tmp_path / "absent.toml"))
    assert c["role"] == "auto"
    assert isinstance(c["transparent"], bool)
    assert ":9050" in c["socks_endpoint"]
