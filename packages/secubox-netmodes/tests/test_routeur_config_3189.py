# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Configuration validée du mode routeur (#3189)."""
from ipaddress import IPv4Network

import pytest

from api.routeur_config import (
    ConfigRouteur, ErreurConfig, charger, depuis_dict, en_toml, verifier_reseaux,
)

BASE = {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100",
        "dhcp_fin": "192.168.42.199"}


def cfg42():
    return depuis_dict(dict(BASE))


def test_defauts():
    c = cfg42()
    assert c.bail == "12h"
    assert c.ports == ("lan0", "lan1", "lan2", "lan3")
    assert c.wan == "eth2"
    assert str(c.adresse.network) == "192.168.42.0/24"


@pytest.mark.parametrize("surcharge", [
    {"adresse": "192.168.255.1/24", "dhcp_debut": "192.168.255.100", "dhcp_fin": "192.168.255.199"},
    {"adresse": "10.100.0.1/24", "dhcp_debut": "10.100.0.100", "dhcp_fin": "10.100.0.199"},
    {"adresse": "192.168.42.1/31"},
    {"adresse": "192.168.42.1/32"},
    {"adresse": "192.168.42.0/24"},
    {"adresse": "fd00::1/64"},
    {"dhcp_debut": "192.168.43.100"},
    {"dhcp_fin": "192.168.43.199"},
    {"dhcp_debut": "192.168.42.199", "dhcp_fin": "192.168.42.100"},
    {"dhcp_debut": "192.168.42.1"},
    {"ports": ["eth1"]},
    {"ports": ["lan4"]},
    {"ports": ["lan0", "lan0"]},
    {"ports": []},
    {"bail": "12x"},
    {"bail": "0h"},
    {"bail": "99999h"},
    {"wan": "wlan0"},
    {"wan": "eth10"},
    {"bail": "12h\n"},
    {"wan": "eth2\n"},
    {"ports": ["lan0\n"]},
    {"adresse": "192.168.42.1/24\n"},
    {"dhcp_debut": "192.168.42.100\n"},
])
def test_refus(surcharge):
    with pytest.raises(ErreurConfig):
        depuis_dict({**BASE, **surcharge})


def test_verifier_reseaux():
    verifier_reseaux(cfg42(), [IPv4Network("192.168.1.0/24")])
    with pytest.raises(ErreurConfig):
        verifier_reseaux(cfg42(), [IPv4Network("192.168.0.0/16")])


def test_aller_retour(tmp_path):
    c = depuis_dict({**BASE, "ports": ["lan2", "lan0"], "bail": "30m"})
    f = tmp_path / "routeur.toml"
    f.write_text(en_toml(c))
    assert charger(f) == c


def test_charger_invalide(tmp_path):
    f = tmp_path / "x.toml"
    f.write_text("[lan\n")
    with pytest.raises(ErreurConfig):
        charger(f)
    f.write_text('[autre]\na = "b"\n')
    with pytest.raises(ErreurConfig):
        charger(f)
    with pytest.raises(ErreurConfig):
        charger(tmp_path / "absent.toml")


def test_charger_octet_non_utf8_et_imbrication_profonde(tmp_path):
    """Relecture finale I1 : un TOML édité à la main (octet Latin-1) ou trop imbriqué reste une ErreurConfig, jamais une
    UnicodeDecodeError ou une RecursionError qui ferait tomber l'état et le retour."""
    f = tmp_path / "x.toml"
    f.write_bytes(b'[lan]\nadresse = "192.168.42.1/24"\n# r\xe9seau du bureau\n')
    with pytest.raises(ErreurConfig, match="UTF-8"):
        charger(f)
    f.write_text("a = " + "[" * 100000)
    with pytest.raises(ErreurConfig, match="imbrication"):
        charger(f)
