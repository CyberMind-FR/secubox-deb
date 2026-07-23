# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le cloud PicoBrew est éteint depuis 2020 : l'appareil ne sait parler qu'à
picobrew.com. Sans cette réécriture locale, il reste briqué."""
from pathlib import Path

CONF = Path(__file__).resolve().parents[1] / "conf" / "unbound-picobrew.conf"

def test_dropin_redirects_picobrew_com_to_the_lxc():
    t = CONF.read_text()
    assert "local-zone:" in t and '"picobrew.com."' in t
    assert "10.100.0.150" in t

def test_dropin_is_scoped_to_picobrew_only():
    """Une zone trop large casserait d'autres résolutions."""
    t = CONF.read_text()
    for forbidden in ('local-zone: "." ', 'local-zone: "com."'):
        assert forbidden not in t
