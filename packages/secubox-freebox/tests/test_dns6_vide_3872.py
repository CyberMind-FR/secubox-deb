# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3872 : une Freebox jamais personnalisée en DHCPv6 rend `"dns": {}` ; c'est une liste vide, pas une réponse anormale
(sinon le DNS IPv6 n'est jamais annoncé et les appareils en double pile contournent la box)."""
import pytest

from api import client as c
from tests.test_service_api import _session, _svc
from tests.test_client import VERSION


def _cfg(dns, custom=False):
    return (200, {"success": True, "result": {"enabled": False, "use_custom_dns": custom, "dns": dns}})


def test_dns6_vide_en_objet_est_une_liste_vide(tmp_path):
    svc, _, _ = _svc(tmp_path, [VERSION] + _session() + [_cfg({})], app_token="T", autorise=True)
    assert svc.lire_dns6() == {"use_custom_dns": False, "dns": []}


@pytest.mark.parametrize("dns", [{"a": "fd00::1"}, "fd00::1", None])
def test_dns6_autre_forme_reste_une_erreur(tmp_path, dns):
    svc, _, _ = _svc(tmp_path, [VERSION] + _session() + [_cfg(dns)], app_token="T", autorise=True)
    with pytest.raises(c.ErreurFreebox):
        svc.lire_dns6()
