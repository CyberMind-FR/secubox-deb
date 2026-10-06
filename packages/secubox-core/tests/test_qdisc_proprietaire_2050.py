# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 vague 0 : un seul propriétaire du qdisc racine par interface (qos / traffic)."""
import pytest

from secubox_core import qdisc


@pytest.fixture(autouse=True)
def _dossier(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_QDISC_DIR", str(tmp_path))


def test_interface_libre_puis_reclamee():
    assert qdisc.owner("eth0") is None
    assert qdisc.claim("eth0", "qos") is True
    assert qdisc.owner("eth0") == "qos"


def test_le_proprietaire_peut_reclamer_de_nouveau():
    assert qdisc.claim("eth0", "qos")
    assert qdisc.claim("eth0", "qos")


def test_un_autre_module_est_refuse():
    assert qdisc.claim("eth0", "qos")
    assert qdisc.claim("eth0", "traffic") is False
    assert qdisc.owner("eth0") == "qos"


def test_liberation_par_le_seul_proprietaire():
    qdisc.claim("eth0", "qos")
    qdisc.release("eth0", "traffic")
    assert qdisc.owner("eth0") == "qos"
    qdisc.release("eth0", "qos")
    assert qdisc.owner("eth0") is None
    assert qdisc.claim("eth0", "traffic") is True


@pytest.mark.parametrize("nom", ["../etc/passwd", "a/b", "", "x" * 40, "eth0;rm"])
def test_nom_d_interface_invalide_refuse(nom):
    with pytest.raises(ValueError):
        qdisc.claim(nom, "qos")


def test_vlan_et_alias_acceptes():
    assert qdisc.claim("eth0.100", "qos")
    assert qdisc.claim("br-lan", "traffic")
