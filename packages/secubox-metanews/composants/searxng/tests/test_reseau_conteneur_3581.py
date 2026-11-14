# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 : l'image Debian du conteneur livre eth0.network en DHCP=true ; systemd-networkd effaçait l'adresse posée par LXC
(aucun DHCP sur br-lxc) et l'installation échouait en apt-get 100 (banc gk6, 2026-11-12). searxngctl pose un eth0 statique
et n'avance que si l'adresse est présente et stable."""
import subprocess

import pytest

CFG = {"lxc": {"name": "searxng", "path": "/data/lxc", "ip": "10.100.0.85", "gateway": "10.100.0.1",
               "dns": ["1.1.1.1", "9.9.9.9"]}}


class FauxConteneur:
    def __init__(self, adresses, reseau=None):
        self.adresses = list(adresses)     # une valeur par sonde : True = adresse présente
        self.fichiers = {} if reseau is None else {"/etc/systemd/network/eth0.network": reseau}
        self.commandes = []

    def etat(self):
        return "running"

    def lire(self, chemin):
        return self.fichiers.get(chemin)

    def ecrire(self, chemin, contenu, mode="0644"):
        self.fichiers[chemin] = contenu

    def executer(self, argv, **kw):
        self.commandes.append(argv)
        if argv[:2] == ["ip", "-4"]:
            present = self.adresses.pop(0) if self.adresses else False
            out = " inet 10.100.0.85/24 " if present else ""
            return subprocess.CompletedProcess(argv, 0, out, "")
        return subprocess.CompletedProcess(argv, 0, "", "")


@pytest.fixture(autouse=True)
def sans_attente(ctl, monkeypatch):
    monkeypatch.setattr(ctl.time, "sleep", lambda s: None)


def test_reseau_statique_sans_dhcp(ctl):
    r = ctl.reseau_conteneur(CFG)
    assert "Address=10.100.0.85/24" in r and "Gateway=10.100.0.1" in r
    assert "DNS=1.1.1.1" in r and "DNS=9.9.9.9" in r
    assert "DHCP" not in r and "LinkLocalAddressing=no" in r


def test_ecrit_le_reseau_et_relance_networkd(ctl):
    ct = FauxConteneur([True, True, True], reseau="[Network]\nDHCP=true\n")
    ctl.demarrer_et_reseau(CFG, ct)
    assert ct.fichiers["/etc/systemd/network/eth0.network"] == ctl.reseau_conteneur(CFG)
    assert ["systemctl", "restart", "systemd-networkd"] in ct.commandes


def test_rien_a_ecrire_si_deja_juste(ctl):
    ct = FauxConteneur([True, True, True], reseau=ctl.reseau_conteneur(CFG))
    ctl.demarrer_et_reseau(CFG, ct)
    assert ["systemctl", "restart", "systemd-networkd"] not in ct.commandes


def test_adresse_qui_disparait_n_est_pas_acceptee(ctl):
    # présente, puis effacée par networkd, puis stable : on n'avance qu'après trois sondes de suite
    ct = FauxConteneur([True, False, True, True, True], reseau=ctl.reseau_conteneur(CFG))
    ctl.demarrer_et_reseau(CFG, ct)
    assert not ct.adresses


def test_sans_adresse_erreur_claire(ctl):
    ct = FauxConteneur([], reseau=ctl.reseau_conteneur(CFG))
    with pytest.raises(RuntimeError, match="10.100.0.85"):
        ctl.demarrer_et_reseau(CFG, ct)
