# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrôle des DNS annoncés par la Freebox (#3769) : alerte, correction gardée, remise à zéro."""
import pytest

from api import dnscontrole as DC

R = dict(DC.DEFAUT)


class FauxSvc:
    def __init__(self, dns4, custom, dns6):
        self.dns4, self.custom, self.dns6, self.ecritures = list(dns4), custom, list(dns6), []

    def lire_dns(self):
        return list(self.dns4)

    def lire_dns6(self):
        return {"use_custom_dns": self.custom, "dns": list(self.dns6)}

    def regler_dns(self, s):
        self.ecritures.append(("dns", list(s)))
        self.dns4 = list(s)

    def regler_dns6(self, perso, s):
        self.ecritures.append(("dns6", perso, list(s)))
        self.custom, self.dns6 = perso, list(s)


def _ctl(svc, reglage=R, sonde=lambda s: True, **kw):
    return DC.controler(svc, "192.168.1.200", reglage, "2a01::200", sonde=sonde, horloge=lambda: 1, ecrire=lambda d: None, **kw)


def test_conforme_rien_n_est_ecrit():
    svc = FauxSvc(["192.168.1.200"], True, ["2a01::200"])
    e = _ctl(svc)
    assert e["conforme"] and not svc.ecritures and not e["alertes"]


def test_mode_corriger_remet_les_deux_familles():
    svc = FauxSvc([], False, [])
    e = _ctl(svc)
    assert e["corrections"] == ["ipv4", "ipv6"] and e["conforme"]
    assert ("dns", ["192.168.1.200"]) in svc.ecritures and ("dns6", True, ["2a01::200"]) in svc.ecritures


def test_mode_alerter_ne_touche_pas_la_freebox():
    svc = FauxSvc(["1.1.1.1"], True, ["2a01::200"])
    e = _ctl(svc, dict(R, mode="alerter"))
    assert not svc.ecritures and not e["conforme"] and "TV Privacy" in e["alertes"][0]


def test_secondaire_est_un_ecart():
    svc = FauxSvc(["192.168.1.200", "8.8.8.8"], True, ["2a01::200"])
    assert [x["famille"] for x in _ctl(svc, dict(R, mode="alerter"))["ecarts"]] == ["ipv4"]


def test_jamais_de_correction_vers_un_serveur_muet():
    svc = FauxSvc([], True, ["2a01::200"])
    e = _ctl(svc, sonde=lambda s: False)
    assert not svc.ecritures and e["refus"] and not e["conforme"]


def test_appliquer_force_meme_en_mode_alerter():
    svc = FauxSvc([], True, ["2a01::200"])
    assert _ctl(svc, dict(R, mode="alerter"), corriger_force=True)["conforme"]


def test_ipv6_inconnue_n_est_pas_controlee():
    svc = FauxSvc(["192.168.1.200"], False, [])
    e = DC.controler(svc, "192.168.1.200", R, "", sonde=lambda s: True, horloge=lambda: 1, ecrire=lambda d: None)
    assert e["conforme"] and not svc.ecritures


def test_reinitialiser_rend_les_dns_et_desactive(tmp_path, monkeypatch):
    monkeypatch.setattr(DC, "CHEMIN_REGLAGE", str(tmp_path / "r.json"))
    svc = FauxSvc(["192.168.1.200"], True, ["2a01::200"])
    e = DC.reinitialiser(svc, ecrire_e=lambda d: None)
    assert svc.dns4 == [] and svc.custom is False and e["actif"] is False
    assert DC.lire_reglage()["actif"] is False


@pytest.mark.parametrize("mauvais", [{"mode": "x"}, {"ipv4": "2a01::1"}, {"ipv6": "1.2.3.4"}, {"actif": "oui"}, {"autre": 1}, {"ipv4": "0.0.0.0"}])
def test_reglage_invalide_refuse(mauvais):
    with pytest.raises(ValueError):
        DC.valider(mauvais)


def test_reglage_ecrit_et_relu(tmp_path):
    p = str(tmp_path / "r.json")
    DC.ecrire_reglage({"mode": "alerter", "ipv4": "192.168.1.9"}, p)
    assert DC.lire_reglage(p) == dict(R, mode="alerter", ipv4="192.168.1.9")


def test_ipv6_stable_sans_prefixe(tmp_path):
    p = tmp_path / "d.toml"
    p.write_text('[ipv6]\nstable = "2a01:e0a:dec:c4e0::200/64"\n')
    assert DC.ipv6_stable(str(p)) == "2a01:e0a:dec:c4e0::200"
    assert DC.ipv6_stable(str(tmp_path / "absent")) == ""
