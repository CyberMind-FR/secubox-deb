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

    ip_fb = "192.168.1.254"

    def ip_freebox(self):
        return self.ip_fb

    def regler_dns6(self, perso, s):
        self.ecritures.append(("dns6", perso, list(s)))
        self.custom, self.dns6 = perso, list(s)


def _ctl(svc, reglage=R, sonde=lambda s: True, **kw):
    kw.setdefault("mobile", False)
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
    e = DC.controler(svc, "192.168.1.200", R, "", sonde=lambda s: True, horloge=lambda: 1, ecrire=lambda d: None, mobile=False)
    assert e["conforme"] and not svc.ecritures and "IPv6 non contrôlé" in e["alertes"][0]


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


# ── IPv6 de la box sans dns-lan.toml : relevée sur l'interface de la route par défaut ───────────────────────────────────────
ROUTES = [{"dst": "default", "dev": "eth0"}]


def _ip(*adresses):
    return [{"ifname": "eth0", "addr_info": list(adresses)}, {"ifname": "wg-mesh", "addr_info": [
        {"family": "inet6", "scope": "global", "local": "2001:db8:9::1", "valid_life_time": 4294967295}]}]


SLAAC = {"family": "inet6", "scope": "global", "local": "2a01:e0a:dec:c4e0:dea6:32ff:fe64:f596", "dynamic": True, "mngtmpaddr": True, "valid_life_time": 86000}
TEMP = {"family": "inet6", "scope": "global", "local": "2a01:e0a:dec:c4e0:1111:2222:3333:4444", "dynamic": True, "temporary": True, "valid_life_time": 80000}


def test_ipv6_slaac_stable_retenue_jamais_la_temporaire():
    assert DC.ipv6_box(_ip(TEMP, SLAAC), ROUTES) == "2a01:e0a:dec:c4e0:dea6:32ff:fe64:f596"     # cas réel de gk7


def test_ipv6_fixe_prioritaire():
    fixe = {"family": "inet6", "scope": "global", "local": "2a01:e0a:dec:c4e0::200", "valid_life_time": 4294967295}
    assert DC.ipv6_box(_ip(SLAAC, fixe), ROUTES) == "2a01:e0a:dec:c4e0::200"


def test_ipv6_depreciee_ou_hors_wan_ou_sans_route_ignoree():
    assert DC.ipv6_box(_ip(TEMP, dict(SLAAC, deprecated=True)), ROUTES) == ""
    assert DC.ipv6_box(_ip(SLAAC), []) == ""                                    # sans route par défaut : aucune devinette


def test_ipv6_relevee_sert_l_api(tmp_path, monkeypatch):
    monkeypatch.setattr(DC, "CHEMIN_ETAT", str(tmp_path / "e.json"))
    monkeypatch.setattr(DC, "CHEMIN_DNS_LAN", str(tmp_path / "absent.toml"))
    svc = FauxSvc(["192.168.1.128"], True, ["2a01::7"])
    DC.controler(svc, "192.168.1.128", R, "2a01::7", sonde=lambda s: True, horloge=lambda: 1, mobile=False)       # passage du minuteur
    assert DC.ipv6_auto_relevee() == "2a01::7"
    e = DC.controler(svc, "192.168.1.128", R, sonde=lambda s: True, horloge=lambda: 2, mobile=False)              # API : sans netlink
    assert e["attendu"]["ipv6"] == "2a01::7" and e["conforme"]


# ── deux box sur la même Freebox : une box en « auto » ne remplace jamais un autre résolveur qui répond ───────────────────
def test_autre_secubox_annoncee_et_vivante_pas_de_correction():
    # cas gk2/gk7 du 17/11 : gk2 (auto) voit la Freebox annoncer gk7, qui répond
    svc = FauxSvc(["192.168.1.128"], True, ["2a01::7"])
    e = DC.controler(svc, "192.168.1.200", R, "2a01::200", sonde=lambda s: True, horloge=lambda: 1, ecrire=lambda d: None, mobile=False)
    assert not svc.ecritures and e["conforme"] and {d["famille"] for d in e["delegue"]} == {"ipv4", "ipv6"}
    assert "autre résolveur" in e["alertes"][0]


def test_freebox_revenue_a_ses_dns_est_reprise():
    svc = FauxSvc(["192.168.1.254"], False, ["2a01::7"])          # sa propre adresse en IPv4, personnalisés décochés en IPv6
    e = _ctl(svc)
    assert e["corrections"] == ["ipv4", "ipv6"] and not e["delegue"]


def test_resolveur_annonce_mort_est_remplace():
    svc = FauxSvc(["192.168.1.128"], True, ["2a01::200"])
    e = _ctl(svc, sonde=lambda s: s != "192.168.1.128")
    assert e["corrections"] == ["ipv4"]


def test_adresse_saisie_ou_geste_appliquer_reprend_la_main():
    svc = FauxSvc(["192.168.1.128"], True, ["2a01::200"])
    assert _ctl(svc, dict(R, ipv4="192.168.1.200"))["corrections"] == ["ipv4"]
    svc = FauxSvc(["192.168.1.128"], True, ["2a01::200"])
    assert _ctl(svc, corriger_force=True)["corrections"] == ["ipv4"]


# ── clé mobile : secubox-mobile possède le DNS de la Freebox (retrait, réglage de l'utilisateur) ─────────────────────────
def test_cle_mobile_jamais_de_correction_meme_apres_retrait():
    svc = FauxSvc([], False, [])                                   # « retirer » a rendu à la Freebox ses DNS d'origine
    e = _ctl(svc, mobile=True)
    assert not svc.ecritures and not e["conforme"] and any("Clé mobile" in a for a in e["alertes"])


def test_cle_mobile_meme_le_geste_appliquer_ne_corrige_pas():
    svc = FauxSvc([], False, [])
    assert not _ctl(svc, mobile=True, corriger_force=True)["corrections"] and not svc.ecritures
