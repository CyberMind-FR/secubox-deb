# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""IPv6 Guardian — le verdict dit la vérité (jamais « protégé » sans avoir lu le pare-feu) ; le service met la mesure en cache."""
import time

from api import service as s
from api import verdict as v
from tests.test_collecte import AVAHI, NEIGH4, NEIGH6


def _appareil(publique=True, services=()):
    return {"mac": "aa:bb:cc:dd:ee:ff", "nom": "X", "adresses_publiques": ["2a01::1"] if publique else [],
            "services": [{"type": t, "sensible": sens, "libelle": t, "port": 1, "nom": ""} for t, sens in services]}


# ── verdict ──────────────────────────────────────────────────────────────────
def test_sans_ipv6_public_rien_n_est_joignable():
    r = v.verdict([_appareil(publique=False)], freebox=None)
    assert r["niveau"] == "sans_ipv6" and "rien" in r["explication"].lower()


def test_sans_lecture_de_la_freebox_on_ne_dit_jamais_protege():
    r = v.verdict([_appareil()], freebox=None)
    assert r["niveau"] == "a_verifier" and "protégé" not in r["titre"].lower()
    assert "Freebox" in r["explication"]


def test_pare_feu_actif_sans_exception_le_reseau_est_protege():
    r = v.verdict([_appareil()], freebox={"pare_feu_actif": True, "exceptions": []})
    assert r["niveau"] == "protege"


def test_pare_feu_actif_avec_exceptions_dit_combien_sont_ouvertes():
    r = v.verdict([_appareil()], freebox={"pare_feu_actif": True, "exceptions": [{"appareil": "NAS", "port": 443}, {"appareil": "NAS", "port": 22}]})
    assert r["niveau"] == "ouvert_partiellement" and "2" in r["titre"]


def test_pare_feu_desactive_est_une_alerte():
    r = v.verdict([_appareil()], freebox={"pare_feu_actif": False, "exceptions": []})
    assert r["niveau"] == "expose"


def test_un_service_sensible_sur_un_appareil_public_est_signale():
    r = v.verdict([_appareil(services=[("_ssh._tcp", True)])], freebox=None)
    assert r["sensibles"] == 1
    assert v.verdict([_appareil(publique=False, services=[("_ssh._tcp", True)])], freebox=None)["sensibles"] == 0


def test_les_quatre_etapes_sont_toujours_presentes_dans_l_ordre():
    e = v.etapes([_appareil(services=[("_ipp._tcp", False)])], freebox=None)
    assert [x["id"] for x in e] == ["appareils", "services", "bloquees", "exceptions"]
    assert e[0]["valeur"] == 1 and e[1]["valeur"] == 1
    assert e[2]["etat"] == "non_lu" and e[3]["etat"] == "non_lu" and e[2]["valeur"] is None


def test_avec_la_freebox_les_etapes_trois_et_quatre_se_remplissent():
    e = v.etapes([_appareil()], freebox={"pare_feu_actif": True, "exceptions": [{"appareil": "NAS", "port": 443}]})
    assert e[2]["etat"] == "ok" and e[3]["valeur"] == 1 and e[3]["etat"] == "ok"
    assert e[3]["liste"] == [{"appareil": "NAS", "port": 443}]


def test_les_textes_sont_du_langage_courant():
    for appareils in ([_appareil()], [_appareil(publique=False)], [_appareil(), _appareil()]):
        r = v.verdict(appareils, None)
        texte = (r["titre"] + " " + r["explication"]).lower()
        for jargon in ("nft", "ndp", "slaac", "gua", "conntrack", "prefix"):
            assert jargon not in texte


# ── service : cache et robustesse ────────────────────────────────────────────
class Faux:
    def __init__(self, mdns=AVAHI, voisins6=NEIGH6, voisins4=NEIGH4, lent=0.0, panne=False):
        self.appels, self.mdns, self.v6, self.v4, self.lent, self.panne = [], mdns, voisins6, voisins4, lent, panne

    def __call__(self, argv, delai=5):
        self.appels.append(tuple(argv))
        if argv[0] == "avahi-browse":
            if self.lent:
                time.sleep(self.lent)
            if self.panne:
                raise OSError("avahi absent")
            return self.mdns
        if argv[:3] == ["ip", "-6", "neigh"]:
            return self.v6
        if argv[:3] == ["ip", "-4", "neigh"]:
            return self.v4
        if argv[:3] == ["ip", "-6", "route"]:
            return "default via fe80::3a07:16ff:fe77:17d3 dev eth2 proto ra metric 100"
        if argv[:3] == ["ip", "-4", "route"]:
            return "default via 192.168.1.254 dev eth2"
        return ""


def _attend(cond, t=3.0):
    fin = time.time() + t
    while time.time() < fin:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_la_lecture_rend_tout_de_suite_et_le_mdns_arrive_en_arriere_plan():
    f = Faux(lent=0.3)
    g = s.Surveillance(f, ttl_mdns=300)
    debut = time.time()
    r = g.lecture()
    assert time.time() - debut < 0.25
    assert r["mesure"]["mdns_en_cours"] is True and r["appareils"]            # appareils connus sans attendre le mDNS
    assert _attend(lambda: not g._mdns["en_cours"])
    r2 = g.lecture()
    assert r2["mesure"]["mdns_en_cours"] is False
    assert any(a["services"] for a in r2["appareils"])


def test_le_mdns_n_est_pas_relance_dans_le_delai():
    f = Faux()
    g = s.Surveillance(f, ttl_mdns=300)
    g.lecture()
    assert _attend(lambda: not g._mdns["en_cours"])
    for _ in range(4):
        g.lecture()
    assert sum(1 for a in f.appels if a[0] == "avahi-browse") == 1


def test_sans_avahi_la_lecture_fonctionne_quand_meme():
    g = s.Surveillance(Faux(panne=True), ttl_mdns=300)
    g.lecture()
    assert _attend(lambda: not g._mdns["en_cours"])
    r = g.lecture()
    assert r["appareils"] and all(a["services"] == [] for a in r["appareils"])


def test_seules_les_interfaces_du_reseau_local_comptent():
    g = s.Surveillance(Faux(), ttl_mdns=300)
    r = g.lecture()
    assert {a["interface"] for a in r["appareils"]} == {"eth2"}


def test_la_reponse_ne_contient_ni_adresse_mac_complete_ni_secret():
    g = s.Surveillance(Faux(), ttl_mdns=300)
    texte = repr(g.lecture())
    assert "fa:c5:c2:ac:b6:1a" not in texte and "token" not in texte.lower()


def test_le_verdict_est_dans_la_lecture():
    r = s.Surveillance(Faux(), ttl_mdns=300).lecture()
    assert r["verdict"]["niveau"] == "a_verifier" and [e["id"] for e in r["etapes"]][0] == "appareils"


def test_les_accords_singulier_pluriel_sont_corrects():
    un = v.verdict([_appareil()], None)["explication"]
    deux = v.verdict([_appareil(), _appareil()], None)["explication"]
    assert un.startswith("1 appareil a ") and "il pourrait être joignable" in un
    assert deux.startswith("2 appareils ont ") and "ils pourraient être joignables" in deux
