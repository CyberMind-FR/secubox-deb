# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2190 : service d'enrôlement et panel — jeton comme preuve, refus uniforme, reprise, limite d'essais, identité par le tunnel, gardes d'administration."""
import json

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from autoload import jetons as J, tunnel as T
from api import main as A

CLE_A, CLE_B = "A" * 43 + "=", "B" * 43 + "="
HUB = "H" * 43 + "="
T0 = 1_800_000_000
P = "/api/v1/autoload"


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t


class Monde:
    def __init__(self, tmp_path):
        self.h = Horloge()
        self.reg = J.Registre(tmp_path / "j.db", tmp_path / "audit.log", horloge=self.h)
        self.pairs = T.Pairs(tmp_path / "j.db", horloge=self.h)
        self.syncs, self.echec_sync = 0, False
        self.app = A.creer_app(self.reg, self.pairs, HUB, self.appliquer, horloge=self.h)
        self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
        self.app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "admin"}
        self.c = TestClient(self.app)
        self.app_tunnel = A.creer_app(self.reg, self.pairs, HUB, self.appliquer, horloge=self.h, portee="tunnel")

    def tunnel(self, ip="10.64.0.2"):
        """Un client qui arrive PAR le tunnel : son adresse source est celle de WireGuard."""
        return TestClient(self.app_tunnel, client=(ip, 51000))

    def appliquer(self):
        if self.echec_sync:
            raise T.TunnelErreur("wg indisponible")
        self.syncs += 1


@pytest.fixture
def m(tmp_path):
    return Monde(tmp_path)


def enrol(m, valeur=None, cle=CLE_A, ip="203.0.113.5", **extra):
    corps = {"cle_pub": cle, **extra}
    if valeur is not None:
        corps["jeton"] = valeur
    return m.c.post(P + "/enrol", json=corps, headers={"X-Forwarded-For": ip + ", 127.0.0.1"})


# ── enrôlement ───────────────────────────────────────────────────────────────────────────────────────────
def test_enrolement_rend_le_tunnel_et_ajoute_le_pair(m):
    e = m.reg.emettre("client-042", "lite", lot="lot-1")
    r = enrol(m, e.valeur)
    assert r.status_code == 200
    j = r.json()
    assert (j["client"], j["profil"], j["lot"]) == ("client-042", "lite", "lot-1")
    assert j["tunnel"] == T.gabarit_box("10.64.0.2", HUB) and m.syncs == 1
    assert [p["cle_pub"] for p in m.pairs.actifs()] == [CLE_A]


def test_refus_uniforme_et_sans_detail(m):
    e1, e2 = m.reg.emettre("c1", "lite"), m.reg.emettre("c2", "lite", duree_s=1)
    m.reg.reclamer(e1.valeur, CLE_B)
    m.h.t += 10
    corps = set()
    for v in (e1.valeur, e2.valeur, "gk2_" + "0" * 32, "n'importe quoi"):
        r = enrol(m, v, ip="203.0.113.9" if v != "n'importe quoi" else "203.0.113.10")
        assert r.status_code == 403
        corps.add(r.text)
    assert corps == {json.dumps({"detail": "jeton refusé"})} or len(corps) == 1


def test_une_reponse_perdue_se_rattrape_avec_la_meme_cle(m):
    e = m.reg.emettre("c1", "lite")
    m.echec_sync = True
    assert enrol(m, e.valeur).status_code == 503                         # le jeton est consommé, le pair pas encore appliqué
    m.echec_sync = False
    r = enrol(m, e.valeur)
    assert r.status_code == 200 and r.json()["tunnel"]["adresse"] == "10.64.0.2/32"
    assert enrol(m, e.valeur, cle=CLE_B).status_code == 403              # une autre clé n'a jamais le droit


def test_enrolement_par_numero_de_serie(m):
    m.reg.preenregistrer("SBX-0001-AB", "client-042", "isp")
    r = m.c.post(P + "/enrol", json={"serie": "SBX-0001-AB", "cle_pub": CLE_A}, headers={"X-Forwarded-For": "203.0.113.5, 127.0.0.1"})
    assert r.status_code == 200 and r.json()["profil"] == "isp"
    assert m.c.post(P + "/enrol", json={"serie": "SBX-0001-AB", "cle_pub": CLE_B}).status_code == 403


def test_les_essais_sont_limites_par_adresse_source(m):
    for _ in range(10):
        assert enrol(m, "gk2_" + "1" * 32, ip="198.18.0.7").status_code == 403
    assert enrol(m, "gk2_" + "1" * 32, ip="198.18.0.7").status_code == 429
    e = m.reg.emettre("c1", "lite")
    assert enrol(m, e.valeur, ip="198.18.0.7").status_code == 429       # même le bon jeton, pendant le blocage
    assert enrol(m, e.valeur, ip="198.18.0.8").status_code == 200       # une autre source n'est pas touchée
    m.h.t += 601
    assert enrol(m, "gk2_" + "2" * 32, ip="198.18.0.7").status_code == 403    # la fenêtre a expiré


@pytest.mark.parametrize("corps", [{}, {"cle_pub": CLE_A}, {"jeton": "x", "serie": "y" * 8, "cle_pub": CLE_A}, {"jeton": "gk2_" + "0" * 32},
                                   {"jeton": "gk2_" + "0" * 32, "cle_pub": CLE_A, "extra": 1}, {"jeton": "a" * 500, "cle_pub": CLE_A}])
def test_corps_invalide_refuse(m, corps):
    assert m.c.post(P + "/enrol", json=corps).status_code == 422


def test_corps_trop_gros_refuse(m):
    r = m.c.post(P + "/enrol", content=b"{" + b" " * 200000 + b"}", headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_sante_publique_sans_secret(m):
    r = m.c.get(P + "/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


# ── gardes d'administration ──────────────────────────────────────────────────────────────────────────────
def test_les_routes_d_ecriture_exigent_un_administrateur(tmp_path):
    m = Monde(tmp_path)
    m.app.dependency_overrides.clear()                                    # plus de contournement : le vrai garde répond
    e = m.reg.emettre("c1", "lite")
    for methode, chemin, corps in [("post", "/jetons", {"client": "c1", "profil": "lite"}), ("post", f"/jetons/{e.id}/revoquer", {"motif": "x"}),
                                   ("post", "/clients/c1/abonnement", {"statut": "actif"}), ("post", "/series", {"serie": "SBX-0001", "client": "c1", "profil": "lite"}),
                                   ("post", "/prerapports/" + "0" * 64 + "/refuser", {"motif": "x"})]:
        r = getattr(m.c, methode)(P + chemin, json=corps)
        assert r.status_code in (401, 403), (chemin, r.status_code)


def test_emission_montre_la_valeur_une_fois_et_la_liste_jamais(m):
    r = m.c.post(P + "/jetons", json={"client": "client-042", "profil": "lite", "lot": "lot-1", "duree_jours": 30})
    assert r.status_code == 200
    j = r.json()
    assert j["valeur"].startswith("gk2_") and j["expire_le"] == T0 + 30 * 86400
    liste = m.c.get(P + "/jetons").text
    assert j["valeur"] not in liste and "empreinte" not in liste
    assert "gk2_" not in m.c.get(P + "/boxes").text


def test_emission_hors_bornes_refusee(m):
    for corps in ({"client": "Mal Forme", "profil": "lite"}, {"client": "c1", "profil": "lite", "duree_jours": 0}, {"client": "c1", "profil": "lite", "duree_jours": 9999}):
        assert m.c.post(P + "/jetons", json=corps).status_code in (400, 422)


def test_revocation_retire_le_pair_et_applique(m):
    e = m.reg.emettre("c1", "lite")
    enrol(m, e.valeur)
    n = m.syncs
    r = m.c.post(P + f"/jetons/{e.id}/revoquer", json={"motif": "box volée"})
    assert r.status_code == 200 and r.json()["tunnel_applique"] is True and m.syncs == n + 1
    assert m.pairs.actifs() == [] and m.c.get(P + "/boxes").json()[0]["statut"] == "révoqué"
    assert m.c.post(P + "/jetons/999/revoquer", json={"motif": "x"}).status_code == 404


def test_revocation_d_un_lot_retire_les_pairs_reclames(m):
    e1, e2 = m.reg.emettre("c1", "lite", lot="lot-1"), m.reg.emettre("c2", "lite", lot="lot-1")
    enrol(m, e1.valeur, cle=CLE_A)
    n = m.syncs
    r = m.c.post(P + "/lots/lot-1/revoquer", json={"motif": "lot défectueux"})
    assert r.status_code == 200 and r.json() == {"revoque": True, "pairs_retires": 1, "tunnel_applique": True} and m.syncs == n + 1
    assert m.pairs.actifs() == [] and {b["statut"] for b in m.c.get(P + "/boxes").json()} == {"révoqué"}
    assert enrol(m, e2.valeur, cle=CLE_B).status_code == 403                    # le jeton non réclamé du lot est révoqué aussi
    assert m.c.post(P + "/lots/Mal Forme/revoquer", json={"motif": "x"}).status_code in (404, 422)


def test_abonnement_avec_duree_et_formule(m):
    e = m.reg.emettre("c1", "lite")
    enrol(m, e.valeur)
    r = m.c.post(P + "/clients/c1/abonnement", json={"statut": "actif", "mois": 12, "formule": "pme_12m"})
    assert r.status_code == 200
    ligne = m.c.get(P + "/jetons").json()[0]
    assert ligne["formule"] == "pme_12m" and ligne["abonnement_expire_le"] > T0 + 360 * 86400
    m.c.post(P + "/clients/c1/abonnement", json={"statut": "suspendu"})
    assert m.reg.livraison_autorisee(CLE_A) is False
    assert m.c.post(P + "/clients/c1/abonnement", json={"statut": "inconnu"}).status_code in (400, 422)


# ── identité par le tunnel ───────────────────────────────────────────────────────────────────────────────
def box_enrolee(m):
    enrol(m, m.reg.emettre("c1", "lite").valeur)
    return m.tunnel("10.64.0.2")


def test_les_routes_de_box_n_existent_pas_dans_l_application_publique(m):
    box_enrolee(m)
    for chemin in ("/progression", "/prerapport"):
        assert m.c.post(P + chemin, json={}, headers={"X-Tunnel-Peer": "10.64.0.2"}).status_code in (404, 405)    # un en-tête forgé n'ouvre rien
    assert m.c.get(P + f"/prerapport/{'0' * 64}/refus", headers={"X-Tunnel-Peer": "10.64.0.2"}).status_code == 404
    assert m.tunnel().post(P + "/enrol", json={"jeton": "gk2_" + "0" * 32, "cle_pub": CLE_A}).status_code in (404, 405)      # ni l'inverse
    assert m.tunnel().get(P + "/boxes").status_code == 404


def test_sans_identite_de_tunnel_valide_aucune_route_de_box(m):
    box_enrolee(m)
    for ip in ("203.0.113.5", "10.64.0.9", "10.64.0.1", "192.168.1.5", "127.0.0.1"):
        r = m.tunnel(ip).post(P + "/progression", json={"etape": "plan", "faites": 1, "total": 8})
        assert r.status_code == 401, ip


def test_une_adresse_de_tunnel_retiree_n_a_plus_la_main(m):
    t = box_enrolee(m)
    m.pairs.retirer(CLE_A)
    assert t.post(P + "/progression", json={"etape": "plan", "faites": 1, "total": 8}).status_code == 401


def test_progression_remontee_par_la_box(m):
    t = box_enrolee(m)
    assert t.post(P + "/progression", json={"etape": "installation", "faites": 6, "total": 8}).status_code == 200
    b = m.c.get(P + "/boxes").json()[0]
    assert (b["statut"], b["progression"], b["etape"]) == ("en cours", 75, "installation")
    assert t.post(P + "/progression", json={"etape": "x", "faites": 9, "total": 8}).status_code == 422


def test_pre_rapport_recu_consulte_et_refuse_puis_sonde_par_la_box(m):
    from autoload_agent import moteur as M, validation as VA
    t = box_enrolee(m)
    pre = VA.construire(M.Plan("lite", "auto", ["secubox-core"]), {"box": {"nom": "c1"}, "provision": {"jeton": "ref:/etc/secubox/secrets/x"}}, T0)
    corps = {**pre, "empreinte": VA.empreinte(pre)}
    assert t.post(P + "/prerapport", json=corps).status_code == 200
    assert t.get(P + f"/prerapport/{corps['empreinte']}/refus").json() == {"refuse": False}
    assert m.c.get(P + "/prerapports").json()[0]["client"] == "c1"
    assert m.c.get(P + f"/prerapports/{corps['empreinte']}").json()["profil"] == "lite"
    assert m.c.post(P + f"/prerapports/{corps['empreinte']}/refuser", json={"motif": "profil inattendu"}).status_code == 200
    assert t.get(P + f"/prerapport/{corps['empreinte']}/refus").json() == {"refuse": True}
    falsifie = {**corps, "paquets": ["evil"]}
    assert t.post(P + "/prerapport", json=falsifie).status_code == 422
    assert m.c.post(P + f"/prerapports/{'0' * 64}/refuser", json={"motif": "x"}).status_code == 404


def test_un_refus_n_est_consultable_que_pour_les_pre_rapports_de_sa_propre_box(m):
    from autoload_agent import moteur as M, validation as VA
    t = box_enrolee(m)
    autre = m.reg.emettre("c2", "lite")
    m.reg.reclamer(autre.valeur, CLE_B)
    pre = VA.construire(M.Plan("lite", "auto", ["secubox-core"]), {"box": {"nom": "c2"}}, T0)
    emp = VA.empreinte(pre)
    m.reg.recevoir_prerapport(CLE_B, {**pre, "empreinte": emp})
    m.reg.refuser_prerapport(emp, "x")
    assert t.get(P + f"/prerapport/{emp}/refus").json() == {"refuse": False}     # c1 ne voit pas le refus du pré-rapport de c2
