# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3303 (décision 4 de #3258) : abonnement PAR BOX (formule, échéance, statut), catalogue des formules, prolongation depuis l'échéance,
suspension/révocation d'une seule box avec motif, vue par box avec écart de profil, projection du pilotage suivant la box."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from autoload import jetons as J, projection as P, tunnel as T
from api import main as A

CLE_A, CLE_B = "A" * 43 + "=", "B" * 43 + "="
HUB = "H" * 43 + "="
T0 = 1_800_000_000
JOUR = 86400


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t


class Monde:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.h = Horloge()
        self.audit = tmp_path / "audit.log"
        self.reg = J.Registre(tmp_path / "j.db", self.audit, horloge=self.h)
        self.pairs = T.Pairs(tmp_path / "j.db", horloge=self.h)
        self.syncs = 0
        self.profils = tmp_path / "profils-appliques.json"
        self.app = A.creer_app(self.reg, self.pairs, HUB, self.appliquer, horloge=self.h, profils_appliques=self.profils)
        self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
        self.c = TestClient(self.app)

    def appliquer(self):
        self.syncs += 1

    def box(self, client="atelier-nord", profil="distante", cle=CLE_A, serie=None):
        e = self.reg.emettre(client, profil, serie=serie)
        self.reg.reclamer(e.valeur, cle)
        self.pairs.attribuer(cle)
        return e.id

    def ligne(self, ident):
        return next(x for x in self.c.get("/abonnements").json() if x["id"] == ident)

    def audits(self):
        return [json.loads(x) for x in self.audit.read_text().splitlines()] if self.audit.exists() else []


@pytest.fixture
def m(tmp_path):
    return Monde(tmp_path)


# ── catalogue des formules ───────────────────────────────────────────────────────────────────────────────
def test_formule_creee_puis_listee(m):
    r = m.c.post("/formules", json={"nom": "sans-ecran", "libelle": "Sans écran", "profil": "distante", "mois": 12})
    assert r.status_code == 200
    assert m.c.get("/formules").json() == [{"nom": "sans-ecran", "libelle": "Sans écran", "profil": "distante", "mois": 12}]


@pytest.mark.parametrize("profil", ["light", "standard", "custom", "../x", ""])
def test_formule_refuse_un_profil_inexistant(m, profil):
    assert m.c.post("/formules", json={"nom": "f", "libelle": "F", "profil": profil, "mois": 12}).status_code == 422


def test_formule_mise_a_jour_sans_doublon(m):
    m.c.post("/formules", json={"nom": "leger", "libelle": "Léger", "profil": "lite", "mois": 12})
    m.c.post("/formules", json={"nom": "leger", "libelle": "Léger", "profil": "lite", "mois": 24})
    assert [f["mois"] for f in m.c.get("/formules").json()] == [24]


# ── migration : chaque box hérite de l'abonnement de son client ──────────────────────────────────────────
def test_migration_box_herite_du_client_et_idempotente(tmp_path):
    db = tmp_path / "j.db"
    reg = J.Registre(db, None, horloge=lambda: T0)
    e = reg.emettre("lgm", "lite")
    reg.reclamer(e.valeur, CLE_A)
    reg.fixer_abonnement("lgm", "actif", expire_le=T0 + 30 * JOUR, formule="leger")
    with sqlite3.connect(db) as cx:                                    # base d'avant #3303 : pas de ligne par box
        cx.execute("DELETE FROM abonnements_box")
    for _ in range(2):
        reg = J.Registre(db, None, horloge=lambda: T0)
    with sqlite3.connect(db) as cx:
        lignes = cx.execute("SELECT jeton_id, formule, statut, expire_le FROM abonnements_box").fetchall()
    assert lignes == [(e.id, "leger", "actif", T0 + 30 * JOUR)]


# ── vue par box ──────────────────────────────────────────────────────────────────────────────────────────
def test_vue_par_box_jours_restants_et_profil_inconnu(m):
    m.c.post("/formules", json={"nom": "sans-ecran", "libelle": "Sans écran", "profil": "distante", "mois": 12})
    i = m.box()
    assert m.c.post(f"/boxes/{i}/abonnement/formule", json={"formule": "sans-ecran"}).status_code == 200
    m.c.post(f"/boxes/{i}/abonnement/prolonger", json={"mois": 1})
    x = m.ligne(i)
    assert x["client"] == "atelier-nord" and x["formule"] == "sans-ecran" and x["profil_formule"] == "distante"
    assert x["statut"] == "actif" and 28 <= x["jours_restants"] <= 31
    assert x["profil_applique"] is None and x["ecart"] is False                  # aucun relevé du pilotage : inconnu, jamais un écart inventé


def test_vue_par_box_signale_l_ecart_depuis_le_releve(m):
    m.c.post("/formules", json={"nom": "sans-ecran", "libelle": "Sans écran", "profil": "distante", "mois": 12})
    i = m.box()
    m.c.post(f"/boxes/{i}/abonnement/formule", json={"formule": "sans-ecran"})
    adresse = m.pairs.actifs()[0]["adresse"]
    m.profils.write_text(json.dumps({"version": 1, "boxes": [{"adresse": adresse, "profil": "lite"}]}))
    x = m.ligne(i)
    assert x["profil_applique"] == "lite" and x["ecart"] is True


def test_releve_illisible_ou_hostile_rend_inconnu(m):
    i = m.box()
    m.profils.write_text("{pas du json")
    assert m.ligne(i)["profil_applique"] is None
    m.profils.write_text(json.dumps({"version": 1, "boxes": [{"adresse": m.pairs.actifs()[0]["adresse"], "profil": "<script>"}]}))
    assert m.ligne(i)["profil_applique"] is None


# ── prolongation ─────────────────────────────────────────────────────────────────────────────────────────
def test_prolonger_part_de_l_echeance_en_cours(m):
    i = m.box()
    m.c.post(f"/boxes/{i}/abonnement/prolonger", json={"mois": 1})
    avant = m.ligne(i)["expire_le"]
    r = m.c.post(f"/boxes/{i}/abonnement/prolonger", json={"mois": 12})
    assert r.status_code == 200 and r.json()["expire_le"] == J.ajouter_mois(avant, 12)


def test_prolonger_une_echeance_passee_part_d_aujourd_hui(m):
    i = m.box()
    m.c.post(f"/boxes/{i}/abonnement/prolonger", json={"mois": 1})
    m.h.t += 60 * JOUR
    assert m.ligne(i)["statut"] == "echu"
    r = m.c.post(f"/boxes/{i}/abonnement/prolonger", json={"mois": 1})
    assert r.json()["expire_le"] == J.ajouter_mois(int(m.h.t), 1) and m.ligne(i)["statut"] == "actif"


def test_prolonger_une_box_revoquee_est_refuse(m):
    i = m.box()
    m.c.post(f"/boxes/{i}/abonnement/revoquer", json={"motif": "fin de contrat", "confirmation": str(i)})
    assert m.c.post(f"/boxes/{i}/abonnement/prolonger", json={"mois": 1}).status_code == 409


# ── suspension / reprise / révocation : une seule box ────────────────────────────────────────────────────
def test_suspendre_une_box_laisse_l_autre_box_du_client(m):
    a, b = m.box(cle=CLE_A), m.box(cle=CLE_B)
    syncs = m.syncs
    r = m.c.post(f"/boxes/{a}/abonnement/suspendre", json={"motif": "impayé"})
    assert r.status_code == 200 and m.syncs == syncs + 1
    assert (m.ligne(a)["statut"], m.ligne(b)["statut"]) == ("suspendu", "actif")
    assert m.reg.livraison_autorisee(CLE_A) is False and m.reg.livraison_autorisee(CLE_B) is True
    assert any(x["action"] == "abonnement-box" and "motif=impayé" in x["detail"] for x in m.audits())


@pytest.mark.parametrize("motif", ["", "  ", "x"])
def test_suspendre_exige_un_motif(m, motif):
    i = m.box()
    assert m.c.post(f"/boxes/{i}/abonnement/suspendre", json={"motif": motif}).status_code == 422
    assert m.ligne(i)["statut"] == "actif"


def test_reprendre_une_box_suspendue(m):
    i = m.box()
    m.c.post(f"/boxes/{i}/abonnement/suspendre", json={"motif": "impayé"})
    assert m.c.post(f"/boxes/{i}/abonnement/reprendre", json={}).status_code == 200
    assert m.ligne(i)["statut"] == "actif"


def test_revoquer_une_box_revoque_son_seul_jeton_et_son_pair(m):
    a, b = m.box(cle=CLE_A), m.box(cle=CLE_B)
    r = m.c.post(f"/boxes/{a}/abonnement/revoquer", json={"motif": "fin de contrat", "confirmation": str(a)})
    assert r.status_code == 200
    etats = {j["id"]: j["etat"] for j in m.reg.lister()}
    assert etats == {a: "revoque", b: "reclame"}
    assert [p["cle_pub"] for p in m.pairs.actifs()] == [CLE_B]
    assert m.ligne(a)["statut"] == "revoque"


def test_revoquer_exige_la_confirmation_exacte(m):
    i = m.box(serie="SN-0001")
    assert m.c.post(f"/boxes/{i}/abonnement/revoquer", json={"motif": "fin", "confirmation": "autre"}).status_code == 422
    assert m.c.post(f"/boxes/{i}/abonnement/revoquer", json={"motif": "fin de contrat", "confirmation": "SN-0001"}).status_code == 200


def test_box_inconnue_404(m):
    assert m.c.post("/boxes/999/abonnement/prolonger", json={"mois": 1}).status_code == 404
    assert m.c.post("/boxes/999/abonnement/suspendre", json={"motif": "impayé"}).status_code == 404


def test_formule_inconnue_refusee(m):
    i = m.box()
    assert m.c.post(f"/boxes/{i}/abonnement/formule", json={"formule": "nulle-part"}).status_code == 422


# ── compatibilité de la route par client ─────────────────────────────────────────────────────────────────
def test_route_client_s_applique_a_toutes_ses_box(m):
    a, b = m.box(cle=CLE_A), m.box(cle=CLE_B)
    assert m.c.post("/clients/atelier-nord/abonnement", json={"statut": "suspendu"}).status_code == 200
    assert (m.ligne(a)["statut"], m.ligne(b)["statut"]) == ("suspendu", "suspendu")


def test_nouvelle_box_herite_de_l_abonnement_du_client(m):
    m.c.post("/clients/atelier-nord/abonnement", json={"statut": "actif", "mois": 6, "formule": "leger"})
    i = m.box()
    x = m.ligne(i)
    assert x["formule"] == "leger" and x["expire_le"] == J.ajouter_mois(T0, 6)


# ── projection du pilotage : l'état de la BOX ────────────────────────────────────────────────────────────
def test_projection_suit_l_etat_de_chaque_box(m):
    a = m.box(cle=CLE_A)
    m.box(cle=CLE_B)
    m.reg.suspendre_box(a, "impayé")
    pairs = {p["adresse"]: p["abonnement"] for p in P.lire_pairs(m.tmp / "j.db", maintenant=T0)}
    adr = {p["cle_pub"]: p["adresse"] for p in m.pairs.actifs()}
    assert pairs[adr[CLE_A]] == "suspendu" and pairs[adr[CLE_B]] == "actif"


# ── gardes ───────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("meth,chemin,corps", [("get", "/abonnements", None), ("get", "/formules", None),
                                               ("post", "/formules", {"nom": "f", "libelle": "F", "profil": "lite", "mois": 1}),
                                               ("post", "/boxes/1/abonnement/prolonger", {"mois": 1}),
                                               ("post", "/boxes/1/abonnement/suspendre", {"motif": "impayé"}),
                                               ("post", "/boxes/1/abonnement/reprendre", {}),
                                               ("post", "/boxes/1/abonnement/formule", {"formule": "f"}),
                                               ("post", "/boxes/1/abonnement/revoquer", {"motif": "fin", "confirmation": "1"})])
def test_routes_gardees(tmp_path, meth, chemin, corps):
    reg = J.Registre(tmp_path / "j.db", None)
    app = A.creer_app(reg, T.Pairs(tmp_path / "j.db"), HUB, lambda: None)
    c = TestClient(app)
    r = c.get(chemin) if meth == "get" else c.post(chemin, json=corps)
    assert r.status_code in (401, 403)


# ── relecture indépendante de #3304 ──────────────────────────────────────────────────────────────────────
def test_reprendre_refuse_un_motif_avec_caracteres_de_controle(m):
    i = m.box()
    m.c.post(f"/boxes/{i}/abonnement/suspendre", json={"motif": "impayé"})
    assert m.c.post(f"/boxes/{i}/abonnement/reprendre", json={"motif": "ok\nfaux=1"}).status_code == 422
    assert m.ligne(i)["statut"] == "suspendu"


def test_lecture_des_abonnements_n_ecrit_rien(m):
    i = m.box()
    with sqlite3.connect(m.tmp / "j.db") as cx:
        cx.execute("DELETE FROM abonnements_box")
    m.c.post("/clients/atelier-nord/abonnement", json={"statut": "actif", "mois": 2, "formule": "leger"})
    with sqlite3.connect(m.tmp / "j.db") as cx:
        cx.execute("DELETE FROM abonnements_box")
        avant = cx.total_changes
    x = m.ligne(i)
    assert x["formule"] == "leger" and x["statut"] == "actif"                     # repli sur le client
    with sqlite3.connect(m.tmp / "j.db") as cx:
        assert cx.execute("SELECT COUNT(*) FROM abonnements_box").fetchone()[0] == 0
    assert avant >= 0


def test_route_client_ne_reactive_pas_une_box_suspendue_seule(m):
    a, b = m.box(cle=CLE_A), m.box(cle=CLE_B)
    m.c.post(f"/boxes/{a}/abonnement/suspendre", json={"motif": "impayé"})
    m.c.post("/clients/atelier-nord/abonnement", json={"statut": "actif", "mois": 12})
    assert (m.ligne(a)["statut"], m.ligne(b)["statut"]) == ("suspendu", "actif")
    m.c.post("/clients/atelier-nord/abonnement", json={"statut": "suspendu"})
    m.c.post("/clients/atelier-nord/abonnement", json={"statut": "actif"})
    assert (m.ligne(a)["statut"], m.ligne(b)["statut"]) == ("suspendu", "actif")   # b suspendue PAR le client, reprise par le client
    assert any(x["action"] == "abonnement" and "box=" in x["detail"] for x in m.audits())


def test_revoquer_box_atomique(m, monkeypatch):
    i = m.box()

    def panne(*_a, **_k):
        raise sqlite3.OperationalError("disque plein")
    monkeypatch.setattr(m.reg, "_audit", lambda *a, **k: None)
    monkeypatch.setattr(J.Registre, "_revoquer_jeton", panne)
    with pytest.raises(sqlite3.OperationalError):
        m.reg.revoquer_box(i, "fin de contrat", str(i))
    monkeypatch.undo()
    assert m.ligne(i)["statut"] == "actif" and {j["id"]: j["etat"] for j in m.reg.lister()}[i] == "reclame"


def test_formule_retiree_entre_temps_refusee(m, monkeypatch):
    m.c.post("/formules", json={"nom": "leger", "libelle": "Léger", "profil": "lite", "mois": 12})
    i = m.box()
    reel = J.Registre._box

    def box_puis_retrait(self, cx, ident):
        cx.execute("DELETE FROM formules WHERE nom='leger'")
        return reel(self, cx, ident)
    monkeypatch.setattr(J.Registre, "_box", box_puis_retrait)
    assert m.c.post(f"/boxes/{i}/abonnement/formule", json={"formule": "leger"}).status_code == 422
