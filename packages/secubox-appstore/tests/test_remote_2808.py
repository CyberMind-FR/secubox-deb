# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2808 — installation a distance : la demande voyage dans la boite OpenPGP (verifiee par le demon), l'admin CIBLE decide.

Rien ne s'installe sur reception : la demande attend, l'admin retape le nom du paquet, secubox-appstorectl garde ses propres gardes."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import remote  # noqa: E402

GK3 = "did:plc:" + "a" * 32
GK2 = "did:plc:" + "b" * 32


class Boite:
    """Boite OpenPGP simulee : lister()/lire() comme les routes /boite et /boite/{id}."""
    def __init__(self):
        self.msgs = {}
        self.lectures = []

    def depose(self, ident, de, objet, contenu, boxname="gk3"):
        self.msgs[ident] = {"id": ident, "de": de, "boxname": boxname, "emis": 1000, "objet": objet, "contenu": contenu}

    def lister(self):
        return [{"id": i, "de": m["de"], "boxname": m["boxname"], "emis": m["emis"]} for i, m in self.msgs.items()]

    def lire(self, ident):
        self.lectures.append(ident)
        return self.msgs[ident]


def demande(paquet="secubox-radio", did="d1" + "0" * 30):
    return json.dumps({"v": 1, "id": did, "paquet": paquet})


@pytest.mark.parametrize("p", ["secubox-radio", "secubox-a.b-c1"])
def test_nom_de_paquet_valide(p):
    assert remote.paquet_valide(p)


@pytest.mark.parametrize("p", ["radio", "secubox-", "secubox-Radio", "secubox-x y", "secubox-x;rm", "secubox-../x", "", None, "secubox-" + "a" * 80])
def test_nom_de_paquet_invalide(p):
    assert not remote.paquet_valide(p)


def test_une_demande_recue_attend_et_n_installe_rien(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(e, b.lister, b.lire)
    r = e.recues()
    assert len(r) == 1 and r[0]["etat"] == "en_attente" and r[0]["paquet"] == "secubox-radio" and r[0]["boxname"] == "gk3" and r[0]["de"] == GK3


def test_un_message_deja_vu_n_est_pas_relu(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(e, b.lister, b.lire)
    remote.synchroniser(e, b.lister, b.lire)
    assert b.lectures == ["m1"] and len(e.recues()) == 1


def test_l_etat_survit_au_redemarrage(tmp_path):
    b = Boite(); b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(remote.Etat(tmp_path / "etat.json"), b.lister, b.lire)
    assert len(remote.Etat(tmp_path / "etat.json").recues()) == 1


def test_un_nom_de_paquet_hostile_est_ecarte(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande("secubox-x;reboot"))
    b.depose("m2", GK3, remote.OBJET_DEMANDE, "pas du json")
    b.depose("m3", GK3, "autre.objet", "bonjour")
    remote.synchroniser(e, b.lister, b.lire)
    assert e.recues() == []


def test_la_file_est_bornee_par_expediteur(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    for i in range(remote.MAX_EN_ATTENTE_PAR_PAIR + 5):
        b.depose(f"m{i:03d}", GK3, remote.OBJET_DEMANDE, demande(did=f"{i:032x}"))
    remote.synchroniser(e, b.lister, b.lire)
    assert len(e.recues()) == remote.MAX_EN_ATTENTE_PAR_PAIR


def test_accepter_exige_de_retaper_le_nom(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(e, b.lister, b.lire)
    appels = []
    with pytest.raises(remote.Refus) as ex:
        remote.decider(e, "m1", True, "secubox-autre", lambda p: appels.append(p) or (True, "ok"), lambda *a: None)
    assert ex.value.statut == 428 and appels == []


def test_accepter_installe_via_le_controleur_puis_repond(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande(did="c" * 32))
    remote.synchroniser(e, b.lister, b.lire)
    installe, reponses = [], []
    r = remote.decider(e, "m1", True, "secubox-radio", lambda p: installe.append(p) or (True, "installé"), lambda *a: reponses.append(a))
    assert installe == ["secubox-radio"] and r["etat"] == "installee"
    pair, objet, contenu = reponses[0]
    assert pair == GK3 and objet == remote.OBJET_REPONSE
    assert json.loads(contenu) == {"v": 1, "id": "c" * 32, "statut": "installee", "message": "installé"}


def test_un_echec_d_installation_est_dit_pas_masque(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(e, b.lister, b.lire)
    r = remote.decider(e, "m1", True, "secubox-radio", lambda p: (False, "paquet absent des dépôts"), lambda *a: None)
    assert r["etat"] == "echec" and "absent" in r["message"]


def test_refuser_ne_lance_aucune_installation_et_previent(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(e, b.lister, b.lire)
    reponses = []
    r = remote.decider(e, "m1", False, None, lambda p: pytest.fail("aucune installation"), lambda *a: reponses.append(a))
    assert r["etat"] == "refusee" and json.loads(reponses[0][2])["statut"] == "refusee"


def test_une_demande_ne_se_decide_qu_une_fois(tmp_path):
    b, e = Boite(), remote.Etat(tmp_path / "etat.json")
    b.depose("m1", GK3, remote.OBJET_DEMANDE, demande())
    remote.synchroniser(e, b.lister, b.lire)
    remote.decider(e, "m1", False, None, lambda p: (True, ""), lambda *a: None)
    with pytest.raises(remote.Refus) as ex:
        remote.decider(e, "m1", True, "secubox-radio", lambda p: (True, ""), lambda *a: None)
    assert ex.value.statut == 409
    with pytest.raises(remote.Refus) as ex:
        remote.decider(e, "inconnue", False, None, lambda p: (True, ""), lambda *a: None)
    assert ex.value.statut == 404


def test_demander_valide_le_paquet_puis_envoie_et_memorise(tmp_path):
    e = remote.Etat(tmp_path / "etat.json")
    envois = []
    r = remote.demander(e, "gk2", "secubox-radio", lambda pair, objet, contenu: envois.append((pair, objet, contenu)) or {"ok": True, "a": GK2, "boxname": "gk2"})
    assert envois[0][0] == "gk2" and envois[0][1] == remote.OBJET_DEMANDE and json.loads(envois[0][2])["paquet"] == "secubox-radio"
    env = e.envoyees()
    assert len(env) == 1 and env[0]["etat"] == "envoyee" and env[0]["a"] == GK2 and env[0]["boxname"] == "gk2" and env[0]["id"] == r["id"]
    with pytest.raises(remote.Refus) as ex:
        remote.demander(e, "gk2", "secubox-x;rm", lambda *a: pytest.fail("pas d'envoi"))
    assert ex.value.statut == 400


def test_la_reponse_met_a_jour_la_demande_envoyee(tmp_path):
    e, b = remote.Etat(tmp_path / "etat.json"), Boite()
    r = remote.demander(e, "gk2", "secubox-radio", lambda *a: {"ok": True, "a": GK2, "boxname": "gk2"})
    b.depose("r1", GK2, remote.OBJET_REPONSE, json.dumps({"v": 1, "id": r["id"], "statut": "installee", "message": "ok"}), "gk2")
    remote.synchroniser(e, b.lister, b.lire)
    assert e.envoyees()[0]["etat"] == "installee" and e.envoyees()[0]["message"] == "ok"


def test_une_reponse_d_un_autre_noeud_est_ignoree(tmp_path):
    """Seule la cible de la demande peut y repondre : un autre pair lie ne peut pas la faire passer pour acceptee."""
    e, b = remote.Etat(tmp_path / "etat.json"), Boite()
    r = remote.demander(e, "gk2", "secubox-radio", lambda *a: {"ok": True, "a": GK2, "boxname": "gk2"})
    b.depose("r1", GK3, remote.OBJET_REPONSE, json.dumps({"v": 1, "id": r["id"], "statut": "installee", "message": "ok"}))
    remote.synchroniser(e, b.lister, b.lire)
    assert e.envoyees()[0]["etat"] == "envoyee"


def test_statut_de_reponse_inconnu_est_ignore(tmp_path):
    e, b = remote.Etat(tmp_path / "etat.json"), Boite()
    r = remote.demander(e, "gk2", "secubox-radio", lambda *a: {"ok": True, "a": GK2, "boxname": "gk2"})
    b.depose("r1", GK2, remote.OBJET_REPONSE, json.dumps({"v": 1, "id": r["id"], "statut": "<script>", "message": "x"}), "gk2")
    remote.synchroniser(e, b.lister, b.lire)
    assert e.envoyees()[0]["etat"] == "envoyee"


def test_le_message_de_reponse_est_borne(tmp_path):
    e, b = remote.Etat(tmp_path / "etat.json"), Boite()
    r = remote.demander(e, "gk2", "secubox-radio", lambda *a: {"ok": True, "a": GK2, "boxname": "gk2"})
    b.depose("r1", GK2, remote.OBJET_REPONSE, json.dumps({"v": 1, "id": r["id"], "statut": "echec", "message": "x" * 5000}), "gk2")
    remote.synchroniser(e, b.lister, b.lire)
    assert len(e.envoyees()[0]["message"]) <= 300
