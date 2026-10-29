# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import os
import sqlite3
import threading

from pilotage.stockage import StockageSqlite
from outils import GK2, GK5, GK5_AUTOLOAD, Horloge, P, releve_gk5

JOUR = 86400


def neuf(tmp_path, h=None):
    h = h or Horloge()
    return StockageSqlite(tmp_path / "pilotage", horloge=h), h


def test_base_creee_en_0640_avec_wal(tmp_path):
    s, _ = neuf(tmp_path)
    db = tmp_path / "pilotage" / "pilotage.db"
    assert (os.stat(db).st_mode & 0o777) == 0o640
    assert sqlite3.connect(db).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    tables = {r[0] for r in sqlite3.connect(db).execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"boites", "inventaire", "evenements"} <= tables


def test_vu_enregistre_la_box_par_cle(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {"agent_version": "0.1.0", "boot_id": "b", "modele": []})
    s.vu(GK5_AUTOLOAD, {})
    assert len(s.boites()) == 2  # même nom, deux réseaux : deux lignes
    b = s.boite(GK5.cle)
    assert b["nom"] == "gk5" and b["reseau"] == "maillage" and b["vu_le"] == int(h.t) and b["agent_version"] == "0.1.0"
    h.avance(10)
    s.vu(GK5, {})  # un sondage n'efface pas la version
    b = s.boite(GK5.cle)
    assert b["agent_version"] == "0.1.0" and b["vu_le"] == int(h.t)


def test_inventaire_complet_remplace_et_efface_les_absents(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    assert s.inventaire_enregistrer(GK5, releve_gk5())
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is False and inv["valeurs"][P + "X_SECUBOX_Services.1.Name"] == "secubox-hub.service"
    r = releve_gk5()
    del r["results"][0]["params"][P + "X_SECUBOX_Services.1.Name"]
    s.inventaire_enregistrer(GK5, r)
    assert P + "X_SECUBOX_Services.1.Name" not in s.inventaire(GK5.cle)["valeurs"]


def test_releve_degrade_n_ecrase_jamais_un_releve_complet(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5(swap_used=660))
    # tronqué : seulement une partie, valeur modifiée ; le reste doit survivre, l'inventaire est marqué partiel
    s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": {P + "DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed": 700}}], "tronque": True})
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is True
    assert inv["valeurs"][P + "DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed"] == 700
    assert P + "X_SECUBOX_Services.1.Name" in inv["valeurs"]
    # un résultat en erreur : même règle
    s.inventaire_enregistrer(GK5, {"results": [{"path": P + "A.", "params": {}, "err": "boom"},
                                               {"path": P, "params": {P + "DeviceInfo.UpTime": 5}}]})
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is True and P + "X_SECUBOX_Services.1.Name" in inv["valeurs"]
    # un relevé complet suivant rétablit
    s.inventaire_enregistrer(GK5, releve_gk5())
    assert s.inventaire(GK5.cle)["partiel"] is False


def test_reponse_vide_ou_mal_formee_n_efface_rien(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5())
    n = len(s.inventaire(GK5.cle)["valeurs"])
    for corps in ({"results": []}, {"results": "x"}, {}, {"results": [{"path": P, "params": {"Autre.chose": 1, P + "ok": [1], 5: 2}}]}):
        s.inventaire_enregistrer(GK5, corps)
    assert len(s.inventaire(GK5.cle)["valeurs"]) >= n  # seul P+"ok" est ajouté


def test_resume_gk5(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {"agent_version": "0.1.0"})
    s.inventaire_enregistrer(GK5, releve_gk5())
    (r,) = s.resumes()
    assert r["cle"] == GK5.cle and r["nom"] == "gk5" and r["en_ligne"] is True
    assert r["memoire_dispo_mo"] == 512 and r["swap_utilise_pct"] == 66 and r["cpu_pct"] == 12
    assert r["services_en_echec"] == 0 and r["mains_liees"] is False and r["boucles_24h"] == 0


def test_resume_valeurs_absentes_sont_null(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK2, {})
    (r,) = s.resumes()
    for k in ("memoire_dispo_mo", "swap_utilise_pct", "cpu_pct", "services_en_echec"):
        assert r[k] is None
    assert r["mains_liees"] is False and r["boucles_24h"] == 0
    # pas de swap du tout : pourcentage inconnu, pas 0
    s.inventaire_enregistrer(GK2, releve_gk5(swap_total=0, swap_used=0))
    assert s.resumes()[0]["swap_utilise_pct"] is None


def test_hors_ligne_apres_90_s(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    h.avance(89)
    assert s.resumes()[0]["en_ligne"] is True
    h.avance(2)  # 91 s
    assert s.resumes()[0]["en_ligne"] is False
    assert [b["cle"] for b in s.boites_vues_depuis(90)] == []


def test_notifications_et_boucles_24h(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    s.notification(GK5, {"type": "X_SECUBOX_ServiceLoop", "unit": "a.service", "value": 7, "ts": int(h.t)})
    s.notification(GK5, {"type": "X_SECUBOX_MemoryLow", "value": 40, "ts": int(h.t)})
    h.avance(JOUR - 10)
    s.notification(GK5, {"type": "X_SECUBOX_ServiceLoop", "unit": "b.service", "value": 5, "ts": int(h.t)})
    assert s.resumes()[0]["boucles_24h"] == 2
    h.avance(20)  # la première boucle a plus de 24 h
    assert s.resumes()[0]["boucles_24h"] == 1
    ev = s.evenements(cle=GK5.cle)
    assert {e["type"] for e in ev} == {"X_SECUBOX_ServiceLoop", "X_SECUBOX_MemoryLow"}
    assert [e["unite"] for e in s.evenements(cle=GK5.cle, depuis=int(h.t) - 60)] == ["b.service"]
    assert s.evenements(cle=GK2.cle) == []


def test_evenements_purges_apres_30_jours(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    s.notification(GK5, {"type": "X_SECUBOX_Boot", "value": 3, "ts": int(h.t)})
    h.avance(30 * JOUR - 5)
    s.notification(GK5, {"type": "X_SECUBOX_MemoryLow", "value": 9, "ts": int(h.t)})
    assert s.purger() == 0
    h.avance(10)
    assert s.purger() == 1
    assert [e["type"] for e in s.evenements()] == ["X_SECUBOX_MemoryLow"]


def test_ecritures_concurrentes_sans_verrou(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    erreurs = []

    def tache(i):
        try:
            for j in range(20):
                s.notification(GK5, {"type": "X_SECUBOX_Boot", "value": j, "ts": 1})
                s.inventaire_enregistrer(GK5, releve_gk5(swap_used=j))
                s.resumes()
        except Exception as e:  # noqa: BLE001
            erreurs.append(e)

    ts = [threading.Thread(target=tache, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not erreurs and len(s.evenements(limite=1000)) == 80


def test_releve_stocke_et_relu(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    assert s.releve_lire(GK5.cle) is None
    s.releve_enregistrer(GK5.cle, 60, "ok", {"processus": [{"comm": "x"}]})
    r = s.releve_lire(GK5.cle)
    assert r["statut"] == "ok" and r["duree_s"] == 60 and r["sortie"] == {"processus": [{"comm": "x"}]} and r["recu_le"] == int(h.t)
