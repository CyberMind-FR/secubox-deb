# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import os
import sqlite3
import threading

import pytest

from pilotage.stockage import EVENEMENTS_MAX, LIGNES_MAX, PARAMS_MAX, StockageSqlite
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
    avant = s.inventaire(GK5.cle)
    for corps in ({"results": []}, {"results": "x"}, {}, {"results": [{"path": P, "params": {"Autre.chose": 1}}]}):
        assert s.inventaire_enregistrer(GK5, corps) is False
    assert s.inventaire(GK5.cle) == avant
    # une valeur valide au milieu de chemins invalides est gardée, le relevé est partiel
    assert s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": {"Autre.chose": 1, P + "ok": [1]}}]})
    apres = s.inventaire(GK5.cle)
    assert apres["partiel"] is True and set(apres["valeurs"]) == set(avant["valeurs"]) | {P + "ok"}


def test_source_en_echec_signalee_par_l_agent_est_une_passe_degradee(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5())
    r = releve_gk5()
    for k in [k for k in r["results"][0]["params"] if "X_SECUBOX_Services" in k]:
        del r["results"][0]["params"][k]
    r["results"][0]["params"][P + "DeviceInfo.UpTime"] = 9
    r["results"][0]["failed"] = ["systemd"]
    assert s.inventaire_enregistrer(GK5, r)
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is True and inv["valeurs"][P + "DeviceInfo.UpTime"] == 9
    assert inv["valeurs"][P + "X_SECUBOX_Services.1.Name"] == "secubox-hub.service"
    assert inv["valeurs"][P + "X_SECUBOX_Services.FailedNumberOfEntries"] == 0


def test_err_accompagne_de_params_garde_les_params_en_passe_degradee(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5())
    s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": {P + "DeviceInfo.UpTime": 3}, "err": "source indisponible"}]})
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is True and inv["valeurs"][P + "DeviceInfo.UpTime"] == 3 and P + "X_SECUBOX_Services.1.Name" in inv["valeurs"]


def test_lignes_d_inventaire_plafonnees_par_box(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    s.vu(GK2, {})
    s.inventaire_enregistrer(GK2, releve_gk5())
    for i in range(3):  # trois passes dégradées aux chemins tous différents
        h.avance(1)
        params = {f"{P}X.{i}.{j}": j for j in range(PARAMS_MAX)}
        assert s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": params}], "tronque": True})
    assert len(s.inventaire(GK5.cle)["valeurs"]) <= LIGNES_MAX == 2 * PARAMS_MAX
    # on garde les plus récentes
    assert f"{P}X.2.0" in s.inventaire(GK5.cle)["valeurs"] and f"{P}X.0.0" not in s.inventaire(GK5.cle)["valeurs"]
    assert len(s.inventaire(GK2.cle)["valeurs"]) == len(releve_gk5()["results"][0]["params"])  # l'autre box n'est pas touchée


def test_evenements_plafonnes_par_box(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.vu(GK2, {})
    s.notification(GK2, {"type": "X_SECUBOX_Boot", "value": 1, "ts": 1})
    for i in range(20000):
        s.notification(GK5, {"type": "X_SECUBOX_MemoryLow", "value": i, "ts": 1})
    ev = s.evenements(cle=GK5.cle, limite=1000)
    assert ev[0]["valeur"] == 19999   # les plus récents survivent
    with s._cx() as cx:
        assert cx.execute("SELECT COUNT(*) FROM evenements WHERE cle=?", (GK5.cle,)).fetchone()[0] <= EVENEMENTS_MAX == 5000
    assert len(s.evenements(cle=GK2.cle)) == 1


def test_mains_liees_vrai_faux_et_inconnu(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.vu(GK2, {})
    s.inventaire_enregistrer(GK5, releve_gk5(mains=True))
    s.inventaire_enregistrer(GK2, releve_gk5(mains=False))
    par = {r["nom"]: r for r in s.resumes()}
    assert par["gk5"]["mains_liees"] is True and par["gk2"]["mains_liees"] is False
    s.inventaire_enregistrer(GK2, releve_gk5())  # complet, sans la clé : inconnu
    assert {r["nom"]: r for r in s.resumes()}["gk2"]["mains_liees"] is None
    assert "mains_liees" not in {c[1] for c in sqlite3.connect(tmp_path / "pilotage" / "pilotage.db").execute("PRAGMA table_info(boites)")}


def test_cpu_arrondi_a_une_decimale(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5(cpu=12.3456789))
    assert s.resumes()[0]["cpu_pct"] == 12.3


def test_sortie_de_releve_illisible(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    s.releve_enregistrer(GK5.cle, 60, "ok", {"x": float("nan")})
    r = s.releve_lire(GK5.cle)
    assert r["statut"] == "erreur" and r["sortie"] == {"err": "sortie illisible"}


def test_base_existante_ramenee_a_0640_et_lien_refuse(tmp_path):
    d = tmp_path / "pilotage"
    d.mkdir()
    (d / "pilotage.db").touch()
    os.chmod(d / "pilotage.db", 0o666)
    StockageSqlite(d)
    assert (os.stat(d / "pilotage.db").st_mode & 0o777) == 0o640
    autre = tmp_path / "autre"
    autre.mkdir()
    (autre / "cible").write_text("x")
    os.symlink(autre / "cible", autre / "pilotage.db")
    with pytest.raises(OSError):
        StockageSqlite(autre)


def test_resume_gk5(tmp_path):
    s, h = neuf(tmp_path)
    s.vu(GK5, {"agent_version": "0.1.0"})
    s.inventaire_enregistrer(GK5, releve_gk5(mains=False))
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
    assert r["mains_liees"] is None and r["boucles_24h"] == 0
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
