# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import json
import os
import sqlite3
import threading

import pytest

from pilotage.identite import Box
from pilotage.stockage import EVENEMENTS_MAX, LIGNES_MAX, PARAMS_MAX, VALEUR_MAX, StockageSqlite
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
    # R38 : un paramètre refusé (chemin hors Device., valeur NaN) ne rend plus la relève partielle s'il est seul en cause :
    # la passe est complète, elle remplace l'inventaire ; le paramètre refusé n'y entre simplement pas
    assert s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": {"Autre.chose": 1, P + "nan": float("nan"), P + "ok": [1]}}]})
    apres = s.inventaire(GK5.cle)
    assert apres["partiel"] is False and set(apres["valeurs"]) == {P + "ok"}


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


NOMS = P + "X_SECUBOX_Exposure.Names"


def _releve_avec(**params):
    r = releve_gk5()
    r["results"][0]["params"].update(params)
    return r


def test_exposure_names_de_200_noms_rangee_et_releve_complet(tmp_path):
    """I4/R38 : ~200 server_name (plus de 4 096 caractères) ne rendent plus chaque relève partielle à jamais ; les entrées {i}
    disparues sont purgées et inventaire_le avance."""
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    noms = [f"service-{i:03d}.client-exemple.secubox.in" for i in range(200)]
    assert len(json.dumps(noms)) > 4096
    s.inventaire_enregistrer(GK5, _releve_avec(**{P + "X_SECUBOX_Services.2.Name": "fantome.service", NOMS: noms}))
    h.avance(60)
    assert s.inventaire_enregistrer(GK5, _releve_avec(**{NOMS: noms}))
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is False and inv["releve_le"] == int(h.t) and inv["tronques"] == []
    assert inv["valeurs"][NOMS] == noms
    assert P + "X_SECUBOX_Services.2.Name" not in inv["valeurs"]


def test_valeur_au_dela_de_64_kio_tronquee_avec_marque_jamais_jetee(tmp_path):
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    assert VALEUR_MAX == 64 << 10
    noms = [f"n{i:05d}.exemple.secubox.in" for i in range(5000)]          # ~150 Kio de JSON
    texte = "é" * (100 << 10)
    assert s.inventaire_enregistrer(GK5, _releve_avec(**{NOMS: noms, P + "Long": texte, P + "Objet": {f"k{i}": "v" * 50 for i in range(3000)}}))
    inv = s.inventaire(GK5.cle)
    assert inv["partiel"] is False                                           # tronquée, pas rejetée : la passe reste complète
    assert inv["tronques"] == sorted([NOMS, P + "Long", P + "Objet"])
    garde = inv["valeurs"][NOMS]
    assert isinstance(garde, list) and 0 < len(garde) < len(noms) and garde == noms[:len(garde)]
    assert len(json.dumps(garde, ensure_ascii=False)) <= VALEUR_MAX < len(json.dumps(garde + [noms[len(garde)]], ensure_ascii=False))
    assert isinstance(inv["valeurs"][P + "Long"], str) and texte.startswith(inv["valeurs"][P + "Long"])
    assert len(json.dumps(inv["valeurs"][P + "Long"], ensure_ascii=False)) <= VALEUR_MAX
    assert isinstance(inv["valeurs"][P + "Objet"], dict) and 0 < len(inv["valeurs"][P + "Objet"]) < 3000
    # la valeur redevient courte : la marque tombe
    s.inventaire_enregistrer(GK5, _releve_avec(**{NOMS: noms[:3], P + "Long": "court", P + "Objet": {}}))
    inv = s.inventaire(GK5.cle)
    assert inv["tronques"] == [] and inv["valeurs"][NOMS] == noms[:3]


def _compteur_d_ecritures(tmp_path):
    db = sqlite3.connect(tmp_path / "pilotage" / "pilotage.db")
    db.executescript("""
        CREATE TABLE compte(n INTEGER); INSERT INTO compte VALUES(0);
        CREATE TRIGGER c_ins AFTER INSERT ON inventaire BEGIN UPDATE compte SET n=n+1; END;
        CREATE TRIGGER c_maj AFTER UPDATE ON inventaire BEGIN UPDATE compte SET n=n+1; END;
        CREATE TRIGGER c_sup AFTER DELETE ON inventaire BEGIN UPDATE compte SET n=n+1; END;""")
    db.commit()

    def lire():
        return db.execute("SELECT n FROM compte").fetchone()[0]

    def zero():
        db.execute("UPDATE compte SET n=0")
        db.commit()
    return lire, zero


def test_releve_identique_n_ecrit_aucune_ligne_d_inventaire(tmp_path):
    """M4 : l'inventaire n'écrit que les lignes changées (plus de DELETE puis réinsertion complète à chaque relève)."""
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5(swap_used=660))
    lire, zero = _compteur_d_ecritures(tmp_path)
    zero()
    h.avance(60)
    assert s.inventaire_enregistrer(GK5, releve_gk5(swap_used=660))
    assert lire() == 0
    assert s.inventaire(GK5.cle)["releve_le"] == int(h.t)                  # la relève complète est datée quand même
    h.avance(60)
    s.inventaire_enregistrer(GK5, releve_gk5(swap_used=700))                # une valeur change : une ligne écrite
    assert lire() == 1 and s.inventaire(GK5.cle)["valeurs"][P + "DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed"] == 700
    zero()
    r = releve_gk5(swap_used=700)
    del r["results"][0]["params"][P + "X_SECUBOX_Services.1.Name"]          # un chemin disparu : une suppression
    s.inventaire_enregistrer(GK5, r)
    assert lire() == 1


def test_plafond_de_lignes_garde_la_passe_courante(tmp_path):
    """Les lignes non modifiées ne sont plus redatées : au-delà du plafond, ce qui vient d'être reçu n'est jamais purgé."""
    s, h = neuf(tmp_path, None)
    s.lignes_max = 10
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": {f"{P}Stable.{j}": j for j in range(5)}}]})
    for i in range(4):  # passes dégradées : les 5 valeurs stables, inchangées, et 3 chemins neufs à chaque fois
        h.avance(60)
        params = {f"{P}Stable.{j}": j for j in range(5)}
        params.update({f"{P}Neuf.{i}.{j}": j for j in range(3)})
        s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": params}], "tronque": True})
    v = s.inventaire(GK5.cle)["valeurs"]
    assert len(v) <= 10 and all(f"{P}Stable.{j}" in v for j in range(5)) and all(f"{P}Neuf.3.{j}" in v for j in range(3))


def test_base_d_avant_r38_gagne_la_colonne_tronque(tmp_path):
    d = tmp_path / "pilotage"
    d.mkdir()
    ancienne = sqlite3.connect(d / "pilotage.db")
    ancienne.executescript("CREATE TABLE inventaire(cle TEXT NOT NULL, chemin TEXT NOT NULL, valeur_json TEXT NOT NULL, "
                           "releve_le INTEGER NOT NULL, PRIMARY KEY(cle, chemin));"
                           "INSERT INTO inventaire VALUES('maillage:gk5','Device.X','1',1);")
    ancienne.close()
    s, _ = neuf(tmp_path)
    assert s.inventaire(GK5.cle)["valeurs"] == {"Device.X": 1} and s.inventaire(GK5.cle)["tronques"] == []
    s.vu(GK5, {})
    assert s.inventaire_enregistrer(GK5, releve_gk5())


def _somme_octets(tmp_path, cle):
    cx = sqlite3.connect(tmp_path / "pilotage" / "pilotage.db")
    try:
        return cx.execute("SELECT COALESCE(SUM(length(CAST(valeur_json AS BLOB))),0) FROM inventaire WHERE cle=?", (cle,)).fetchone()[0]
    finally:
        cx.close()


def _passe_degradee(s, h, box, tag, n=4, taille=60000):
    h.avance(60)
    params = {f"{P}Gros.{tag}.{j}": "x" * taille for j in range(n)}
    s.inventaire_enregistrer(box, {"results": [{"path": P, "params": params}], "tronque": True})
    return params


def test_octets_par_box_plafonnes(tmp_path):
    """R39 : l'inventaire d'une box est plafonné en octets ; les plus anciennes lignes absentes de la passe courante partent."""
    s, h = neuf(tmp_path)
    s.octets_max = 300_000
    s.vu(GK5, {})
    for i in range(10):
        _passe_degradee(s, h, GK5, i)
        assert _somme_octets(tmp_path, GK5.cle) <= s.octets_max
        v = s.inventaire(GK5.cle)["valeurs"]
        assert all(f"{P}Gros.{i}.{j}" in v for j in range(4))
    assert not any(k.startswith(f"{P}Gros.0.") for k in v)


def test_octets_passe_courante_jamais_purgee(tmp_path):
    s, h = neuf(tmp_path)
    s.octets_max = 300_000
    s.vu(GK5, {})
    _passe_degradee(s, h, GK5, "a", n=3)
    _passe_degradee(s, h, GK5, "b", n=4)  # 240 Kio seuls : approche le plafond, les anciennes partent
    v = s.inventaire(GK5.cle)["valeurs"]
    assert all(f"{P}Gros.b.{j}" in v for j in range(4)) and not any(".a." in k for k in v)
    h.avance(60)  # passe à elle seule au-dessus du plafond : elle reste entière
    gros = {f"{P}Gros.c.{j}": "y" * 60000 for j in range(6)}
    s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": gros}], "tronque": True})
    v = s.inventaire(GK5.cle)["valeurs"]
    assert all(k in v for k in gros) and not any(".b." in k for k in v)


def test_octets_autre_box_intacte(tmp_path):
    s, h = neuf(tmp_path)
    s.octets_max = 300_000
    s.vu(GK5, {})
    s.vu(GK5_AUTOLOAD, {})
    _passe_degradee(s, h, GK5_AUTOLOAD, "z", n=4)
    avant = s.inventaire(GK5_AUTOLOAD.cle)["valeurs"]
    for i in range(6):
        _passe_degradee(s, h, GK5, i)
    assert s.inventaire(GK5_AUTOLOAD.cle)["valeurs"] == avant


def test_tri_temporaire_en_memoire_m15(tmp_path):
    """M15 : SQLite sous AppArmor n'a pas accès à /tmp ; ses fichiers temporaires (tri, index transitoire) restent en mémoire."""
    s, _ = neuf(tmp_path)
    with s._cx() as cx:
        assert cx.execute("PRAGMA temp_store").fetchone()[0] == 2   # 2 = MEMORY
    with s._tx() as cx:
        assert cx.execute("PRAGMA temp_store").fetchone()[0] == 2


def _somme_vrais_octets(tmp_path, cle):
    cx = sqlite3.connect(tmp_path / "pilotage" / "pilotage.db")
    try:
        return cx.execute("SELECT COALESCE(SUM(length(CAST(valeur_json AS BLOB))),0) FROM inventaire WHERE cle=?", (cle,)).fetchone()[0]
    finally:
        cx.close()


def test_plafond_compte_des_octets_pas_des_caracteres_r39(tmp_path):
    """R39 (mineur) : `é` vaut deux octets en UTF-8 ; le plafond borne le disque, il compte donc des OCTETS."""
    s, h = neuf(tmp_path)
    s.octets_max = 300_000
    s.vu(GK5, {})
    for i in range(6):
        h.avance(60)
        params = {f"{P}Gros.{i}.{j}": "é" * 60000 for j in range(2)}   # 2 × 120 002 octets, 2 × 60 002 caractères
        s.inventaire_enregistrer(GK5, {"results": [{"path": P, "params": params}], "tronque": True})
        assert _somme_vrais_octets(tmp_path, GK5.cle) <= s.octets_max, i
        assert all(k in s.inventaire(GK5.cle)["valeurs"] for k in params)


def _traces(tmp_path, cle):
    cx = sqlite3.connect(tmp_path / "pilotage" / "pilotage.db")
    try:
        return {t: cx.execute(f"SELECT COUNT(*) FROM {t} WHERE cle=?", (cle,)).fetchone()[0]
                for t in ("boites", "inventaire", "evenements", "releves")}
    finally:
        cx.close()


def test_box_sans_contact_depuis_30_jours_oubliee_m12(tmp_path):
    """M12 : une box (révoquée, renommée) sans contact depuis 30 jours est oubliée : ligne `boites`, inventaire, événements, relevé."""
    s, h = neuf(tmp_path)
    s.vu(GK5_AUTOLOAD, {})
    s.inventaire_enregistrer(GK5_AUTOLOAD, releve_gk5())
    s.notification(GK5_AUTOLOAD, {"type": "X_SECUBOX_Boot", "value": 3, "ts": int(h.t)})
    s.releve_enregistrer(GK5_AUTOLOAD.cle, 10, "ok", {"cpu_pct": 1})
    t0 = h.t
    h.avance(30 * JOUR)
    s.vu(GK5, {})                                   # une autre box, en ligne
    assert s.oublier() == []                        # 30 jours pile : pas encore
    h.avance(1)
    (o,) = s.oublier()
    assert o == {"cle": GK5_AUTOLOAD.cle, "nom": "gk5", "reseau": "autoload", "dernier_contact": int(t0)}
    assert _traces(tmp_path, GK5_AUTOLOAD.cle) == {"boites": 0, "inventaire": 0, "evenements": 0, "releves": 0}
    assert s.boite(GK5.cle) is not None and s.oublier() == []


def test_oubli_ne_touche_jamais_une_box_en_ligne_m12(tmp_path):
    """Une box qui sonde (vu_le rafraîchi à chaque contact) n'est jamais oubliée, quel que soit l'âge de sa première venue."""
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    s.inventaire_enregistrer(GK5, releve_gk5())
    for _ in range(40):
        h.avance(JOUR)
        s.vu(GK5, {})                               # sondage : dernier contact réel
        assert s.oublier() == []
    assert s.boite(GK5.cle)["en_ligne"] and _traces(tmp_path, GK5.cle)["inventaire"] > 0


def test_oubli_compte_depuis_le_dernier_contact_reel_m12(tmp_path):
    """Le seuil part du DERNIER contact (sondage, relève rangée, notification reçue), pas de la première venue ni d'une autre trace."""
    s, h = neuf(tmp_path)
    s.vu(GK5, {})
    h.avance(25 * JOUR)
    s.notification(GK5, {"type": "X_SECUBOX_Boot", "value": 3, "ts": 1})   # reçue du canal : un contact
    h.avance(6 * JOUR)                                                     # 31 j depuis vu_le, 6 j depuis la notification
    assert s.oublier() == []
    h.avance(24 * JOUR + 1)
    assert [o["cle"] for o in s.oublier()] == [GK5.cle]
    s.vu(GK5, {})
    h.avance(29 * JOUR)
    s.inventaire_enregistrer(GK5, releve_gk5())                            # relève rangée : un contact
    h.avance(2 * JOUR)
    assert s.oublier() == []


def _flotte(s, n):
    boites = [Box(f"gk{i}", f"10.10.0.{10 + i}", "maillage", None, None) for i in range(n)]
    for b in boites:
        s.vu(b, {})
    return boites


def test_saut_d_horloge_n_oublie_aucune_box_r_l2_45(tmp_path):
    """R-L2-45 : un saut de 40 jours de l'horloge du maître rend toute la flotte « muette » : rien n'est oublié, l'oubli est suspendu."""
    s, h = neuf(tmp_path)
    boites = _flotte(s, 5)
    h.avance(40 * JOUR)
    r = s.oublier()
    assert r == [] and r.suspendu == {"candidates": 5, "total": 5}
    assert all(s.boite(b.cle) is not None for b in boites)


def test_une_box_muette_sur_cinq_reste_oubliee_r_l2_45(tmp_path):
    s, h = neuf(tmp_path)
    muette, *autres = _flotte(s, 5)
    h.avance(31 * JOUR)
    for b in autres:
        s.vu(b, {})
    r = s.oublier()
    assert [o["cle"] for o in r] == [muette.cle] and r.suspendu is None


def test_plus_de_la_moitie_suspend_la_moitie_non_r_l2_45(tmp_path):
    s, h = neuf(tmp_path)
    boites = _flotte(s, 4)
    h.avance(31 * JOUR)
    for b in boites[2:]:
        s.vu(b, {})
    assert len(s.oublier()) == 2                      # 2 sur 4 : la moitié, pas plus → oubliées
    s2, h2 = neuf(tmp_path / "b")
    boites = _flotte(s2, 4)
    h2.avance(31 * JOUR)
    s2.vu(boites[0], {})
    r = s2.oublier()
    assert r == [] and r.suspendu == {"candidates": 3, "total": 4}


def test_resume_interface_pour_le_panneau_flotte(tmp_path):
    """L5 tâche 7 : le panneau Flotte du maître ouvre une box « distante » par l'émission du code, une box « locale »
    par son lien direct ; inconnue (agent < 0.5.0, valeur hors liste) = « locale », le comportement d'avant."""
    s, _ = neuf(tmp_path)
    s.vu(GK5, {})
    assert s.resumes()[0]["interface"] == "locale"
    s.inventaire_enregistrer(GK5, releve_gk5(interface="distante"))
    assert s.resumes()[0]["interface"] == "distante"
    s.inventaire_enregistrer(GK5, releve_gk5(interface="<b>autre</b>"))
    assert s.resumes()[0]["interface"] == "locale"
