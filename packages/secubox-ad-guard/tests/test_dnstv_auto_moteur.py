# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import time

import pytest

from api import dnstv, dnstv_auto as M, dnstv_regles as R

IP = "192.168.1.95"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}, {"ip": "192.168.1.9", "nom": "Autre", "mode": "observe"}]}
REGLAGE = M.Reglage(declencheurs=("fwmrm.net",))
CLASSES = {"7cd77.v.fwmrm.net": "advertising"}


def classer(d):
    return CLASSES.get(d, "")


def evt(ts, d, client=IP, decision="ALLOWED"):
    return dnstv.Evenement(ts, client, d, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision)


@pytest.fixture
def magasin(tmp_path):
    return dnstv.Magasin(tmp_path / "m.db")


def coupure(t, client=IP):
    return [evt(t, "7cd77.v.fwmrm.net", client), evt(t + 3, "videos-pub.ftv-publicite.fr", client)]


def charger(magasin, evts):
    magasin.ajouter([(e, "") for e in evts])


def regle_en_essai(regles, domaine, depuis, appareil="tv-banc"):
    rid = regles.proposer(appareil, domaine, 50, "faible", depuis)["id"]
    regles.transiter(rid, "essai", "admin", "", depuis)
    return rid


def test_deux_coupures_donnent_des_candidats_sans_rien_activer(magasin):
    t = int(time.time())
    charger(magasin, [evt(t - 3300, "cloudreplay.ftven.fr")] + coupure(t - 3000) + [evt(t - 1700, "cloudreplay.ftven.fr")] + coupure(t - 1500))
    r = R.Regles()
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    domaines = {x["domaine"]: x["etat"] for x in r.liste()}
    assert domaines.get("videos-pub.ftv-publicite.fr") == "candidat" and domaines.get("7cd77.v.fwmrm.net") == "candidat"
    assert res["applique"] is False and r.par_appareil() == {}        # rien n'est bloqué sans l'administrateur


def test_auto_essai_active_directement_l_essai(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 3000) + coupure(t - 1500))
    r = R.Regles()
    res = M.tick(ETAT, r, magasin, classer, M.Reglage(declencheurs=("fwmrm.net",), auto_essai=True), t)
    assert res["applique"] is True and "videos-pub.ftv-publicite.fr" in r.actives("tv-banc")


def test_essai_expire_est_retire_et_declenche_l_application(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "ad.example.com", t - R.ESSAI_S - 10)
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "retire" and res["applique"] is True


def test_rafale_retire_la_regle(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "ad.example.com", t - 3600)
    charger(magasin, [evt(t - m * 60 - (k * 60) // 80, "ad.example.com", decision="BLOCKED") for m in range(6) for k in range(80)])
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "retire" and "rafale" in r.get(rid)["motif"] and res["applique"] is True


def test_comportement_normal_mesure_ne_retire_rien(magasin):
    """~10 refus par minute en lecture normale (mesuré) : la règle reste."""
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "videos-pub.ftv-publicite.fr", t - 3600)
    charger(magasin, [evt(t - m * 60 - (k * 60) // 10, "videos-pub.ftv-publicite.fr", decision="BLOCKED") for m in range(10) for k in range(10)])
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "essai"


def test_tv_inactive_ne_retire_aucune_regle(magasin):
    """TV éteinte depuis 2 h : aucune requête, donc aucun signal."""
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "ad.example.com", t - 7200)
    for jours in (2, 3, 4, 5):
        charger(magasin, [evt(t - jours * 86400, "cloudreplay.ftven.fr")])       # contenu habituel connu
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "essai" and res["applique"] is False


def test_contenu_habituel_disparu_retire_toutes_les_regles_en_essai(magasin):
    t = int(time.time())
    r = R.Regles()
    a, b = regle_en_essai(r, "a.example.com", t - 7200), regle_en_essai(r, "b.example.com", t - 7200)
    for jours in (2, 3, 4, 5):
        charger(magasin, [evt(t - jours * 86400, "cloudreplay.ftven.fr")])
    charger(magasin, [evt(t - 600 + i, "autre.example.com") for i in range(150)])   # l'appareil reste actif, mais n'appelle plus le contenu
    res = M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(a)["etat"] == r.get(b)["etat"] == "retire" and res["applique"] is True


def test_appareil_hors_mode_auto_jamais_touche(magasin):
    t = int(time.time())
    charger(magasin, coupure(t - 3000, "192.168.1.9") + coupure(t - 1500, "192.168.1.9"))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.liste() == []


def test_regroupement_des_adresses_d_un_meme_appareil():
    etat = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}, {"ip": "2a01:e0a::1", "nom": "TV banc", "mode": "auto"}]}
    assert M.appareils(etat) == {"tv-banc": [IP, "2a01:e0a::1"]}


# ── script de la minuterie ─────────────────────────────────────────────────────

def charger_script(monkeypatch, tmp_path, etat):
    import importlib.machinery
    import importlib.util
    from pathlib import Path
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", tmp_path / "listes")
    dnstv.ecrire_etat(etat, tmp_path)
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_auto", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_tv_auto", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Rep:
    def __init__(self, code=0):
        self.returncode, self.stdout, self.stderr = code, "", ""


def test_script_sort_aussitot_sans_appareil_auto(monkeypatch, tmp_path):
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP, "nom": "TV", "mode": "observe"}]})
    appels = []
    assert mod.main(sudo=lambda: appels.append(1) or Rep()) == 0
    assert appels == [] and not (tmp_path / "regles.json").exists()


def test_script_ecrit_les_regles_et_n_appelle_sudo_que_s_il_y_a_un_effet(monkeypatch, tmp_path):
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}]})
    t = int(time.time())
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter([(e, "") for e in coupure(t - 3000) + coupure(t - 1500)])
    appels = []
    assert mod.main(sudo=lambda: appels.append(1) or Rep(), maintenant=t) == 0
    assert any(r["domaine"] == "videos-pub.ftv-publicite.fr" for r in R.charger(tmp_path).liste())
    assert appels == []                                              # candidats seulement : aucun effet DNS, donc aucun sudo


def test_script_refus_du_controleur_remonte_l_echec(monkeypatch, tmp_path):
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}]})
    t = int(time.time())
    r = R.Regles()
    regle_en_essai(r, "ad.example.com", t - R.ESSAI_S - 10)
    R.ecrire(r, tmp_path)
    assert mod.main(sudo=lambda: Rep(1), maintenant=t) == 1


def test_script_relance_l_application_apres_un_echec_du_controleur(monkeypatch, tmp_path):
    """Mesuré sur gk2 : sudo refusé par l'unité. La règle est déjà retirée dans regles.json : sans relance, le DNS resterait périmé."""
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}]})
    t = int(time.time())
    r = R.Regles()
    regle_en_essai(r, "ad.example.com", t - R.ESSAI_S - 10)
    R.ecrire(r, tmp_path)
    assert mod.main(sudo=lambda: Rep(1), maintenant=t) == 1                 # échec : la tâche reste due
    assert (tmp_path / ".a-appliquer").exists()
    appels = []
    assert mod.main(sudo=lambda: appels.append(1) or Rep(), maintenant=t + 60) == 0     # aucune nouvelle transition, mais la relance a lieu
    assert appels == [1] and not (tmp_path / ".a-appliquer").exists()
    assert mod.main(sudo=lambda: appels.append(1) or Rep(), maintenant=t + 120) == 0
    assert appels == [1]                                                    # rien d'en attente : plus d'appel


def test_script_regles_corrompues_ne_change_rien(monkeypatch, tmp_path):
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}]})
    (tmp_path / "regles.json").write_text("{pas du json")
    appels = []
    assert mod.main(sudo=lambda: appels.append(1) or Rep()) == 1
    assert appels == [] and (tmp_path / "regles.json").read_text() == "{pas du json"
