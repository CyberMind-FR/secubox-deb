# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 3 SBX TV PRIVACY (#3374), passe 2 après relectures : fuite d'adresses au lecteur délégué (S1), audit des gestes (S2),
« Je débloque » = pause de 24 h au plus (S3), exceptions écrites avant application (S4) et efficaces quel que soit le mode (I1),
défaut AUTO à la seule première installation (I2), « nouveaux » masqué sous un jour (I3), et les mineurs."""
import json
import os
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_analyse as A, dnstv_protection as P, dnstv_regles as R
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

RACINE = Path(__file__).resolve().parents[1]
MAC1, MAC2 = "00:24:d4:00:00:01", "00:24:d4:00:00:02"
IP1, IP2, IP3 = "192.168.1.95", "192.168.1.96", "192.168.1.97"
T0 = int(time.time())


def etat_base():
    return {"actif": True, "clients": [{"ip": IP1, "nom": "TV salon", "mode": "auto", "mac": MAC1},
                                       {"ip": IP2, "nom": "TV chambre", "mode": "block", "mac": MAC2},
                                       {"ip": IP3, "nom": "Enceinte", "mode": "observe"}]}


@pytest.fixture
def tv(api, monde):
    dnstv.ecrire_etat(etat_base(), monde["etat"])
    return api


def _audit(monde):
    f = monde["tmp"] / "audit.log"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.is_file() else []


# ── S1 : aucune adresse ni acteur au lecteur délégué ─────────────────────────────────────────────────
def _magasin(d):
    m = dnstv.Magasin(d / "dnstv.db")
    m.ajouter([(dnstv.Evenement(T0 - 30, IP1, "pub.example.com", "A", "NXDOMAIN", "BLOCKED"), ""),
               (dnstv.Evenement(T0 - 20, IP1, "api.example.net", "A", "SERVFAIL", "UPSTREAM_ERROR"), "")])
    return m


def test_s1_evenements_et_diagnostic_sans_adresse_ni_acteur_pour_le_delegue(tv, monde, monkeypatch):
    from api import dnstv_journal as J, dnstv_lot3_routes as L
    _magasin(monde["etat"])
    J.ajouter([J.entree(T0, "TV salon", MAC1, "", "", "pause", "usager", "1 h par marie")], monde["etat"])
    monkeypatch.setattr(L, "est_admin_reel", lambda p: False)          # porteur délégué du pilotage : nominatif, pas administrateur réel
    ev = tv.get("/adblock-tv/protection/evenements?heures=1").text
    dg = tv.get("/adblock-tv/protection/diagnostic").text
    for txt in (ev, dg):
        assert IP1 not in txt and "marie" not in txt and MAC1 not in txt
    assert "pub.example.com" in ev and "api.example.net" in dg


# ── S2 : audit.log reçoit le geste, le périmètre, l'origine et l'acteur ──────────────────────────────
def test_s2_verbe_root_audit_protection_valide_et_ecrit(monde):
    import io
    import sys
    bon = {"acteur": "marie", "origine": "usager", "geste": "pause", "cibles": ["TV salon"], "minutes": 60, "domaine": None, "type": None,
           "force": False}
    for brut, rc in ((bon, 0), (dict(bon, origine="pirate"), 2), (dict(bon, geste="durcir"), 2), (dict(bon, acteur="a b"), 2),
                     (dict(bon, cibles=["x\ny"]), 2), (dict(bon, minutes=999999), 2), (dict(bon, extra=1), 2),
                     (dict(bon, geste="exception", domaine="pas un domaine", type="bloquer"), 2)):
        sys.stdin = io.StringIO(json.dumps(brut))
        try:
            assert ctl(monde, "audit-protection") == rc, brut
        finally:
            sys.stdin = sys.__stdin__
    a = [x for x in _audit(monde) if x["action"] == "protection"]
    assert len(a) == 1 and a[0]["acteur"] == "marie" and a[0]["origine"] == "usager" and a[0]["cibles"] == ["TV salon"]


def test_s2_sudoers_et_routes_auditent(tv, monde, monkeypatch):
    s = (RACINE / "sudoers.d" / "secubox-adguard-tv").read_text()
    assert "/usr/sbin/secubox-adguard-tv audit-protection" in s and "*" not in s
    from api import dnstv_routes as r
    vus = []
    monkeypatch.setattr(r, "_ctl_entree", lambda action, entree: vus.append((action, json.loads(entree))))
    tv.post("/adblock-tv/protection/pause", json={"appareil": "TV salon", "minutes": 60})
    tv.post("/adblock-tv/protection/observe", json={"appareil": None})
    tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV salon", "domaine": "pub.example.com", "type": "autoriser"})
    assert [(a, e["geste"], e["origine"], e["acteur"]) for a, e in vus] == [
        ("audit-protection", "pause", "admin", "admin"), ("audit-protection", "observe", "admin", "admin"),
        ("audit-protection", "exception", "admin", "admin")]
    assert vus[0][1]["cibles"] == ["TV salon"] and vus[0][1]["minutes"] == 60


def test_s2_audit_impossible_refuse_le_geste(tv, monkeypatch):
    from fastapi import HTTPException
    from api import dnstv_routes as r

    def refus(action, entree):
        raise HTTPException(502, "audit refusé")
    monkeypatch.setattr(r, "_ctl_entree", refus)
    assert tv.post("/adblock-tv/protection/pause", json={"appareil": "TV salon", "minutes": 60}).status_code == 502
    assert dnstv.lire_etat()[0]["clients"][0]["mode"] == "auto"


# ── S3 : l'usager ne fait qu'une pause, 24 h au plus ─────────────────────────────────────────────────
@pytest.fixture
def usager(tv, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot3_routes as L, dnstv_routes as r
    L._DEBIT.clear()
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    tv.app.dependency_overrides[auth.require_personne] = lambda: {"sub": "marie"}
    return tv


def test_s3_usager_pause_24h_au_plus_jamais_observe(usager):
    assert usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "observe"}).status_code == 422
    assert usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "pause", "minutes": 1441}).status_code == 422
    r = usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "pause", "minutes": 1440})
    assert r.status_code == 200 and r.json()["message"] == "protection en pause pour TV salon pendant 24 h"
    assert P.charger_pauses()[0]["fin"] <= int(time.time()) + 86400
    assert 1440 in usager.get("/adblock-tv/protection/usager/tv").json()["durees"]


def test_s3_interfaces_sans_observe_pour_l_usager():
    page = (RACINE / "www" / "tv-privacy" / "index.html").read_text()
    assert 'id="debloque-observe"' not in page and 'data-minutes="1440"' in page
    k = RACINE.parents[0] / "secubox-kiosque" / "www" / "kiosque"
    assert 'id="k-observe"' not in (k / "index.html").read_text() and 'data-minutes="1440"' in (k / "index.html").read_text()


# ── S4 : exceptions.json écrit avant l'application, restauré si elle échoue ──────────────────────────
def test_s4_exceptions_restaurees_si_application_echoue(tv, monde, monkeypatch):
    from fastapi import HTTPException
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    ordre = []
    vrai = P.ecrire_exceptions
    monkeypatch.setattr(P, "ecrire_exceptions", lambda ex, d=None: ordre.append("ecrire") or vrai(ex, d))

    def echec(action):
        ordre.append("appliquer")
        raise HTTPException(502, "contrôleur en échec")
    monkeypatch.setattr(r, "_ctl", echec)
    rep = tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV salon", "domaine": "pub.example.com", "type": "bloquer"})
    assert rep.status_code == 502 and ordre[:2] == ["ecrire", "appliquer"]
    assert P.charger_exceptions() == []


# ── I1 : une exception a un effet quel que soit le mode, ou elle est refusée ─────────────────────────
def _conf(monde):
    return monde["conf"].read_text()


def test_i1_protect_autoriser_prime_sur_la_liste_et_bloquer_ajoute(tv, monde, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    assert tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV chambre", "domaine": "ad.doubleclick.net", "type": "autoriser"}).status_code == 200
    assert tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV chambre", "domaine": "pub-maison.example.com", "type": "bloquer"}).status_code == 200
    c = _conf(monde)
    assert f"access-control-view: {IP2}/32 sbx-tv-block-tv-chambre" in c
    vue = c.split('name: "sbx-tv-block-tv-chambre"')[1].split("view:")[0]
    assert 'local-zone: "ad.doubleclick.net." transparent' in vue and 'local-zone: "doubleclick.net." always_nxdomain' in vue
    assert 'local-zone: "pub-maison.example.com." always_nxdomain' in vue
    assert 'name: "sbx-tv-block"' in c                                          # les autres appareils PROTECT gardent la vue commune


def test_i1_rendu_protect_sans_exception_inchange():
    etat = {"actif": True, "clients": [{"ip": IP2, "nom": "TV chambre", "mode": "block"}]}
    c = dnstv.rendre_unbound(etat, {"doubleclick.net": "advertising"}, {})
    assert f"{IP2}/32 sbx-tv-block\n" in c and "sbx-tv-block-" not in c


def test_i1_bloquer_en_observe_refuse_explicitement(tv, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    rep = tv.post("/adblock-tv/protection/exceptions", json={"appareil": "Enceinte", "domaine": "x.example.com", "type": "bloquer"})
    assert rep.status_code == 422 and "OBSERVE" in rep.json()["detail"]


def test_i1_autorisation_au_puits_posee_pendant_une_pause():
    etat, pauses, regles = etat_base(), [], R.Regles()
    P.mettre_en_pause(etat, pauses, ["TV salon"], 60, T0, "admin")
    P.poser_exception([], etat, regles, "TV salon", "cdn.example.com", "autoriser", True, T0, "admin", pauses=pauses)
    assert etat["autorisations"]["tv-salon"] == ["cdn.example.com"]
    P.reprendre(etat, pauses, None, T0 + 4000, echues=True)
    assert etat["clients"][0]["mode"] == "auto" and "cdn.example.com" in dnstv.rendre_unbound(etat, {}, {})


def test_i1_plafond_d_autorisations_409(tv, monde, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    e = etat_base()
    e["autorisations"] = {"tv-salon": [f"d{i}.example.com" for i in range(dnstv.AUTORISATIONS_PAR_APPAREIL)]}
    dnstv.ecrire_etat(e, monde["etat"])
    rep = tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV salon", "domaine": "encore.example.com", "type": "autoriser"})
    assert rep.status_code == 409 and "autorisations" in rep.json()["detail"]
    assert P.charger_exceptions() == []


def test_i1_bloquer_categorie_protegee_demande_force(tv, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    corps = {"appareil": "TV salon", "domaine": "license.oqee.net", "type": "bloquer"}
    rep = tv.post("/adblock-tv/protection/exceptions", json=corps)
    assert rep.status_code == 409 and "DRM" in rep.json()["detail"]
    assert tv.post("/adblock-tv/protection/exceptions", json=dict(corps, force=True)).status_code == 200


# ── I2 : AUTO par défaut à la seule première installation ────────────────────────────────────────────
def test_i2_etat_absent_n_active_pas_l_ajout_auto(monde, monkeypatch):
    monkeypatch.setattr(dnstv, "CONF_PAQUET", monde["tmp"] / "ad-guard.toml")
    (monde["tmp"] / "ad-guard.toml").write_text("[adblock_tv]\najout_auto_initial = true\n")
    etat, err = dnstv.lire_etat()
    assert err is None and etat["ajout_auto"] is False and etat["mode_defaut"] == "auto"


def test_i2_premiere_installation_pose_l_etat_initial_une_seule_fois(monde, monkeypatch):
    monkeypatch.setattr(dnstv, "CONF_PAQUET", monde["tmp"] / "ad-guard.toml")
    (monde["tmp"] / "ad-guard.toml").write_text("[adblock_tv]\najout_auto_initial = true\n")
    assert dnstv.poser_etat_initial(monde["etat"]) is True
    assert dnstv.lire_etat()[0]["ajout_auto"] is True
    dnstv.ecrire_etat(dict(dnstv.lire_etat()[0], ajout_auto=False))
    assert dnstv.poser_etat_initial(monde["etat"]) is False and dnstv.lire_etat()[0]["ajout_auto"] is False


def test_i2_postinst_seulement_sur_premiere_installation():
    p = (RACINE / "debian" / "postinst").read_text()
    assert 'if [ "$1" = configure ] && [ -z "$2" ]; then' in p and "poser_etat_initial" in p


# ── I3 : « nouveaux » masqué sous un jour ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fenetre,attendu", [("1h", None), ("24h", None), ("7j", 1)])
def test_i3_nouveaux_seulement_au_dela_d_un_jour(tmp_path, fenetre, attendu):
    hier = T0 - 30 * 3600
    A.ecrire_cache([{"domaine": "pub.example.com", "mac": MAC1, "categorie": "PUBLICITE", "source": "liste", "confiance": 80,
                     "protegee": False, "ips": [IP1], "requetes": 3, "bloquees": 3, "derniere_observation": T0 - 60,
                     "premiere_observation": hier - hier % 86400}], T0, tmp_path, etat={}, regles=[])
    assert A.analyser(tmp_path, fenetre=fenetre, maintenant=T0)["metriques"]["nouveaux"] == attendu


# ── mineurs ──────────────────────────────────────────────────────────────────────────────────────────
def test_m_sqlite_corrompu_rend_cache_false(tmp_path):
    A.ecrire_cache([], T0, tmp_path, etat={}, regles=[])
    cx = sqlite3.connect(tmp_path / A.FICHIER)
    cx.execute("DROP TABLE lignes")
    cx.commit()
    cx.close()
    assert A.analyser(tmp_path, maintenant=T0)["cache"] is False
    assert A.selection(tmp_path, maintenant=T0)[2] is None and A.toutes(tmp_path) is None


def test_m_purge_temporaires_et_ancien_json(tmp_path):
    vieux = tmp_path / ".classification-cache.abcd"
    vieux.write_bytes(b"x")
    os.utime(vieux, (T0 - 3600, T0 - 3600))
    neuf = tmp_path / ".classification-cache.efgh"
    neuf.write_bytes(b"x")
    (tmp_path / "classification-cache.json").write_text("{}")
    A.menage(tmp_path, T0)
    assert not vieux.exists() and neuf.exists() and not (tmp_path / "classification-cache.json").exists()


def test_m_moteur_inactif_fait_le_menage(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import Rep, charger_script, lancer
    mod = charger_script(monkeypatch, tmp_path, {"actif": False, "clients": []})
    (tmp_path / "classification-cache.json").write_text("{}")
    assert lancer(mod, lambda: Rep(), T0) == 0
    assert not (tmp_path / "classification-cache.json").exists()


def test_m_changer_mode_oublie_la_pause(tv, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    tv.post("/adblock-tv/protection/pause", json={"appareil": "TV salon", "minutes": 60})
    assert P.charger_pauses()
    tv.post("/adblock-tv/mode", json={"mode": "protect", "ip": IP1})
    assert P.charger_pauses() == []


def test_m_sub_absent_403(tv, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot3_routes as L
    L._DEBIT.clear()
    tv.app.dependency_overrides[auth.require_personne] = lambda: {}
    assert tv.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "pause", "minutes": 15}).status_code == 403


def test_m_debit_non_decompte_sur_refus(usager):
    for _ in range(8):
        assert usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "inconnue", "geste": "pause", "minutes": 15}).status_code == 404
    assert usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "pause", "minutes": 15}).status_code == 200


def test_m_reprise_pose_a_appliquer_si_pauses_illisibles_en_ecriture(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import charger_script
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "clients": [{"ip": IP1, "nom": "TV salon", "mode": "observe", "mac": MAC1}]})
    P.ecrire_pauses([{"appareil": "TV salon", "fin": T0 - 1, "modes": {IP1: "auto"}, "origine": "usager"}], tmp_path)

    def casse(*a, **k):
        raise OSError("disque plein")
    monkeypatch.setattr(mod.dnstv_protection, "ecrire_pauses", casse)
    etat, _ = dnstv.lire_etat(tmp_path)
    mod.reprendre_pauses(etat, T0)
    assert (tmp_path / ".a-appliquer").exists() and dnstv.lire_etat(tmp_path)[0]["clients"][0]["mode"] == "auto"


# ── gardes réelles de /usager/* (aucune dépendance remplacée) ────────────────────────────────────────
@pytest.fixture
def brut(monde, monkeypatch):
    from api import dnstv_routes as r
    from secubox_core import auth
    app = FastAPI()
    app.include_router(r.router)
    dnstv.ecrire_etat(etat_base(), monde["etat"])
    return TestClient(app), auth


def test_garde_sans_session_401(brut):
    c, _ = brut
    assert c.get("/adblock-tv/protection/usager/tv").status_code == 401
    assert c.post("/adblock-tv/protection/usager/debloquer", json={"tv": "toutes", "geste": "pause", "minutes": 15}).status_code == 401


def test_garde_invite_plafonne_403(brut, monkeypatch):
    c, auth = brut
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": "invite", auth.PLAFOND: "guest"})
    h = {"Authorization": "Bearer x"}
    assert c.get("/adblock-tv/protection/usager/tv", headers=h).status_code == 403
    assert c.post("/adblock-tv/protection/usager/debloquer", headers=h, json={"tv": "toutes", "geste": "pause", "minutes": 15}).status_code == 403


def test_garde_porteur_delegue_403(brut, monkeypatch):
    c, auth = brut
    monkeypatch.setattr(auth, "_validate_token", lambda t: None)
    monkeypatch.setattr(auth, "_porteur_pilotage", lambda req, t: {"sub": auth.PREFIXE_PILOTAGE + "maitre", "portee": "admin"})
    h = {"Authorization": "Bearer x"}
    assert c.get("/adblock-tv/protection/usager/tv", headers=h).status_code == 403
    assert c.post("/adblock-tv/protection/usager/debloquer", headers=h, json={"tv": "toutes", "geste": "pause", "minutes": 15}).status_code == 403


# ── passe 3 ──────────────────────────────────────────────────────────────────────────────────────────
def test_p3_ecriture_des_exceptions_en_echec_restaure_regles_et_etat(tv, monde, monkeypatch):
    from api import dnstv_routes as r
    vus = []
    monkeypatch.setattr(r, "_ctl_entree", lambda a, e: vus.append(json.loads(e)))

    def casse(*a, **k):
        raise OSError("disque plein")
    monkeypatch.setattr(P, "ecrire_exceptions", casse)
    rep = tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV salon", "domaine": "pub.example.com", "type": "autoriser"})
    assert rep.status_code == 503
    assert "autorisations" not in dnstv.lire_etat()[0] and R.charger().liste() == []
    assert [x["geste"] for x in vus] == ["exception", "annule"]


def test_p3_force_audite(tv, monkeypatch):
    from api import dnstv_routes as r
    vus = []
    monkeypatch.setattr(r, "_ctl_entree", lambda a, e: vus.append(json.loads(e)))
    tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV salon", "domaine": "license.oqee.net", "type": "bloquer", "force": True})
    tv.post("/adblock-tv/protection/pause", json={"appareil": "TV salon", "minutes": 15})
    assert vus[0]["force"] is True and vus[1]["force"] is False


def test_p3_verbe_root_valide_force_et_annule(monde):
    import io
    import sys
    bon = {"acteur": "admin", "origine": "admin", "geste": "exception", "cibles": ["TV salon"], "minutes": None,
           "domaine": "x.example.com", "type": "bloquer", "force": True}
    for brut, rc in ((bon, 0), (dict(bon, force="oui"), 2), ({k: v for k, v in bon.items() if k != "force"}, 2),
                     (dict(bon, geste="annule"), 0), (dict(bon, geste="annule", domaine=None, type=None), 0)):
        sys.stdin = io.StringIO(json.dumps(brut))
        try:
            assert ctl(monde, "audit-protection") == rc, brut
        finally:
            sys.stdin = sys.__stdin__


def test_p3_annule_audite_apres_retour_arriere_d_un_geste(tv, monkeypatch):
    from fastapi import HTTPException
    from api import dnstv_routes as r
    vus = []
    monkeypatch.setattr(r, "_ctl_entree", lambda a, e: vus.append(json.loads(e)))

    def echec(action):
        raise HTTPException(502, "contrôleur en échec")
    monkeypatch.setattr(r, "_ctl", echec)
    assert tv.post("/adblock-tv/protection/pause", json={"appareil": "TV salon", "minutes": 15}).status_code == 502
    assert [x["geste"] for x in vus] == ["pause", "annule"]


def test_p3_journal_lecteur_sans_mac(tv, monde, monkeypatch):
    from api import dnstv_journal as J, dnstv_lot3_routes as L
    J.ajouter([J.entree(T0, "TV salon", MAC1, "x.example.com", "", "retrait", "admin", "m")], monde["etat"])
    monkeypatch.setattr(L, "est_admin_reel", lambda p: False)
    assert "00:24:d4" not in tv.get("/adblock-tv/protection/diagnostic").text


def test_p3_taxonomie_indisponible_503(tv, monkeypatch):
    from api import dnstv_taxonomie as T

    def casse(*a, **k):
        raise OSError("listes absentes")
    monkeypatch.setattr(T.Taxonomie, "depuis_dossier", classmethod(lambda cls, *a, **k: casse()))
    rep = tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV salon", "domaine": "x.example.com", "type": "bloquer"})
    assert rep.status_code == 503


def test_p3_diagnostic_signale_protect_sans_regles(tv, monde):
    (monde["etat"] / "regles.json").write_text("{pas du json")
    assert tv.get("/adblock-tv/protection/diagnostic").json()["protect_sans_regles"] is True
