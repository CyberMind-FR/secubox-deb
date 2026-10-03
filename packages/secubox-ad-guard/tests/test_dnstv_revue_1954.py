# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Passe de correction après la relecture de sécurité du mode auto (#1954) : un test par constat Critique/Important."""
import inspect
import json
import os
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_auto as M, dnstv_detect as D, dnstv_regles as R
from test_dnstv_ctl_api import monde  # noqa: F401  (fixture)
from test_dnstv_auto_rendu import ETAT, charger_ctl, faux, preparer, regles_essai
from test_dnstv_auto_moteur import IP, REGLAGE, classer, coupure, charger, evt, regle_en_essai

ICI = Path(__file__).resolve().parents[1]


@pytest.fixture
def monde_api(monde, monkeypatch):
    """API avec un faux contrôleur dont l'échec se commande par monde["echec"]."""
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
    from secubox_core import auth
    from api import dnstv_routes as routes
    dnstv.ecrire_etat(ETAT, monde["etat"])
    r = R.Regles()
    ids = {"cand": r.proposer("tv-banc", "ad.example.com", 80, "faible", int(time.time()))["id"]}
    R.ecrire(r, monde["etat"])

    def appel(action):
        if monde.get("echec"):
            raise HTTPException(502, "contrôleur en échec")
        return {"ok": True}
    monkeypatch.setattr(routes, "_ctl", appel)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "admin"}
    from fastapi.testclient import TestClient
    return TestClient(app), monde, ids


# ── C1 : l'instantané de root ne se range pas dans un dossier que secubox contrôle ──────────────────────────────────────────
def test_c1_instantane_refuse_un_dossier_lien_symbolique(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    vrai = tmp_path / "vrai"
    vrai.mkdir(mode=0o700)
    os.symlink(vrai, tmp_path / "root")
    monkeypatch.setattr(mod, "APPLIQUE", tmp_path / "root" / "applique.json")
    with pytest.raises(SystemExit):
        mod.ecrire_instantane({"actif": True})


def test_c1_un_lien_pose_sur_le_nom_temporaire_n_est_jamais_suivi(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    racine = tmp_path / "root"
    racine.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "APPLIQUE", racine / "applique.json")
    victime = tmp_path / "victime"
    victime.write_text("intact")
    os.symlink(victime, racine / "applique.tmp")                    # le piège de la relecture : un lien sur le nom prévisible
    mod.ecrire_instantane({"actif": True})
    assert victime.read_text() == "intact" and stat_mode(racine / "applique.json") == 0o600


def stat_mode(p):
    return os.stat(p).st_mode & 0o777


def test_c1_dossier_d_instantane_hors_de_l_arbre_de_secubox():
    src = (ICI / "sbin" / "secubox-adguard-tv").read_text()
    assert "/var/lib/secubox/ad-guard/dnstv-root" not in src and "/var/lib/secubox-adguard-tv" in src
    post = (ICI / "debian" / "postinst").read_text()
    assert "install -d -m 0700 -o root -g root /var/lib/secubox-adguard-tv" in post


# ── C2 / I9 : le sudo de la minuterie doit pouvoir écrire là où le contrôleur écrit ─────────────────────────────────────────
def test_c2_unite_autorise_les_chemins_du_controleur_et_porte_son_exception():
    u = (ICI / "debian" / "secubox-ad-guard-auto.service").read_text()
    rw = next(ligne for ligne in u.splitlines() if ligne.startswith("ReadWritePaths="))
    for chemin in ("/etc/unbound/unbound.conf.d", "/var/log/secubox", "/var/lib/secubox-adguard-tv", "/var/lib/secubox/ad-guard"):
        assert chemin in rw
    assert "NoNewPrivileges=no" in u and "ProtectSystem=strict" in u
    for durcissement in ("ProtectKernelTunables=yes", "ProtectControlGroups=yes", "LockPersonality=yes"):
        assert durcissement in u
    assert u.startswith("# SPDX-License-Identifier") and (ICI / "debian" / "secubox-ad-guard-auto.timer").read_text().startswith("# SPDX-License-Identifier")
    regles = (ICI.parents[1] / ".claude" / "RULES-CODE.md").read_text()
    assert "secubox-ad-guard-auto" in regles                                                       # l'exception est écrite


# ── I1 : le drop-in est écrit et vérifié AVANT toute application à chaud ────────────────────────────────────────────────────
def test_i1_checkconf_refuse_rien_n_est_applique_a_chaud(monkeypatch, tmp_path):
    ok = faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    avant = (tmp_path / "applique.json").read_text()
    faux(tmp_path, "checkconf", code=1)                                                            # le contrôle refusera désormais
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    with pytest.raises(SystemExit):
        mod.regles_appliquer()
    assert not (tmp_path / "unbound-control.log").exists()                                         # aucune zone ajoutée en mémoire
    assert (tmp_path / "applique.json").read_text() == avant


def test_i1_echec_de_l_application_remet_regles_json_dans_l_etat_precedent(monde_api):
    api, monde, regles = monde_api
    monde["echec"] = True
    r = api.post(f"/adblock-tv/auto/regles/{regles['cand']}/essayer")
    assert r.status_code == 502
    assert R.charger(monde["etat"]).get(regles["cand"])["etat"] == "candidat"                     # l'interface ne ment pas


# ── I2 : un verrou commun évite qu'une écriture en écrase une autre ─────────────────────────────────────────────────────────
def test_i2_verrou_exclusif(tmp_path):
    with R.verrou(tmp_path):
        with pytest.raises(R.ErreurRegle):
            with R.verrou(tmp_path, bloquant=False):
                pass
    with R.verrou(tmp_path, bloquant=False):                                                       # libéré après la sortie
        pass


# ── I3 : deux noms différents ne partagent jamais une vue ─────────────────────────────────────────────────────────────────────
def test_i3_deux_noms_au_meme_identifiant_refuses():
    etat = {"actif": True, "clients": [{"ip": "192.168.1.5", "nom": "TV Salon", "mode": "auto"}, {"ip": "192.168.1.6", "nom": "tv-salon", "mode": "auto"}]}
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat(etat)
    ok = {"actif": True, "clients": [{"ip": "192.168.1.5", "nom": "TV banc", "mode": "auto"}, {"ip": "2a01::5", "nom": "TV banc", "mode": "auto"}]}
    assert len(dnstv.valider_etat(ok)["clients"]) == 2                                             # même nom exact = même appareil (IPv4 + IPv6)


# ── I4 : une veille bavarde n'est pas une activité de lecture ─────────────────────────────────────────────────────────────────
@pytest.fixture
def magasin(tmp_path):
    return dnstv.Magasin(tmp_path / "m.db")


def test_i4_veille_bavarde_ne_retire_rien(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "videos-pub.ftv-publicite.fr", t - 3600)
    for jours in (2, 3, 4, 5):
        charger(magasin, [evt(t - jours * 86400, "cloudreplay.ftven.fr")])
    charger(magasin, [evt(t - 1800 + i * 5, "videos-pub.ftv-publicite.fr", decision="BLOCKED") for i in range(300)])   # relances d'un domaine refusé
    charger(magasin, [evt(t - 1800 + i * 90, "telemetry.example.com") for i in range(15)])                          # télémétrie de veille
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "essai"


def test_i4_pas_de_jugement_avant_trente_minutes_d_essai(magasin):
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "a.example.com", t - 600)
    for jours in (2, 3, 4, 5):
        charger(magasin, [evt(t - jours * 86400, "cloudreplay.ftven.fr")])
    charger(magasin, [evt(t - 500 + i, "autre.example.com") for i in range(200)])
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "essai"


def test_i4_jours_vus_est_borne_a_une_fenetre(magasin):
    t = int(time.time())
    charger(magasin, [evt(t - 40 * 86400, "vieux.example.com"), evt(t - 3 * 86400, "recent.example.com")])
    vus = magasin.jours_vus([IP], dnstv._jour(t), dnstv._jour(t - 7 * 86400))
    assert "recent.example.com" in vus and "vieux.example.com" not in vus


# ── I5 : purge, plafond, et `apply` indépendant des règles hors mode auto ────────────────────────────────────────────────────
def test_i5_les_regles_retirees_anciennes_sont_purgees_et_les_rejetees_gardees():
    t = int(time.time())
    r = R.Regles()
    a = r.proposer("tv", "a.example.com", 1, "faible", t - 100 * 86400)["id"]
    b = r.proposer("tv", "b.example.com", 1, "faible", t - 100 * 86400)["id"]
    r.transiter(a, "retire", "auto", "vieux", t - 90 * 86400)
    r.transiter(b, "rejete", "admin", "non", t - 90 * 86400)
    r.expirer(t)
    assert [x["domaine"] for x in r.liste()] == ["b.example.com"]


def test_i5_plafond_atteint_le_moteur_n_echoue_pas_et_expire_quand_meme(magasin, monkeypatch):
    t = int(time.time())
    r = R.Regles()
    rid = regle_en_essai(r, "ad.example.com", t - R.ESSAI_S - 10)
    monkeypatch.setattr(R, "REGLES_MAX", 1)
    charger(magasin, coupure(t - 3000) + coupure(t - 1500))
    M.tick(ETAT, r, magasin, classer, REGLAGE, t)
    assert r.get(rid)["etat"] == "retire"


def test_i5_apply_ne_depend_pas_de_regles_json_sans_appareil_auto(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.9", "nom": "Autre", "mode": "observe"}]}, tmp_path)
    (tmp_path / "regles.json").write_text("{corrompu")
    assert mod.appliquer() == 0


# ── I6 : `disable` est durable ───────────────────────────────────────────────────────────────────────────────────────────────
def test_i6_disable_empeche_regles_appliquer_de_reactiver_le_poc(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()
    assert mod.desactiver() == 0 and not (tmp_path / "94.conf").exists() and not (tmp_path / "applique.json").exists()
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    assert mod.regles_appliquer() == 0
    assert not (tmp_path / "94.conf").exists()                                                     # toujours désactivé
    mod.appliquer()                                                                                # une demande explicite le réactive
    assert (tmp_path / "94.conf").exists()


# ── I7 : routes sans boucle d'événements bloquée par subprocess ──────────────────────────────────────────────────────────────
def test_i7_les_routes_auto_sont_synchrones():
    from api import dnstv_routes as r
    for nom in ("regles_liste", "regle_action", "ca_ne_marche_plus", "auto_reglage", "auto_essai"):
        assert not inspect.iscoroutinefunction(getattr(r, nom)), nom


# ── I8 : audit des transitions effectives ──────────────────────────────────────────────────────────────────────────────────────
def test_i8_le_controleur_audite_chaque_transition_et_auto_essai(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()
    r = regles_essai("a.example.com")
    rid = R.identifiant("tv-banc", "a.example.com")
    r.transiter(rid, "confirme", "admin", "ok", 1_800_000_100)
    R.ecrire(r, tmp_path)
    dnstv.ecrire_etat(dict(ETAT, auto_essai=True), tmp_path)
    mod.regles_appliquer()
    audit = (tmp_path / "audit.log").read_text()
    assert "a.example.com" in audit and "essai→confirme" in audit and "origine=admin" in audit
    assert "auto_essai" in audit


# ── I10 : un parent n'est jamais proposé si son sous-arbre sert aussi du contenu ──────────────────────────────────────────────
def test_i10_parent_refuse_si_un_nom_du_sous_arbre_est_vu_hors_coupure():
    var = ["a1.cdn.tv.example", "a2.cdn.tv.example", "a3.cdn.tv.example"]
    T0 = 1_800_000_000
    evts = [{"ts": T0 - 50, "domaine": "live.cdn.tv.example", "decision": "ALLOWED"}]
    for t in (T0, T0 + 900):
        evts += [{"ts": t, "domaine": "7cd77.v.fwmrm.net", "decision": "ALLOWED"}] + [{"ts": t + 2 + i, "domaine": n, "decision": "ALLOWED"} for i, n in enumerate(var)]
    noms = {c.domaine for c in D.detecter(sorted(evts, key=lambda e: e["ts"]), lambda d: d.endswith("fwmrm.net"), lambda d: "", set())}
    assert "cdn.tv.example" not in noms


def test_i10_auto_essai_ne_met_a_l_essai_que_les_candidats_sans_risque(magasin):
    t = int(time.time())
    # le serveur d'insertion est aussi demandé 90 s après le début de la 1re coupure : hors de sa fenêtre, donc « partagé »
    charger(magasin, coupure(t - 3000) + [evt(t - 2910, "7cd77.v.fwmrm.net")] + coupure(t - 1500))
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, M.Reglage(declencheurs=("fwmrm.net",), auto_essai=True), t)
    etats = {x["domaine"]: (x["etat"], x["risque"]) for x in r.liste()}
    assert etats["videos-pub.ftv-publicite.fr"][0] == "essai"
    assert etats["7cd77.v.fwmrm.net"] == ("candidat", "partage")                                    # « partagé » reste à valider par un humain
