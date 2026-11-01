# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 5b (#3374) : file d'actions différées de l'assistant (bornée, sans doublon, atomique, revalidée), consommation par le moteur
(exception du lot 3, garde revérifiée, `force`), apprentissage guidé par appareil (AUTO pur inchangé par défaut), verbe d'audit étendu."""
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_assistant as A, dnstv_auto as M, dnstv_dpi as D, dnstv_regles as R
from api import dnstv_taxonomie as T
from test_dnstv_ctl_api import ctl, monde  # noqa: F401  (fixtures)

LISTES = Path(__file__).resolve().parents[1] / "lists"
TAXO = T.Taxonomie.depuis_dossier(LISTES)
MAC = "aa:bb:cc:00:00:01"
T0 = 1_800_000_000


def etat():
    return {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}


# ── file : ajout, doublon, plafond, annulation ──────────────────────────────────────────────────────────
def test_ajout_sans_doublon_et_annulation_tant_qu_en_attente():
    c = A.vide()
    x = A.ajouter(c, MAC, "TV salon", "relais-pub.example.net", "bloquer", False, 12, "admin", T0)
    assert x["etat"] == "en-attente" and x["applique"] is None and len(x["id"]) == 16
    with pytest.raises(A.ErreurDoublon):
        A.ajouter(c, MAC, "TV salon", "relais-pub.example.net", "legitime", False, None, "admin", T0 + 1)
    A.annuler(c, x["id"])
    assert c["file"] == []
    with pytest.raises(A.ErreurAssistant):
        A.annuler(c, x["id"])


def test_choix_et_domaine_valides():
    c = A.vide()
    with pytest.raises(A.ErreurAssistant):
        A.ajouter(c, MAC, "TV salon", "x.example.com", "durcir", False, None, "admin", T0)
    with pytest.raises(A.ErreurAssistant):
        A.ajouter(c, MAC, "TV salon", "pas un domaine", "bloquer", False, None, "admin", T0)
    with pytest.raises(A.ErreurAssistant):
        A.ajouter(c, "pas-une-mac", "TV salon", "x.example.com", "bloquer", False, None, "admin", T0)


def test_file_bornee():
    c = A.vide()
    for i in range(A.ATTENTE_MAX):
        A.ajouter(c, MAC, "TV salon", f"d{i}.example.com", "plus-tard", False, None, "admin", T0)
    with pytest.raises(A.ErreurPlafond):
        A.ajouter(c, MAC, "TV salon", "encore.example.com", "plus-tard", False, None, "admin", T0)


def test_une_action_appliquee_n_est_plus_annulable_et_part_apres_24_h():
    c = A.vide()
    x = A.ajouter(c, MAC, "TV salon", "x.example.com", "plus-tard", False, None, "admin", T0)
    x.update(etat="applique", applique=T0 + 60)
    with pytest.raises(A.ErreurAssistant):
        A.annuler(c, x["id"])
    A.purger(c, T0 + 60 + 86400 + 1)
    assert c["file"] == []


def test_ecriture_atomique_relue_et_revalidee(tmp_path):
    c = A.vide()
    A.ajouter(c, MAC, "TV salon", "x.example.com", "bloquer", True, 3, "admin", T0)
    A.basculer_guide(c, MAC, True)
    A.ecrire(c, tmp_path)
    f = tmp_path / A.FICHIER
    assert oct(f.stat().st_mode & 0o777) == "0o640" and not [p for p in tmp_path.iterdir() if p.name.startswith(".assistant")]
    assert A.charger(tmp_path) == c
    f.write_text(json.dumps({"version": 1, "guides": [], "file": [dict(c["file"][0], choix="durcir")]}))
    with pytest.raises(A.ErreurAssistant):
        A.charger(tmp_path)
    f.unlink()
    os.symlink("/etc/passwd", f)
    with pytest.raises(A.ErreurAssistant):
        A.charger(tmp_path)


def test_absent_vaut_vide(tmp_path):
    assert A.charger(tmp_path) == {"version": 1, "guides": [], "file": []}


# ── consommation par le moteur ─────────────────────────────────────────────────────────────────────────
def test_consommer_applique_exception_du_lot_3_comme_decision_manuelle():
    e, r, c = etat(), R.Regles(), A.vide()
    A.ajouter(c, MAC, "TV salon", "relais-pub.example.net", "bloquer", False, 7, "admin", T0)
    A.ajouter(c, MAC, "TV salon", "video.example.org", "legitime", False, 8, "admin", T0)
    A.ajouter(c, MAC, "TV salon", "plus.example.org", "plus-tard", False, 9, "admin", T0)
    res = A.consommer(c, e, r, [], [], TAXO, T0 + 60)
    regles = {x["domaine"]: x for x in r.liste()}
    assert regles["relais-pub.example.net"]["etat"] == "confirme"
    assert regles["relais-pub.example.net"]["historique"][-1]["origine"] == "admin"          # lève la garde du lot 2
    assert "relais-pub.example.net" in T.confirmes_par_admin(r)
    assert regles["video.example.org"]["etat"] == "rejete" and "video.example.org" in e["autorisations"]["tv-salon"]
    assert "plus.example.org" not in regles
    assert [x["etat"] for x in c["file"]] == ["applique"] * 3 and all(x["applique"] == T0 + 60 for x in c["file"])
    assert sorted(res["marques"]) == [(7, "confirmee"), (8, "legitime"), (9, "plus-tard")]
    assert res["dns"] is True and {(x["domaine"], x["type"]) for x in res["exceptions"]} == {
        ("relais-pub.example.net", "bloquer"), ("video.example.org", "autoriser")}


def test_consommer_refuse_une_categorie_protegee_sans_force_imasdk():
    e, r, c = etat(), R.Regles(), A.vide()
    A.ajouter(c, MAC, "TV salon", "imasdk.googleapis.com", "bloquer", False, None, "admin", T0)
    res = A.consommer(c, e, r, [], [], TAXO, T0 + 60)
    assert c["file"][0]["etat"] == "refuse" and "protégée" in c["file"][0]["raison"]
    assert r.liste() == [] and res["dns"] is False
    c2 = A.vide()
    A.ajouter(c2, MAC, "TV salon", "imasdk.googleapis.com", "bloquer", True, None, "admin", T0)
    A.consommer(c2, e, r, [], [], TAXO, T0 + 60)
    assert c2["file"][0]["etat"] == "applique" and r.liste()[0]["etat"] == "confirme"


def test_consommer_appareil_disparu_refuse_sans_planter():
    e, r, c = {"actif": True, "clients": []}, R.Regles(), A.vide()
    A.ajouter(c, MAC, "TV salon", "x.example.com", "bloquer", False, None, "admin", T0)
    A.consommer(c, e, r, [], [], TAXO, T0 + 60)
    assert c["file"][0]["etat"] == "refuse" and c["file"][0]["raison"]


def test_marquer_une_decouverte_par_identifiant(tmp_path):
    m = D.MagasinDPI(tmp_path / "d.db")
    m.ajouter_decouvertes(MAC, [{"type": "repli", "domaine": "x.example.com", "ts": T0, "refus_ts": T0 - 3, "confiance": 70}])
    i = m.decouvertes()[0]["id"]
    m.marquer_id(i, "confirmee")
    assert m.decouvertes()[0]["etat"] == "confirmee"
    with pytest.raises(ValueError):
        m.marquer_id(i, "n'importe")


# ── apprentissage guidé ────────────────────────────────────────────────────────────────────────────────
IP = "192.168.1.95"
ETAT_BANC = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": "00:24:d4:00:00:01"}]}


@pytest.fixture
def magasin(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    m.ajouter([(dnstv.Evenement(ts, IP, d, "A", "NXDOMAIN" if dec == "BLOCKED" else "NOERROR", dec), "") for ts, d, dec in (
        (t - 100, "pagead2.googlesyndication.com", "BLOCKED"), (t - 97, "metaproxy.francetvpub.fr", "ALLOWED"))])
    return m


def _replis(magasin):
    return {"tv-banc": D.correler(magasin.evenements([IP], 0), lambda d: TAXO.classer(d)["categorie"])}


def test_apprentissage_guide_les_candidats_attendent_la_validation(magasin):
    r = R.Regles()
    M.tick(ETAT_BANC, r, magasin, lambda d: "", M.Reglage(auto_essai=True), int(time.time()), taxo=TAXO, replis=_replis(magasin),
           guides={"tv-banc"})
    assert {y["domaine"]: y["etat"] for y in r.liste()}["metaproxy.francetvpub.fr"] == "candidat"


def test_auto_pur_par_defaut_inchange(magasin):
    r = R.Regles()
    M.tick(ETAT_BANC, r, magasin, lambda d: "", M.Reglage(auto_essai=True), int(time.time()), taxo=TAXO, replis=_replis(magasin))
    assert {y["domaine"]: y["etat"] for y in r.liste()}["metaproxy.francetvpub.fr"] == "essai"


def test_slugs_guides():
    c = A.vide()
    A.basculer_guide(c, "00:24:d4:00:00:01", True)
    assert A.slugs_guides(c, ETAT_BANC) == {"tv-banc"}
    A.basculer_guide(c, "00:24:d4:00:00:01", False)
    assert A.slugs_guides(c, ETAT_BANC) == set()


# ── compteur agrégé du kiosque ─────────────────────────────────────────────────────────────────────────
def test_compteur_appris_sans_detail():
    r = R.Regles()
    for app, d in (("tv-a", "x.example.com"), ("tv-b", "x.example.com"), ("tv-a", "y.example.com")):
        n = r.proposer(app, d, 80, "faible", T0)
        r.transiter(n["id"], "essai", "auto", "essai", T0)
    r.proposer("tv-a", "z.example.com", 80, "faible", T0)                      # candidat : pas appris
    assert A.nouveaux_pisteurs(r, T0 + 3600) == 2
    assert A.nouveaux_pisteurs(r, T0 + 8 * 86400) == 0


# ── verbe root d'audit, extension bornée ───────────────────────────────────────────────────────────────
def test_audit_protection_accepte_les_gestes_de_l_assistant_bornes(monde):  # noqa: F811
    bon = {"acteur": "admin", "origine": "admin", "geste": "assistant", "cibles": ["TV salon"], "minutes": None,
           "domaine": "relais-pub.example.net", "type": "bloquer", "force": False}
    cas = ((bon, 0), (dict(bon, geste="assistant-annule", type="legitime"), 0), (dict(bon, type="plus-tard"), 0),
           (dict(bon, geste="guide", type="active", domaine=None), 0), (dict(bon, geste="guide", type="desactive", domaine=None), 0),
           (dict(bon, type="durcir"), 2), (dict(bon, domaine=None), 2), (dict(bon, minutes=5), 2),
           (dict(bon, geste="guide", type="active"), 2), (dict(bon, geste="guide", type="bloquer", domaine=None), 2))
    for brut, rc in cas:
        sys.stdin = io.StringIO(json.dumps(brut))
        try:
            assert ctl(monde, "audit-protection") == rc, brut
        finally:
            sys.stdin = sys.__stdin__


# ── le moteur consomme la file à son passage, même sans appareil en AUTO ─────────────────────────────────
def _moteur(monkeypatch, tmp_path, e):
    import importlib.machinery
    import importlib.util
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", LISTES)
    dnstv.ecrire_etat(e, tmp_path)
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_auto_5b", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_tv_auto_5b", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _Rep:
    returncode, stdout, stderr = 0, "", ""


@pytest.mark.parametrize("mode", ["auto", "block"])
def test_moteur_applique_la_file_et_marque_la_decouverte(monkeypatch, tmp_path, mode):
    e = etat()
    e["clients"][0]["mode"] = mode
    mod = _moteur(monkeypatch, tmp_path, e)
    m = D.MagasinDPI(tmp_path / "dpi-appareils.db")
    m.ajouter_decouvertes(MAC, [{"type": "repli", "domaine": "relais-pub.example.net", "ts": T0, "refus_ts": T0 - 3, "confiance": 70}])
    ident = m.decouvertes()[0]["id"]
    c = A.vide()
    A.ajouter(c, MAC, "TV salon", "relais-pub.example.net", "bloquer", False, ident, "admin", T0)
    A.ecrire(c, tmp_path)
    appels = []
    assert mod.main(sudo=lambda: appels.append(1) or _Rep(), maintenant=T0 + 60, voisins=lambda: {}, locales=lambda: set(),
                    passerelles=lambda: set(), dpi=lambda v: _Rep()) == 0
    f = A.charger(tmp_path)["file"][0]
    assert f["etat"] == "applique" and f["applique"] == T0 + 60
    assert {r["domaine"]: r["etat"] for r in R.charger(tmp_path).liste()}["relais-pub.example.net"] == "confirme"
    assert [x["domaine"] for x in json.loads((tmp_path / "exceptions.json").read_text())["exceptions"]] == ["relais-pub.example.net"]
    assert D.MagasinDPI(tmp_path / "dpi-appareils.db").decouvertes()[0]["etat"] == "confirmee"
    assert appels == [1]                                                # application (et audit) par regles-appliquer


def test_moteur_passe_les_appareils_guides_a_tick(monkeypatch, tmp_path):
    mod = _moteur(monkeypatch, tmp_path, etat())
    c = A.vide()
    A.basculer_guide(c, MAC, True)
    A.ecrire(c, tmp_path)
    vus = {}
    vrai = mod.dnstv_auto.tick
    monkeypatch.setattr(mod.dnstv_auto, "tick", lambda *a, **k: vus.update(k) or vrai(*a, **k))
    mod.main(sudo=lambda: _Rep(), maintenant=T0, voisins=lambda: {}, locales=lambda: set(), passerelles=lambda: set(), dpi=lambda v: _Rep())
    assert vus.get("guides") == {"tv-salon"}
