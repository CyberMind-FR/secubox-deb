# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3676 : encart « Pubs bloquées récemment » par appareil — attribution du blocage (règle, indice, exception, tri, listes),
regroupement par service, lecture en flux des listes compilées, cache réécrit seulement s'il change, au plus toutes les 10 min,
route en lecture nominative qui ne lit QUE le cache."""
import importlib.machinery
import importlib.util
import json
import os
import stat
import time
import tracemalloc
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_protection, dnstv_pubs, dnstv_regles

RACINE = Path(__file__).resolve().parents[1]
IP, IP6, IP2 = "192.168.1.95", "2001:db8::95", "192.168.1.96"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV salon", "mode": "auto"}, {"ip": IP6, "nom": "TV salon", "mode": "auto"},
                                   {"ip": IP2, "nom": "Lecteur", "mode": "block"}]}
MAINTENANT = 1_800_000_000


def ev(ts, client, domaine, decision="BLOCKED", cat=""):
    return (dnstv.Evenement(ts, client, domaine, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision), cat)


@pytest.fixture
def monde(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    sources = tmp_path / "sources"
    sources.mkdir()
    monkeypatch.setattr(dnstv_pubs, "DOSSIER_SOURCES", sources)
    listes = tmp_path / "listes"
    listes.mkdir()
    (listes / "services-pub.txt").write_bytes((RACINE / "lists" / "services-pub.txt").read_bytes())
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", listes)
    dnstv.ecrire_etat(ETAT, tmp_path)
    return tmp_path


def magasin(d):
    return dnstv.Magasin(d / "dnstv.db")


def regle(slug, domaine, etat, indice=None, origine="auto"):
    return {"appareil": slug, "domaine": domaine, "etat": etat, "origine": origine, "risque": "faible", "score": 1, "cree": MAINTENANT - 100,
            "maj": MAINTENANT - 100, "fin_essai": MAINTENANT + 3600, "motif": "x", "historique": [], **({"indice": indice} if indice else {})}


def poser_regles(d, *regles):
    dnstv_regles.ecrire(dnstv_regles.Regles.depuis_dict({"version": 1, "regles": list(regles)}), d)


# ── services ──────────────────────────────────────────────────────────────────────────────────────

def test_fichier_des_services_livre_au_manifeste_et_valide():
    f = RACINE / "lists" / "services-pub.txt"
    assert f.read_text(encoding="utf-8").startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    services = dnstv_pubs.charger_services(f)
    assert len(services) >= 30
    assert dnstv.verifier_manifeste(RACINE / "lists") == []
    assert "services-pub.txt" in json.loads((RACINE / "lists" / "MANIFEST.json").read_text())


def test_service_par_plus_long_suffixe_et_repli_sur_le_domaine_enregistrable():
    s = dnstv_pubs.charger_services(RACINE / "lists" / "services-pub.txt")
    assert dnstv_pubs.service_de("adproxy.tf1.fr", s) == "TF1+"
    assert dnstv_pubs.service_de("tf1.fr", s) == "TF1+"
    assert dnstv_pubs.service_de("occ-0-56-55.1.nflxso.net", s) == "Netflix"
    assert dnstv_pubs.service_de("ipv4-c001.oca.nflxvideo.net", s) == "Netflix"
    assert dnstv_pubs.service_de("securepubads.g.doubleclick.net", s) == "YouTube / Google"
    assert dnstv_pubs.service_de("aax-eu.amazon-adsystem.com", s) == "Amazon"
    assert dnstv_pubs.service_de("pub.proxad.net", s) == "Freebox"
    assert dnstv_pubs.service_de("api.brightline.tv", s) == "Brightline"
    assert dnstv_pubs.service_de("sdk.fra-01.braze.eu", s) == "Braze"
    # repli : domaine enregistrable (deux étiquettes, trois pour un suffixe public à deux niveaux)
    assert dnstv_pubs.service_de("a.b.inconnu-pub.com", s) == "inconnu-pub.com"
    assert dnstv_pubs.service_de("ads.exemple.co.uk", s) == "exemple.co.uk"
    assert dnstv_pubs.service_de("notf1.fr", s) == "notf1.fr"                      # suffixe à la frontière d'étiquette seulement


def test_service_ignore_les_lignes_invalides(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("# commentaire\nexemple.com Mon_Service\n pas_un_domaine Truc\nseul.com\nautre.net  X  # fin\n", encoding="utf-8")
    assert dnstv_pubs.charger_services(f) == [("exemple.com", "Mon Service"), ("autre.net", "X")]


# ── listes compilées : lecture en flux ───────────────────────────────────────────────────────────

def test_parents_du_plus_precis_au_plus_large():
    assert dnstv_pubs.parents("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com", "com"]


def test_zone_parente_d_une_liste_et_zone_transparente_plus_precise(monde):
    src = dnstv_pubs.DOSSIER_SOURCES
    (src / "95-secubox-adblock.conf").write_text('server:\n    local-zone: "tf1.fr." always_nxdomain\n'
                                                 '    local-zone: "www.tf1.fr." always_transparent\n'
                                                 '    local-zone-override: "x.tf1.fr." 1.2.3.4/32 always_transparent\n')
    (src / "96-secubox-adult.conf").write_text('server:\n    local-zone: "adulte.example." always_nxdomain\n')
    (src / "93-secubox-webfilter.conf").write_text('server:\nview:\n    name: "v"\n    view-first: yes\n'
                                                   '    local-zone: "brightline.tv." always_nxdomain\n    local-zone: "tf1.fr." always_nxdomain\n')
    attr, _ = dnstv_pubs.attribuer_listes({"adproxy.tf1.fr", "www.tf1.fr", "api.brightline.tv", "a.adulte.example", "rien.example.org", "x.tf1.fr"}, {})
    assert attr["adproxy.tf1.fr"] == "adblock"                     # zone parente, la plus prioritaire des listes qui bloquent
    assert attr["www.tf1.fr"] == "webfilter"                       # transparent dans 95, bloqué par 93
    assert attr["api.brightline.tv"] == "webfilter"
    assert attr["a.adulte.example"] == "adulte"
    assert attr["rien.example.org"] == ""
    assert attr["x.tf1.fr"] == "adblock"                           # `local-zone-override` n'est pas une zone


def test_liste_lue_en_flux_sans_chargement_entier(monde, monkeypatch):
    f = dnstv_pubs.DOSSIER_SOURCES / "95-secubox-adblock.conf"
    with f.open("w") as h:
        h.write("server:\n")
        for i in range(200_000):
            h.write(f'    local-zone: "pub{i}.exemple-{i % 97}.com." always_nxdomain\n')
    taille = f.stat().st_size
    assert taille > 8_000_000

    def interdit(*a, **k):
        raise AssertionError("liste chargée en entier")
    monkeypatch.setattr(Path, "read_text", interdit)
    monkeypatch.setattr(Path, "read_bytes", interdit)
    tracemalloc.start()
    try:
        attr, _ = dnstv_pubs.attribuer_listes({"x.pub199999.exemple-82.com", "absent.example.org"}, {})
        _, pic = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert attr == {"x.pub199999.exemple-82.com": "adblock", "absent.example.org": ""}
    assert pic < 2_000_000, pic                                   # mémoire bornée, loin de la taille du fichier


def test_cache_des_listes_relu_seulement_si_une_liste_change_ou_un_domaine_apparait(monde, monkeypatch):
    f = dnstv_pubs.DOSSIER_SOURCES / "95-secubox-adblock.conf"
    f.write_text('server:\n    local-zone: "tf1.fr." always_nxdomain\n')
    ouverts = []
    vrai = dnstv_pubs._ouvrir_liste

    def compte(p):
        ouverts.append(p.name)
        return vrai(p)
    monkeypatch.setattr(dnstv_pubs, "_ouvrir_liste", compte)
    attr, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, {})
    assert attr == {"a.tf1.fr": "adblock"} and ouverts == ["95-secubox-adblock.conf"]       # chaque fichier présent lu une fois
    attr, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, cache)
    assert attr == {"a.tf1.fr": "adblock"} and len(ouverts) == 1                            # rien de neuf : aucune relecture
    attr, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr", "b.tf1.fr"}, cache)
    assert attr["b.tf1.fr"] == "adblock" and len(ouverts) == 2                              # domaine nouveau : un passage
    f.write_text('server:\n    local-zone: "autre.fr." always_nxdomain\n')
    os.utime(f, ns=(f.stat().st_mtime_ns + 10**9,) * 2)
    attr, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, cache)
    assert attr == {"a.tf1.fr": ""} and len(ouverts) == 3                                   # liste changée : tout est relu
    assert set(cache["domaines"]) == {"a.tf1.fr"}                                           # le cache ne garde que l'utile


# ── attribution : priorités ───────────────────────────────────────────────────────────────────────

def _passe(monde, evts, regles=(), exceptions=(), listes=None, etat=None):
    if etat:
        dnstv.ecrire_etat(etat, monde)
    magasin(monde).ajouter(evts)
    poser_regles(monde, *regles)
    if exceptions:
        dnstv_protection.ecrire_exceptions(list(exceptions), monde)
    for nom, contenu in (listes or {}).items():
        (dnstv_pubs.DOSSIER_SOURCES / nom).write_text(contenu)
    assert dnstv_pubs.rafraichir(int(time.time()), force=True) is True
    return json.loads((monde / dnstv_pubs.FICHIER).read_text())


def _domaines(doc, slug):
    return {d["domaine"]: d for s in doc["appareils"].get(slug, []) for d in s["domaines"]}


def test_priorites_regle_indice_exception_tri_listes_autre(monde):
    t = int(time.time()) - 60
    adblock = 'server:\n    local-zone: "tf1.fr." always_nxdomain\n    local-zone: "regle.example.com." always_nxdomain\n'
    etat = dict(ETAT, tri_netflix={"appareils": ["tv-salon"]})
    doc = _passe(monde, [ev(t, IP, "regle.example.com"), ev(t, IP, "sous.essai.example.net"), ev(t, IP, "indice.example.net"),
                         ev(t, IP, "excep.example.org"), ev(t, IP, "seule.example.org"), ev(t, IP, "a.b.oca.nflxvideo.net"),
                         ev(t, IP, "adproxy.tf1.fr"), ev(t, IP, "mystere.example.biz")],
                 regles=[regle("tv-salon", "regle.example.com", "confirme"), regle("tv-salon", "essai.example.net", "essai"),
                         regle("tv-salon", "indice.example.net", "essai", indice=["gk1", "gk3"]),
                         regle("tv-salon", "excep.example.org", "confirme", origine="admin"),
                         regle("tv-salon", "retiree.example.biz", "retire")],
                 exceptions=[{"appareil": "tv-salon", "mac": "", "domaine": "excep.example.org", "type": "bloquer", "origine": "admin", "maj": 1},
                             {"appareil": "tv-salon", "mac": "", "domaine": "seule.example.org", "type": "bloquer", "origine": "admin", "maj": 1},
                             {"appareil": "tv-salon", "mac": "", "domaine": "mystere.example.biz", "type": "autoriser", "origine": "admin", "maj": 1}],
                 listes={"95-secubox-adblock.conf": adblock}, etat=etat)
    d = _domaines(doc, "tv-salon")
    assert (d["regle.example.com"]["source"], d["regle.example.com"]["detail"]) == ("regle", "règle TV Privacy (confirmée)")   # règle > liste
    assert (d["sous.essai.example.net"]["source"], d["sous.essai.example.net"]["detail"]) == ("regle", "règle TV Privacy (essai)")  # zone parente
    assert (d["indice.example.net"]["source"], d["indice.example.net"]["detail"]) == ("indice", "indice de gk1, gk3")
    assert (d["excep.example.org"]["source"], d["excep.example.org"]["detail"]) == ("exception", "exception de l'administrateur")
    assert d["seule.example.org"]["source"] == "exception"
    assert (d["a.b.oca.nflxvideo.net"]["source"], d["a.b.oca.nflxvideo.net"]["detail"]) == ("tri", "tri Netflix")
    assert (d["adproxy.tf1.fr"]["source"], d["adproxy.tf1.fr"]["detail"]) == ("adblock", "liste adblock")
    assert (d["mystere.example.biz"]["source"], d["mystere.example.biz"]["detail"]) == ("autre", "autre")   # règle retirée, autorisation : rien


def test_regle_d_un_autre_appareil_ignoree_et_protect_liste_tv(monde):
    t = int(time.time()) - 60
    doc = _passe(monde, [ev(t, IP2, "regle.example.com", cat="advertising"), ev(t, IP2, "sans.example.com")],
                 regles=[regle("tv-salon", "regle.example.com", "confirme")])
    d = _domaines(doc, "lecteur")
    assert (d["regle.example.com"]["source"], d["regle.example.com"]["detail"]) == ("liste-tv", "liste TV Privacy (publicité)")
    assert d["sans.example.com"]["source"] == "autre"
    assert "tv-salon" not in doc["appareils"]


# ── contenu : fenêtre, regroupement, tri, plafonds ──────────────────────────────────────────────

def test_regroupe_par_service_trie_par_recence_et_compte(monde):
    t = int(time.time())
    doc = _passe(monde, [ev(t - 7200, IP, "adproxy.tf1.fr"), ev(t - 600, IP6, "adproxy.tf1.fr"), ev(t - 500, IP, "adproxy.tf1.fr"),
                         ev(t - 100, IP, "pub.tf1info.fr"), ev(t - 50, IP, "api.brightline.tv"),
                         ev(t - 40, IP, "ok.tf1.fr", decision="ALLOWED"), ev(t - 90000, IP, "vieux.tf1.fr")])
    services = doc["appareils"]["tv-salon"]
    assert [s["service"] for s in services] == ["Brightline", "TF1+"]
    tf1 = services[1]
    assert tf1["nombre"] == 4 and tf1["dernier_ts"] == t - 100
    assert [(d["domaine"], d["nombre"], d["dernier_ts"]) for d in tf1["domaines"]] == [("pub.tf1info.fr", 1, t - 100), ("adproxy.tf1.fr", 3, t - 500)]
    assert "ok.tf1.fr" not in json.dumps(doc) and "vieux.tf1.fr" not in json.dumps(doc)          # autorisé ; hors des 24 h
    assert doc["version"] == 1 and doc["fenetre_s"] == 86400 and doc["maj"] > 0


def test_plafonds_par_appareil_et_d_appareils(monde, monkeypatch):
    monkeypatch.setattr(dnstv_pubs, "DOMAINES_PAR_APPAREIL", 3)
    monkeypatch.setattr(dnstv_pubs, "APPAREILS_MAX", 1)
    t = int(time.time())
    doc = _passe(monde, [ev(t - 100 + i, IP, f"d{i}.example.com") for i in range(6)] + [ev(t - 500, IP2, "x.example.com")])
    assert list(doc["appareils"]) == ["tv-salon"]                                               # l'appareil le plus récent
    assert sorted(d for s in doc["appareils"]["tv-salon"] for d in [x["domaine"] for x in s["domaines"]]) == ["d3.example.com", "d4.example.com", "d5.example.com"]


# ── cache : écrit seulement s'il change, au plus toutes les 10 min ───────────────────────────────

def test_cache_atomique_0640_reecrit_seulement_s_il_change_et_au_plus_toutes_les_10_min(monde):
    t = int(time.time())
    magasin(monde).ajouter([ev(t - 60, IP, "adproxy.tf1.fr")])
    assert dnstv_pubs.rafraichir(t) is True
    f = monde / dnstv_pubs.FICHIER
    assert stat.S_IMODE(f.stat().st_mode) == 0o640
    ino, contenu = f.stat().st_ino, f.read_bytes()
    assert dnstv_pubs.rafraichir(t + 60) is False                                               # moins de 10 min : rien
    assert f.stat().st_ino == ino
    assert dnstv_pubs.rafraichir(t + 601) is True                                               # passe faite, contenu identique : fichier intact
    assert f.stat().st_ino == ino and f.read_bytes() == contenu
    magasin(monde).ajouter([ev(t + 500, IP, "pub.tf1info.fr")])
    assert dnstv_pubs.rafraichir(t + 1202) is True
    assert f.stat().st_ino != ino and b"pub.tf1info.fr" in f.read_bytes()
    assert not [p for p in monde.iterdir() if p.name.startswith(".pubs-bloquees.") and p.name != dnstv_pubs.MARQUE]


def test_regles_illisibles_rien_n_est_ecrit(monde):
    magasin(monde).ajouter([ev(int(time.time()) - 60, IP, "adproxy.tf1.fr")])
    (monde / "regles.json").write_text("{pas du json")
    with pytest.raises(dnstv_regles.ErreurRegle):
        dnstv_pubs.rafraichir(int(time.time()), force=True)
    assert not (monde / dnstv_pubs.FICHIER).exists()


# ── moteur : branchement, jamais de panne ───────────────────────────────────────────────────────

def script(monkeypatch, tmp_path):
    chemin = RACINE / "sbin" / "secubox-adguard-auto"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_auto_3676", str(chemin))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("sbx_tv_auto_3676", loader))
    loader.exec_module(mod)
    monkeypatch.setattr(mod, "rafraichir_feed", lambda *a, **k: False)
    monkeypatch.setattr(mod, "rafraichir_dpi", lambda *a, **k: None)
    monkeypatch.setattr(mod, "amorcer", lambda *a, **k: False)
    return mod


class Rep:
    returncode, stdout, stderr = 0, "", ""


def test_moteur_ecrit_le_cache(monde, monkeypatch):
    mod = script(monkeypatch, monde)
    magasin(monde).ajouter([ev(int(time.time()) - 60, IP, "adproxy.tf1.fr")])
    assert mod.main(sudo=lambda: Rep(), voisins=lambda: {}, locales=set, passerelles=set) == 0
    assert "adproxy.tf1.fr" in (monde / dnstv_pubs.FICHIER).read_text()


def test_une_panne_du_cache_n_arrete_jamais_le_moteur(monde, monkeypatch, capsys):
    mod = script(monkeypatch, monde)

    def boum(*a, **k):
        raise RuntimeError("boum")
    monkeypatch.setattr(dnstv_pubs, "rafraichir", boum)
    assert mod.main(sudo=lambda: Rep(), voisins=lambda: {}, locales=set, passerelles=set) == 0
    assert "pubs bloquées" in capsys.readouterr().err


# ── route ─────────────────────────────────────────────────────────────────────────────────────────

def _client(lecteur):
    from secubox_core import auth
    from api import dnstv_routes as r
    app = FastAPI()
    app.include_router(r.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: lecteur
    return TestClient(app)


def test_route_lit_le_cache_seulement(monde, monkeypatch):
    t = int(time.time())
    magasin(monde).ajouter([ev(t - 60, IP, "adproxy.tf1.fr")])
    api = _client({"sub": "admin"})
    r = api.get("/adblock-tv/appareils/TV salon/pubs-bloquees")
    assert r.status_code == 200 and r.json()["services"] == [] and r.json()["maj"] is None          # pas encore calculé
    dnstv_pubs.rafraichir(t)

    def interdit(*a, **k):
        raise AssertionError("calcul dans une requête")
    monkeypatch.setattr(dnstv_pubs, "rafraichir", interdit)
    monkeypatch.setattr(dnstv_pubs, "attribuer_listes", interdit)
    monkeypatch.setattr(dnstv.Magasin, "__init__", interdit)
    j = api.get("/adblock-tv/appareils/TV salon/pubs-bloquees").json()
    assert j["maj"] and j["verifie"] and j["services"][0]["service"] == "TF1+"
    assert j["services"][0]["domaines"][0] == {"domaine": "adproxy.tf1.fr", "dernier_ts": t - 60, "nombre": 1, "source": "autre", "detail": "autre"}
    assert api.get("/adblock-tv/appareils/Lecteur/pubs-bloquees").json()["services"] == []


def test_route_404_et_garde_nominative(monde):
    api = _client({"sub": "admin"})
    assert api.get("/adblock-tv/appareils/Inconnu/pubs-bloquees").status_code == 404
    assert api.get("/adblock-tv/appareils/..%2Fx/pubs-bloquees").status_code == 404
    assert _client({"sub": None, "tableau_de_bord": True}).get("/adblock-tv/appareils/TV salon/pubs-bloquees").status_code == 403
    assert _client({"sub": "usager"}).get("/adblock-tv/appareils/TV salon/pubs-bloquees").status_code == 403


def test_route_cache_lien_symbolique_refuse(monde):
    (monde / "ailleurs.json").write_text(json.dumps({"version": 1, "maj": 1, "appareils": {"tv-salon": [{"service": "X"}]}}))
    (monde / dnstv_pubs.FICHIER).symlink_to(monde / "ailleurs.json")
    assert _client({"sub": "admin"}).get("/adblock-tv/appareils/TV salon/pubs-bloquees").json()["services"] == []


def test_liste_illisible_ignoree_puis_relue_quand_elle_redevient_lisible(monde, monkeypatch):
    f = dnstv_pubs.DOSSIER_SOURCES / "95-secubox-adblock.conf"
    f.write_text('server:\n    local-zone: "tf1.fr." always_nxdomain\n')
    vrai = dnstv_pubs._ouvrir_liste

    def refuse(p):
        raise PermissionError(p)
    monkeypatch.setattr(dnstv_pubs, "_ouvrir_liste", refuse)
    attr, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, {})
    assert attr == {"a.tf1.fr": ""} and cache["fichiers"]["95-secubox-adblock.conf"] is None
    monkeypatch.setattr(dnstv_pubs, "_ouvrir_liste", vrai)
    attr, _ = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, cache)
    assert attr == {"a.tf1.fr": "adblock"}


# ── relecture sécurité (#3676) ────────────────────────────────────────────────────────────────────

def test_marque_remplacee_par_un_lien_jamais_ecrite_a_travers(monde):
    cible = monde / "cible"
    cible.write_text("intact")
    os.utime(cible, (1000, 1000))
    (monde / dnstv_pubs.MARQUE).symlink_to(cible)
    with pytest.raises(OSError):
        dnstv_pubs.rafraichir(int(time.time()), force=True)
    assert cible.read_text() == "intact" and cible.stat().st_mtime == 1000
    assert not (monde / dnstv_pubs.FICHIER).exists()


def test_marque_creee_0640(monde):
    dnstv_pubs.rafraichir(MAINTENANT, force=True)
    st = os.lstat(monde / dnstv_pubs.MARQUE)
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o007 == 0 and st.st_mtime == MAINTENANT


def test_liste_illisible_journalisee_et_signalee(monde, monkeypatch, capsys):
    f = dnstv_pubs.DOSSIER_SOURCES / "95-secubox-adblock.conf"
    f.write_text('server:\n    local-zone: "tf1.fr." always_nxdomain\n')

    def refuse(p):
        raise PermissionError(13, "refusé", str(p))
    monkeypatch.setattr(dnstv_pubs, "_ouvrir_liste", refuse)
    magasin(monde).ajouter([ev(int(time.time()) - 60, IP, "adproxy.tf1.fr")])
    dnstv_pubs.rafraichir(int(time.time()), force=True)
    err = capsys.readouterr().err
    assert err.count("listes compilées illisibles") == 1 and "95-secubox-adblock.conf: EACCES" in err
    assert json.loads((monde / dnstv_pubs.FICHIER).read_text())["listes_lisibles"] is False
    assert dnstv_pubs.vue("tv-salon")["listes_lisibles"] is False


def test_liste_absente_n_est_pas_une_erreur(monde, capsys):
    attr, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, {})
    assert cache["listes_lisibles"] is True and "illisibles" not in capsys.readouterr().err


def test_dossier_des_listes_non_traversable_signale(monde, monkeypatch, capsys):
    vrai = os.stat

    def stat_refuse(p, *a, **k):
        if str(p).startswith(str(dnstv_pubs.DOSSIER_SOURCES)):
            raise PermissionError(13, "refusé", str(p))
        return vrai(p, *a, **k)
    monkeypatch.setattr(dnstv_pubs.os, "stat", stat_refuse)
    _, cache = dnstv_pubs.attribuer_listes({"a.tf1.fr"}, {})
    assert cache["listes_lisibles"] is False and "EACCES" in capsys.readouterr().err


def test_fifo_a_la_place_du_cache_ne_bloque_jamais(monde):
    os.mkfifo(monde / dnstv_pubs.FICHIER)
    debut = time.monotonic()
    assert dnstv_pubs._lire_json(monde / dnstv_pubs.FICHIER) is None
    assert dnstv_pubs.vue("tv-salon")["services"] == []
    assert time.monotonic() - debut < 2


def test_categorie_du_dernier_blocage_pas_l_ordre_alphabetique(monde):
    t = int(time.time())
    magasin(monde).ajouter([ev(t - 300, IP, "x.example.com", cat="tracking"), ev(t - 100, IP, "x.example.com", cat="advertising")])
    (ligne,) = magasin(monde).bloques(t - 3600)
    assert ligne["categorie"] == "advertising" and ligne["nombre"] == 2 and ligne["dernier_ts"] == t - 100


def test_ecriture_du_cache_synchronisee_avant_remplacement(monde, monkeypatch):
    ordre = []
    vrai_fsync, vrai_replace = os.fsync, os.replace
    monkeypatch.setattr(dnstv_pubs.os, "fsync", lambda fd: ordre.append("fsync") or vrai_fsync(fd))
    monkeypatch.setattr(dnstv_pubs.os, "replace", lambda a, b: ordre.append("replace") or vrai_replace(a, b))
    assert dnstv_pubs._ecrire_si_change(monde / "x.json", {"a": 1}) is True
    assert ordre == ["fsync", "replace"]
