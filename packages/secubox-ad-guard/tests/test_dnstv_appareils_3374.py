# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 1 SBX TV PRIVACY (#3374) : pivot MAC, migration de etat.json, inventaire NAC, profils d'équipement, routes."""
import json
import os
import sqlite3

import pytest

from api import dnstv, dnstv_appareils as A
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

MAC_TV = "00:24:d4:00:00:01"
MAC_FB = "00:24:d4:00:00:02"
MAC_CAST = "00:24:d4:00:00:03"


def etat_v1():
    """Forme réelle de gk2 : une entrée par adresse, le même nom relie les adresses d'un appareil."""
    return {"actif": True, "mode_defaut": "auto", "ajout_auto": True, "auto_essai": False, "ignores": [],
            "clients": [
                {"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "mac": MAC_TV, "ajoute": 100},
                {"ip": "2a01:e0a::95", "nom": "TV banc", "mode": "auto", "mac": MAC_TV, "ajoute": 200},
                {"ip": "2a01:e0a::96", "nom": "TV banc", "mode": "observe", "mac": MAC_TV, "ajoute": 300},
                {"ip": "192.168.1.60", "nom": "TV fb5b", "mode": "observe", "mac": MAC_FB, "ajoute": 100},
                {"ip": "2a01:e0a::60", "nom": "TV fb5b", "mode": "block", "mac": MAC_FB, "ajoute": 500},
                {"ip": "192.168.1.70", "nom": "Enceinte cast", "mode": "auto", "mac": MAC_CAST},
                {"ip": "192.168.1.80", "nom": "Sans MAC", "mode": "observe"},
            ]}


# ── validation (le contrôleur root ne connaît que dnstv.valider_etat) ─────────────────────────────────
def test_valider_etat_v1_garde_exactement_son_format():
    v = dnstv.valider_etat(etat_v1())
    assert "schema" not in v and "appareils" not in v


def test_valider_etat_v2_conserve_schema_et_appareils():
    e = etat_v1()
    e["schema"] = 2
    e["appareils"] = {MAC_TV: {"nom": "TV banc", "profil": {"type": "ANDROID_TV", "source": "manuel", "confiance": 100, "maj": 5}}}
    v = dnstv.valider_etat(e)
    assert v["schema"] == 2 and v["appareils"][MAC_TV]["profil"]["type"] == "ANDROID_TV"


@pytest.mark.parametrize("appareils", [
    {"AA:BB:CC:00:00:01": {"nom": "x"}},                                           # MAC non canonique
    {MAC_TV: {"nom": "x;rm"}},                                                      # nom hors NOM_RE
    {MAC_TV: {"nom": "x", "profil": {"type": "TOASTER", "source": "manuel", "confiance": 1}}},
    {MAC_TV: {"nom": "x", "profil": {"type": "LG_WEBOS", "source": "devine", "confiance": 1}}},
    {MAC_TV: {"nom": "x", "profil": {"type": "LG_WEBOS", "source": "manuel", "confiance": 101}}},
    {MAC_TV: {"nom": "x", "profil": {"type": "LG_WEBOS", "source": "manuel", "confiance": True}}},
    {MAC_TV: {"nom": "x", "inconnu": 1}},
    {f"aa:bb:cc:00:01:{i:02x}": {"nom": "x"} for i in range(65)},                    # plafond
    [],
])
def test_valider_etat_refuse_des_appareils_hostiles(appareils):
    e = etat_v1()
    e["schema"] = 2
    e["appareils"] = appareils
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat(e)


def test_valider_etat_refuse_un_schema_inconnu():
    e = etat_v1()
    e["schema"] = 3
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat(e)


# ── migration ─────────────────────────────────────────────────────────────────────────────────────────
def test_migrer_regroupe_par_mac_sans_toucher_aux_modes():
    v2, rapport = A.migrer(etat_v1(), 1000)
    assert v2["schema"] == 2
    assert set(v2["appareils"]) == {MAC_TV, MAC_FB, MAC_CAST}
    assert v2["clients"] == dnstv.valider_etat(etat_v1())["clients"]   # modes, noms, adresses : identiques
    assert rapport["appareils"] == 3 and rapport["modes_divergents"] == 2
    assert "modes_changes" not in rapport


def test_le_filtrage_effectif_ne_change_pas():
    """Décision du contrôleur : la migration n'a AUCUN effet DNS. État mixte block/auto/observe, même MAC : même mode par IP avant et après."""
    e = {"actif": True, "clients": [{"ip": "192.168.1.1", "nom": "A", "mode": "block", "mac": MAC_TV, "ajoute": 1},
                                    {"ip": "192.168.1.2", "nom": "A", "mode": "auto", "mac": MAC_TV, "ajoute": 2},
                                    {"ip": "192.168.1.3", "nom": "A2", "mode": "auto", "mac": MAC_TV, "ajoute": 3, "puits": False},
                                    {"ip": "192.168.1.4", "nom": "B", "mode": "observe", "mac": MAC_TV, "ajoute": 4},
                                    {"ip": "192.168.1.5", "nom": "C", "mode": "observe", "mac": MAC_FB}]}
    avant = {c["ip"]: (c["mode"], c.get("puits", True), c["nom"]) for c in e["clients"]}
    v2, rapport = A.migrer(e, 1)
    assert {c["ip"]: (c["mode"], c.get("puits", True), c["nom"]) for c in v2["clients"]} == avant
    assert rapport["modes_divergents"] == 1
    tv = {a["mac"]: a for a in A.vue_appareils(v2, {}, {})}[MAC_TV]
    assert tv["mode"] == "block" and tv["modes_divergents"] is True                     # le plus strict, signalé
    assert {a["mac"]: a for a in A.vue_appareils(v2, {}, {})}[MAC_FB]["modes_divergents"] is False


def test_migrer_est_idempotente():
    v2, _ = A.migrer(etat_v1(), 1000)
    v2b, rapport = A.migrer(v2, 2000)
    assert v2b == v2 and rapport["modes_divergents"] == 0


def test_migrer_fichier_sauvegarde_une_seule_fois(tmp_path):
    brut = json.dumps(etat_v1())
    (tmp_path / "etat.json").write_text(brut)
    r = A.migrer_fichier(tmp_path)
    assert r and r["appareils"] == 3
    sauvegarde = tmp_path / "etat.json.avant-3374"
    assert sauvegarde.read_text() == brut and oct(sauvegarde.stat().st_mode & 0o777) == "0o640"
    assert json.loads((tmp_path / "etat.json").read_text())["schema"] == 2
    assert A.migrer_fichier(tmp_path) is None                         # déjà v2
    # Un retour arrière manuel vers v1 ne remplace jamais la première sauvegarde
    (tmp_path / "etat.json").write_text(json.dumps({"actif": False, "clients": []}))
    A.migrer_fichier(tmp_path)
    assert sauvegarde.read_text() == brut
    assert not [f for f in tmp_path.iterdir() if f.name.startswith(".avant-3374")]      # aucun brouillon laissé


def test_sauvegarde_deja_presente_conservee_et_journalisee(tmp_path, caplog):
    (tmp_path / "etat.json").write_text(json.dumps(etat_v1()))
    (tmp_path / "etat.json.avant-3374").write_text("ancienne")
    with caplog.at_level("INFO"):
        assert A.migrer_fichier(tmp_path)
    assert (tmp_path / "etat.json.avant-3374").read_text() == "ancienne" and "conservée" in caplog.text


def test_migrer_fichier_absent_ou_invalide_ne_fait_rien(tmp_path):
    assert A.migrer_fichier(tmp_path) is None
    (tmp_path / "etat.json").write_text("{pas du json")
    assert A.migrer_fichier(tmp_path) is None
    assert (tmp_path / "etat.json").read_text() == "{pas du json" and not (tmp_path / "etat.json.avant-3374").exists()


def test_le_controleur_root_accepte_l_etat_migre(monde):
    dnstv.ecrire_etat(etat_v1(), monde["etat"])
    A.migrer_fichier(monde["etat"])
    assert ctl(monde, "apply") == 0
    conf = monde["conf"].read_text()
    assert "2a01:e0a::60/128 sbx-tv-block" in conf and "192.168.1.60/32 sbx-tv-observe" in conf      # modes d'origine


def test_ecrire_etat_ne_perd_pas_les_appareils(monde):
    v2, _ = A.migrer(etat_v1(), 1)
    dnstv.ecrire_etat(v2, monde["etat"])
    e, err = dnstv.lire_etat(monde["etat"])
    assert err is None and e["schema"] == 2 and MAC_TV in e["appareils"]


# ── inventaire NAC ────────────────────────────────────────────────────────────────────────────────────
def base_nac(chemin, lignes):
    cx = sqlite3.connect(chemin)
    cx.execute("CREATE TABLE devices(mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, oui_vendor TEXT, device_type TEXT, os TEXT, os_source TEXT,"
               " device_subtype TEXT, mac_random INTEGER DEFAULT 0, last_seen INTEGER)")
    for x in lignes:
        cx.execute("INSERT INTO devices(mac, ip, hostname, oui_vendor, device_type, os, os_source, device_subtype, mac_random, last_seen)"
                   " VALUES (?,?,?,?,?,?,?,?,?,?)", (x["mac"], x.get("ip"), x.get("hostname"), x.get("oui_vendor"), x.get("device_type", "unknown"),
                                                     x.get("os"), x.get("os_source"), x.get("device_subtype"), x.get("mac_random", 0), 1))
    cx.commit()
    cx.close()
    os.chmod(chemin, 0o640)


def test_lire_inventaire_nac_lecture_seule(tmp_path):
    db = tmp_path / "devices.db"
    base_nac(db, [{"mac": MAC_TV, "ip": "192.168.1.95", "hostname": "android-123", "os": "Android 11", "os_source": "dhcp-vendor-class:android-dhcp-11"},
                  {"mac": "pas-une-mac", "ip": "1.2.3.4"}])
    avant = db.stat().st_mtime_ns
    inv = A.lire_inventaire_nac(db)
    assert set(inv) == {MAC_TV} and inv[MAC_TV]["ip"] == "192.168.1.95" and inv[MAC_TV]["os"] == "Android 11"
    assert db.stat().st_mtime_ns == avant and not (tmp_path / "devices.db-wal").exists()


def test_lire_inventaire_nac_refuse_lien_trop_gros_ou_inscriptible(tmp_path):
    db = tmp_path / "devices.db"
    base_nac(db, [{"mac": MAC_TV}])
    lien = tmp_path / "lien.db"
    lien.symlink_to(db)
    assert A.lire_inventaire_nac(lien) == {}
    os.chmod(db, 0o646)
    assert A.lire_inventaire_nac(db) == {}
    os.chmod(db, 0o640)
    assert A.lire_inventaire_nac(db, taille_max=10) == {}
    assert A.lire_inventaire_nac(tmp_path / "absent.db") == {}
    wal = tmp_path / "devices.db-wal"
    wal.write_bytes(b"x" * 100)
    os.chmod(wal, 0o646)
    assert A.lire_inventaire_nac(db) == {}                                   # -wal inscriptible par « autres »
    os.chmod(wal, 0o640)
    assert A.lire_inventaire_nac(db, taille_max=50) == {}                    # -wal au-delà du plafond
    wal.unlink()
    (tmp_path / "vrai-wal").write_bytes(b"")
    wal.symlink_to(tmp_path / "vrai-wal")
    assert A.lire_inventaire_nac(db) == {}                                   # -wal en lien
    wal.unlink()
    assert A.lire_inventaire_nac(db) != {}
    os.chmod(tmp_path, 0o757)
    try:
        assert A.lire_inventaire_nac(db) == {}                               # dossier parent inscriptible par « autres »
    finally:
        os.chmod(tmp_path, 0o755)
    (tmp_path / "corrompue.db").write_bytes(b"ceci n'est pas sqlite" * 10)
    assert A.lire_inventaire_nac(tmp_path / "corrompue.db") == {}


# ── profils ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ligne, attendu, conf_min", [
    ({"os": "Tizen (Samsung)", "os_source": "dns:samsungads.com", "device_subtype": "télévision"}, "SAMSUNG_TIZEN", 80),
    ({"os": "webOS (LG)", "os_source": "hostname:lgwebostv"}, "LG_WEBOS", 60),
    ({"hostname": "Freebox-Player-Pop", "oui_vendor": "Freebox SAS", "device_subtype": "décodeur"}, "FREEBOX_PLAYER", 70),
    ({"oui_vendor": "Freebox SAS"}, "FREEBOX_PLAYER", 30),
    ({"hostname": "player-123"}, "FREEBOX_PLAYER", 40),
    ({"hostname": "Apple-TV", "device_subtype": "streaming"}, "APPLE_TV", 60),
    ({"oui_vendor": "Apple, Inc.", "device_subtype": "récepteur multimédia"}, "APPLE_TV", 55),
    ({"os": "Google Cast", "os_source": "hostname:chromecast-ultra", "device_subtype": "streaming"}, "GOOGLE_TV", 60),
    ({"hostname": "google-tv-salon", "os": "Android 12", "os_source": "dhcp-vendor-class:android-dhcp-12"}, "GOOGLE_TV", 60),
    ({"os": "Android 11", "os_source": "dhcp-vendor-class:android-dhcp-11", "device_type": "smart_tv"}, "ANDROID_TV", 70),
    ({"device_type": "smart_tv"}, "GENERIC_SMART_TV", 40),
    ({"os": "Android 13", "os_source": "user-agent:x", "device_subtype": "smartphone"}, "INCONNU", 0),
    ({}, "INCONNU", 0),
])
def test_profil_depuis_nac(ligne, attendu, conf_min):
    p = A.profil_depuis_nac(dict(ligne, mac=MAC_TV))
    assert p["type"] == attendu and p["confiance"] >= conf_min and 0 <= p["confiance"] <= 100
    assert p["source"] == ("aucune" if attendu == "INCONNU" else "nac")
    if attendu != "INCONNU":
        assert p["preuves"]


@pytest.mark.parametrize("ligne, plafond", [
    ({"oui_vendor": "Freebox SAS"}, 30),                     # un Server ou un répéteur porte aussi ce préfixe
    ({"hostname": "player-123"}, 40),
])
def test_preuves_faibles_confiance_basse(ligne, plafond):
    assert A.profil_depuis_nac(dict(ligne, mac=MAC_TV))["confiance"] <= plafond


def test_preuves_filtrees():
    p = A.profil_depuis_nac({"mac": MAC_TV, "hostname": "Freebox-Player<script>alert(1)</script>" + "x" * 200, "oui_vendor": "Freebox\n SAS;rm"})
    for preuve in p["preuves"]:
        assert all(ch.isalnum() or ch in " ._:-" for ch in preuve) and len(preuve) <= 80


def test_mac_aleatoire_jamais_typee_par_son_oui():
    assert A.profil_depuis_nac({"mac": MAC_TV, "oui_vendor": "Freebox SAS", "mac_random": 1})["type"] == "INCONNU"      # drapeau du NAC
    assert A.profil_depuis_nac({"mac": "02:24:d4:00:00:01", "oui_vendor": "Freebox SAS"})["type"] == "INCONNU"         # bit « localement administré »


def test_profil_par_observation():
    assert A.profil_par_observation(["api.samsungcloudsolution.com", "x.example"])["type"] == "SAMSUNG_TIZEN"
    assert A.profil_par_observation(["api.samsungcloudsolution.com"])["confiance"] <= 40     # vu aussi sur les téléphones
    assert A.profil_par_observation(["x.samsungads.com"])["confiance"] >= 70
    p = A.profil_par_observation(["snu.lgtvsdp.com"])
    assert p["type"] == "LG_WEBOS" and p["source"] == "observation"
    assert A.profil_par_observation(["evilsamsungads.com.example", "google.com"]) is None


# ── vue par MAC et correction manuelle ─────────────────────────────────────────────────────────────────
def test_vue_appareils_rattache_les_ip_et_prend_le_profil_nac():
    v2, _ = A.migrer(etat_v1(), 1)
    nac = {MAC_TV: {"mac": MAC_TV, "ip": "192.168.1.95", "os": "Android 11", "os_source": "dhcp-vendor-class:android-dhcp-11", "device_type": "smart_tv"}}
    voisins = {"fe80::95": MAC_TV, "192.168.1.70": MAC_CAST}
    vue = {a["mac"]: a for a in A.vue_appareils(v2, nac, voisins)}
    tv = vue[MAC_TV]
    assert tv["ips"] == sorted(["192.168.1.95", "2a01:e0a::95", "2a01:e0a::96", "fe80::95"])
    assert tv["profil"] == "ANDROID_TV" and tv["profil_source"] == "nac" and tv["nac"] is True and tv["mode"] == "auto"
    assert vue[MAC_CAST]["profil"] == "INCONNU" and vue[MAC_CAST]["nac"] is False and vue[MAC_CAST]["profil_source"] == "aucune"
    assert vue[None]["nom"] == "Sans MAC" and vue[None]["ips"] == ["192.168.1.80"]


def test_le_nom_affiche_suit_un_renommage_de_clients():
    v2, _ = A.migrer(etat_v1(), 1)
    for c in v2["clients"]:
        if c.get("mac") == MAC_TV:
            c["nom"] = "Salon"
    assert {a["mac"]: a for a in A.vue_appareils(v2, {}, {})}[MAC_TV]["nom"] == "Salon"


def test_vue_appareils_sans_nac_utilise_l_observation():
    v2, _ = A.migrer(etat_v1(), 1)
    vue = {a["mac"]: a for a in A.vue_appareils(v2, {}, {}, {"192.168.1.60": ["x.samsungotn.net"]})}
    assert vue[MAC_FB]["profil"] == "SAMSUNG_TIZEN" and vue[MAC_FB]["profil_source"] == "observation"


def test_correction_manuelle_prime_et_s_efface():
    v2, _ = A.migrer(etat_v1(), 1)
    e = A.corriger_profil(v2, MAC_TV, "GOOGLE_TV", 42)
    nac = {MAC_TV: {"mac": MAC_TV, "os": "Tizen (Samsung)", "os_source": "dns:samsungads.com"}}
    tv = {a["mac"]: a for a in A.vue_appareils(e, nac, {})}[MAC_TV]
    assert (tv["profil"], tv["profil_source"], tv["profil_confiance"]) == ("GOOGLE_TV", "manuel", 100)
    e = A.corriger_profil(e, MAC_TV, None, 43)
    assert "profil" not in e["appareils"][MAC_TV]
    with pytest.raises(dnstv.ErreurTV):
        A.corriger_profil(e, MAC_TV, "TOASTER", 1)
    with pytest.raises(dnstv.ErreurTV):
        A.corriger_profil(e, "aa:bb:cc:99:99:99", "LG_WEBOS", 1)        # MAC inconnue du périmètre


# ── routes ────────────────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def sans_nac(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "NAC_DB", tmp_path / "absent.db")
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_voisins", lambda: {})


def test_routes_migrent_au_chargement_et_ajoutent_des_champs(api, monde, sans_nac):
    (monde["etat"] / "etat.json").write_text(json.dumps(etat_v1()))
    s = api.get("/adblock-tv/status").json()
    assert (monde["etat"] / "etat.json.avant-3374").exists()
    c = next(x for x in s["clients"] if x["ip"] == "192.168.1.95")
    assert {"ip", "nom", "mode", "mac"} <= set(c) and c["profil"] == "INCONNU" and c["profil_source"] == "aucune" and "2a01:e0a::96" in c["ips"]
    assert {a["mac"] for a in s["appareils"]} >= {MAC_TV, MAC_FB, MAC_CAST}
    d = api.get("/adblock-tv/auto/detection").json()
    tv = next(a for a in d["appareils"] if a["nom"] == "TV banc")
    assert {"nom", "mode", "mac", "adresses", "puits"} <= set(tv) and tv["profil"] == "INCONNU"


def test_route_appareils_et_correction(api, monde, sans_nac):
    dnstv.ecrire_etat(etat_v1(), monde["etat"])
    r = api.post(f"/adblock-tv/appareils/{MAC_TV}/profil", json={"type": "ANDROID_TV"})
    assert r.status_code == 200 and r.json()["profil"] == "ANDROID_TV" and r.json()["profil_source"] == "manuel"
    tv = next(a for a in api.get("/adblock-tv/appareils").json()["appareils"] if a["mac"] == MAC_TV)
    assert tv["profil"] == "ANDROID_TV" and tv["profil_confiance"] == 100
    assert api.post(f"/adblock-tv/appareils/{MAC_TV}/profil", json={"type": None}).json()["profil_source"] != "manuel"
    assert api.post(f"/adblock-tv/appareils/{MAC_TV}/profil", json={"type": "TOASTER"}).status_code == 422
    assert api.post("/adblock-tv/appareils/AA:BB/profil", json={"type": "LG_WEBOS"}).status_code == 404
    assert api.post(f"/adblock-tv/appareils/{MAC_TV.upper()}/profil", json={"type": "LG_WEBOS"}).json()["profil"] == "LG_WEBOS"   # normalisée
    assert api.post(f"/adblock-tv/appareils/{MAC_TV}/profil", json={"type": "LG_WEBOS", "role": "admin"}).status_code == 422     # extra=forbid
    assert api.post("/adblock-tv/appareils/aa:bb:cc:99:99:99/profil", json={"type": "LG_WEBOS"}).status_code == 404


def test_correction_refusee_tant_que_l_etat_est_v1(api, monde, sans_nac, monkeypatch):
    dnstv.ecrire_etat(etat_v1(), monde["etat"])
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_migrer", lambda: None)                         # migration différée (verrou occupé)
    assert api.post(f"/adblock-tv/appareils/{MAC_TV}/profil", json={"type": "LG_WEBOS"}).status_code == 409


def test_lecture_v2_ne_prend_pas_le_verrou(api, monde, sans_nac, monkeypatch):
    v2, _ = A.migrer(etat_v1(), 1)
    dnstv.ecrire_etat(v2, monde["etat"])
    from api import dnstv_regles
    def interdit(*a, **k):
        raise AssertionError("verrou pris en lecture")
    monkeypatch.setattr(dnstv_regles, "verrou", interdit)
    assert api.get("/adblock-tv/status").status_code == 200 and api.get("/adblock-tv/appareils").status_code == 200


def test_migration_ignoree_si_le_verrou_est_occupe(monde):
    from api import dnstv_regles
    dnstv.ecrire_etat(etat_v1(), monde["etat"])
    with dnstv_regles.verrou(monde["etat"]):
        assert A.migrer_si_v1(monde["etat"]) is None                       # non bloquant : ignorée cette fois
    assert "schema" not in json.loads((monde["etat"] / "etat.json").read_text())
    assert A.migrer_si_v1(monde["etat"])["appareils"] == 3


def test_observation_une_seule_requete_et_cache(monde, monkeypatch):
    import time as _t
    from api import dnstv_routes as r
    mag = dnstv.Magasin(monde["etat"] / "dnstv.db")
    mag.ajouter([(dnstv.Evenement(int(_t.time()), "192.168.1.60", "x.samsungads.com", "A", "NOERROR", "ALLOWED"), ""),
                 (dnstv.Evenement(int(_t.time()), "192.168.1.61", "www.example.com", "A", "NOERROR", "ALLOWED"), "")])
    r._CACHE.pop("observation", None)
    requetes = []
    vrai = A.domaines_temoins
    monkeypatch.setattr(A, "domaines_temoins", lambda *a, **k: requetes.append(1) or vrai(*a, **k))
    t = r._observation(["192.168.1.60", "192.168.1.61"])
    assert t == {"192.168.1.60": ["x.samsungads.com"]} and len(requetes) == 1
    r._observation(["192.168.1.60", "192.168.1.61"])
    assert len(requetes) == 1                                                 # servi par le cache


def test_gardes_des_nouvelles_routes():
    from secubox_core import auth
    from api import dnstv_routes as r
    gardes = {}
    for route in r.router.routes:
        if "/appareils" in route.path and "/auto/" not in route.path:
            gardes[(route.path, tuple(sorted(route.methods)))] = {d.call for d in route.dependant.dependencies}
    assert r.require_lecture_nominative in gardes[("/adblock-tv/appareils", ("GET",))]
    assert auth.require_jwt in gardes[("/adblock-tv/appareils/{mac}/profil", ("POST",))]


# ── moteur auto : la migration se fait sous son verrou, sans visite de la page ─────────────────────────
def test_le_moteur_auto_migre_sans_toucher_aux_modes(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import charger_script, lancer
    from test_dnstv_auto_moteur import Rep
    etat = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "mac": MAC_TV, "ajoute": 10},
                                       {"ip": "2a01:e0a::95", "nom": "TV banc", "mode": "auto", "mac": MAC_TV, "ajoute": 20},
                                       {"ip": "2a01:e0a::96", "nom": "TV banc", "mode": "observe", "mac": MAC_TV, "ajoute": 30}]}
    mod = charger_script(monkeypatch, tmp_path, etat)
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), 1_800_000_000) == 0
    e, err = dnstv.lire_etat(tmp_path)
    assert err is None and e["schema"] == 2 and [c["mode"] for c in e["clients"]] == ["auto", "auto", "observe"]
    assert (tmp_path / "etat.json.avant-3374").exists()
