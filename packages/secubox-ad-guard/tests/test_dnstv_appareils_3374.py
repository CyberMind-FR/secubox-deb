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
def test_migrer_regroupe_par_mac_et_garde_le_mode_le_plus_frequent():
    v2, rapport = A.migrer(etat_v1(), 1000)
    assert v2["schema"] == 2
    assert set(v2["appareils"]) == {MAC_TV, MAC_FB, MAC_CAST}
    modes = {c["ip"]: c["mode"] for c in v2["clients"]}
    assert modes["2a01:e0a::96"] == "auto"                          # 2 auto contre 1 observe
    assert modes["192.168.1.60"] == modes["2a01:e0a::60"] == "block"  # égalité : l'entrée la plus récente (ajoute=500)
    assert modes["192.168.1.80"] == "observe"                       # sans MAC : intouché
    assert v2["appareils"][MAC_TV]["nom"] == "TV banc" and "profil" not in v2["appareils"][MAC_TV]
    assert rapport["modes_changes"] == 2 and rapport["appareils"] == 3
    assert len(v2["clients"]) == 7                                  # aucune adresse perdue


def test_migrer_egalite_sans_date_prend_la_derniere_entree():
    e = {"actif": True, "clients": [{"ip": "192.168.1.1", "nom": "A", "mode": "observe", "mac": MAC_TV},
                                    {"ip": "192.168.1.2", "nom": "A", "mode": "block", "mac": MAC_TV}]}
    v2, _ = A.migrer(e, 1)
    assert {c["mode"] for c in v2["clients"]} == {"block"}


def test_migrer_garde_les_modes_si_la_fusion_serait_refusee():
    # Deux noms, réglage puits divergent : tout passer en auto violerait « même puits par nom » ⇒ modes d'origine gardés.
    e = {"actif": True, "clients": [{"ip": "192.168.1.1", "nom": "A", "mode": "auto", "mac": MAC_TV, "puits": False},
                                    {"ip": "192.168.1.2", "nom": "A", "mode": "observe", "mac": MAC_TV},
                                    {"ip": "192.168.1.3", "nom": "A", "mode": "auto", "mac": MAC_TV, "puits": False}]}
    v2, rapport = A.migrer(e, 1)
    assert [c["mode"] for c in v2["clients"]] == ["auto", "observe", "auto"] and rapport["modes_changes"] == 0
    assert rapport["fusion_refusee"] and v2["schema"] == 2


def test_migrer_est_idempotente():
    v2, _ = A.migrer(etat_v1(), 1000)
    v2b, rapport = A.migrer(v2, 2000)
    assert v2b == v2 and rapport["modes_changes"] == 0


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
    assert "2a01:e0a::60/128 sbx-tv-block" in conf and "192.168.1.60/32 sbx-tv-block" in conf


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
    (tmp_path / "corrompue.db").write_bytes(b"ceci n'est pas sqlite" * 10)
    assert A.lire_inventaire_nac(tmp_path / "corrompue.db") == {}


# ── profils ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ligne, attendu, conf_min", [
    ({"os": "Tizen (Samsung)", "os_source": "dns:samsungads.com", "device_subtype": "télévision"}, "SAMSUNG_TIZEN", 80),
    ({"os": "webOS (LG)", "os_source": "hostname:lgwebostv"}, "LG_WEBOS", 60),
    ({"hostname": "Freebox-Player-Pop", "oui_vendor": "Freebox SAS", "device_subtype": "décodeur"}, "FREEBOX_PLAYER", 70),
    ({"oui_vendor": "Freebox SAS"}, "FREEBOX_PLAYER", 50),
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
    assert p["type"] == attendu and p["source"] == "nac" and p["confiance"] >= conf_min and 0 <= p["confiance"] <= 100
    if attendu != "INCONNU":
        assert p["preuves"]


def test_mac_aleatoire_jamais_typee_par_son_oui():
    assert A.profil_depuis_nac({"mac": MAC_TV, "oui_vendor": "Freebox SAS", "mac_random": 1})["type"] == "INCONNU"      # drapeau du NAC
    assert A.profil_depuis_nac({"mac": "02:24:d4:00:00:01", "oui_vendor": "Freebox SAS"})["type"] == "INCONNU"         # bit « localement administré »


def test_profil_par_observation():
    assert A.profil_par_observation(["api.samsungcloudsolution.com", "x.example"])["type"] == "SAMSUNG_TIZEN"
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
    assert vue[MAC_CAST]["profil"] == "INCONNU" and vue[MAC_CAST]["nac"] is False
    assert vue[None]["nom"] == "Sans MAC" and vue[None]["ips"] == ["192.168.1.80"]


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
    assert {"ip", "nom", "mode", "mac"} <= set(c) and c["profil"] == "INCONNU" and c["profil_source"] == "nac" and "2a01:e0a::96" in c["ips"]
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
    assert api.post("/adblock-tv/appareils/aa:bb:cc:99:99:99/profil", json={"type": "LG_WEBOS"}).status_code == 404


def test_gardes_des_nouvelles_routes():
    from secubox_core import auth
    from api import dnstv_routes as r
    gardes = {}
    for route in r.router.routes:
        if "/appareils" in route.path and "/auto/" not in route.path:
            gardes[(route.path, tuple(sorted(route.methods)))] = {d.call for d in route.dependant.dependencies}
    assert auth.require_lecture in gardes[("/adblock-tv/appareils", ("GET",))]
    assert auth.require_jwt in gardes[("/adblock-tv/appareils/{mac}/profil", ("POST",))]


# ── moteur auto : la migration se fait sous son verrou, sans visite de la page ─────────────────────────
def test_le_moteur_auto_migre_et_demande_l_application(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import charger_script, lancer
    from test_dnstv_auto_moteur import Rep
    etat = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "mac": MAC_TV, "ajoute": 10},
                                       {"ip": "2a01:e0a::95", "nom": "TV banc", "mode": "auto", "mac": MAC_TV, "ajoute": 20},
                                       {"ip": "2a01:e0a::96", "nom": "TV banc", "mode": "observe", "mac": MAC_TV, "ajoute": 30}]}
    mod = charger_script(monkeypatch, tmp_path, etat)
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), 1_800_000_000) == 0
    e, err = dnstv.lire_etat(tmp_path)
    assert err is None and e["schema"] == 2 and {c["mode"] for c in e["clients"]} == {"auto"} and appels
    assert (tmp_path / "etat.json.avant-3374").exists()
